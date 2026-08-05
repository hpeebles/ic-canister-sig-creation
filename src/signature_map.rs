//! Maintains signatures with associated expirations.
use crate::{hash_bytes, hash_with_domain, CanisterSig};
use ic0::time;
use ic_certification::{fork, labeled, pruned, Hash, HashTree};
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::time::Duration;
use thiserror::Error;

mod heap;

pub use heap::{HeapExpirationQueue, HeapSignatureStore};

const MAX_SIGS_TO_PRUNE: usize = 50;
pub const LABEL_SIG: &[u8] = b"sig";

/// A certified store of `(seed_hash, message_hash)` pairs.
///
/// Beyond plain insertion and deletion, implementations must be able to certify
/// their contents: [root_hash](SignatureStore::root_hash) returns the root of a
/// hash tree containing every stored pair at path `/<seed_hash>/<message_hash>`,
/// and [witness](SignatureStore::witness) proves the presence of a single pair
/// against that root.
///
/// Different implementations may produce differently shaped hash trees for the
/// same contents (and therefore different root hashes); a witness is only valid
/// against the root hash of the store that produced it.
pub trait SignatureStore {
    /// Inserts the given pair into the store. Inserting an already present pair
    /// is a no-op.
    fn insert(&mut self, seed_hash: Hash, message_hash: Hash);

    /// Deletes the given pair from the store. Deleting an absent pair is a no-op.
    fn delete(&mut self, seed_hash: Hash, message_hash: Hash);

    /// Returns whether the given pair is present in the store.
    fn contains(&self, seed_hash: &Hash, message_hash: &Hash) -> bool;

    /// The root hash of the store's hash tree, i.e. the hash to certify
    /// (after wrapping with the [LABEL_SIG] label).
    fn root_hash(&self) -> Hash;

    /// A hash tree proving the presence of `/<seed_hash>/<message_hash>` in this
    /// store, with all other content pruned. Its digest equals
    /// [root_hash](SignatureStore::root_hash). Returns `None` if the pair is not
    /// present.
    fn witness(&self, seed_hash: &Hash, message_hash: &Hash) -> Option<HashTree>;
}

/// A priority queue of signature expirations, ordered by ascending expiration time.
pub trait ExpirationQueue {
    /// Adds an entry to the queue. The same `(seed_hash, message_hash)` pair may
    /// be queued multiple times with different expiration times.
    fn push(&mut self, expires_at: u64, seed_hash: Hash, message_hash: Hash);

    /// The expiration time of the earliest-expiring entry, or `None` if the
    /// queue is empty.
    fn peek_expires_at(&self) -> Option<u64>;

    /// Removes and returns the earliest-expiring entry, or `None` if the queue
    /// is empty.
    fn pop(&mut self) -> Option<(Hash, Hash)>;

    /// The number of queued entries.
    fn len(&self) -> usize;

    /// Returns whether the queue is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Inputs to create and retrieve a canister signature.
/// - domain: The domain is used to ensure that the same signature cannot be misused in a different context.
/// - seed: The seed is used to derive the canister signature public key to use for this particular signature.
/// - message: The message to sign.
#[derive(PartialEq, Eq)]
pub struct CanisterSigInputs<'a> {
    pub domain: &'a [u8],
    pub seed: &'a [u8],
    pub message: &'a [u8],
}

impl CanisterSigInputs<'_> {
    pub fn message_hash(&self) -> Hash {
        hash_with_domain(self.domain, self.message)
    }
}

/// Maintains canister signatures with associated expirations.
///
/// The store holding the signatures and the queue tracking their expirations are
/// pluggable: the defaults ([HeapSignatureStore] and [HeapExpirationQueue]) keep
/// all data on the heap, while alternative implementations of [SignatureStore]
/// and [ExpirationQueue] can keep it elsewhere, e.g. in stable memory.
pub struct SignatureMap<S = HeapSignatureStore, Q = HeapExpirationQueue> {
    store: S,
    expiration_queue: Q,
}

// Implemented manually (rather than derived) so that it only exists for the
// default type parameters, which lets `SignatureMap::default()` infer them.
impl Default for SignatureMap {
    fn default() -> Self {
        Self::new(
            HeapSignatureStore::default(),
            HeapExpirationQueue::default(),
        )
    }
}

#[derive(Error, Debug)]
pub enum CanisterSigError {
    #[error("Data certificates (which are required to create canister signatures) are only available in query calls.")]
    NoCertificate,
    #[error("No signature found for the given inputs.")]
    NoSignature,
}

impl<S: SignatureStore, Q: ExpirationQueue> SignatureMap<S, Q> {
    /// Creates a signature map backed by the given store and expiration queue.
    pub fn new(store: S, expiration_queue: Q) -> Self {
        Self {
            store,
            expiration_queue,
        }
    }

    fn put(&mut self, seed: &[u8], message_hash: Hash, signature_expires_at: Option<u64>) {
        let seed_hash = hash_bytes(seed);
        self.store.insert(seed_hash, message_hash);
        if let Some(expires_at) = signature_expires_at {
            self.expiration_queue
                .push(expires_at, seed_hash, message_hash);
        }
    }

    pub fn delete(&mut self, seed_hash: Hash, message_hash: Hash) {
        self.store.delete(seed_hash, message_hash);
    }

    /// Removes a batch of expired signatures from the signature map.
    ///
    /// This function piggybacks on update calls that create new signatures to
    /// amortize the cost of tree pruning. Each operation on the signature map
    /// will prune at most [MAX_SIGS_TO_PRUNE] other signatures.
    ///
    /// Pruning the signature map also requires updating the `certified_data`
    /// with the new root hash. Therefore, this function is only called by [add_signature]
    /// which requires updating the `certified_data` as well. This avoids the risk
    /// of clients forgetting to update `certified_data` as it would be a bug even
    /// without pruning.
    fn prune_expired(&mut self, now: u64) -> usize {
        let mut num_pruned = 0;

        for _step in 0..MAX_SIGS_TO_PRUNE {
            match self.expiration_queue.peek_expires_at() {
                Some(expires_at) if expires_at <= now => {
                    if let Some((seed_hash, message_hash)) = self.expiration_queue.pop() {
                        self.delete(seed_hash, message_hash);
                    }
                    num_pruned += 1;
                }
                _ => return num_pruned,
            }
        }

        num_pruned
    }

    /// Retrieves the signature for the given inputs from this map.
    /// The returned value (if found) is a CBOR-serialised [CanisterSig].
    ///
    /// [certified_data](https://internetcomputer.org/docs/current/references/ic-interface-spec/#system-api-certified-data)
    /// for [response verification](https://internetcomputer.org/docs/current/references/http-gateway-protocol-spec#response-verification),
    /// the caller should provide also the root hash of the assets subtree containing the
    /// paths `/http_assets` and / or `/http_expr`.
    pub fn get_signature_as_cbor(
        &self,
        sig_inputs: &CanisterSigInputs,
        maybe_certified_assets_root_hash: Option<Hash>,
    ) -> Result<Vec<u8>, CanisterSigError> {
        let certificate = data_certificate().ok_or(CanisterSigError::NoCertificate)?;
        self.get_signature_as_cbor_internal(
            sig_inputs,
            certificate,
            maybe_certified_assets_root_hash,
        )
    }

    fn get_signature_as_cbor_internal(
        &self,
        sig_inputs: &CanisterSigInputs,
        certificate: Vec<u8>,
        maybe_certified_assets_root_hash: Option<Hash>,
    ) -> Result<Vec<u8>, CanisterSigError> {
        let witness = self
            .witness(sig_inputs.seed, sig_inputs.message_hash())
            .ok_or(CanisterSigError::NoSignature)?;

        debug_assert_eq!(
            witness.digest(),
            self.root_hash(),
            "signature map computed an invalid hash tree, witness hash is {}, root hash is {}",
            hex::encode(witness.digest()),
            hex::encode(self.root_hash())
        );

        let sigs_tree = labeled(LABEL_SIG, witness);
        let tree = match maybe_certified_assets_root_hash {
            Some(certified_assets_root_hash) => fork(pruned(certified_assets_root_hash), sigs_tree),
            None => sigs_tree,
        };

        let sig = CanisterSig {
            certificate: ByteBuf::from(certificate),
            tree,
        };

        let mut cbor = serde_cbor::ser::Serializer::new(Vec::new());
        cbor.self_describe().unwrap();
        sig.serialize(&mut cbor).unwrap();
        Ok(cbor.into_inner())
    }

    /// Adds a signature to the map, given the signature inputs.
    pub fn add_signature(
        &mut self,
        sig_inputs: &CanisterSigInputs,
        signature_expires_after: Option<Duration>,
    ) {
        let now = time();
        self.add_signature_internal(sig_inputs, signature_expires_after, now);
    }

    fn add_signature_internal(
        &mut self,
        sig_inputs: &CanisterSigInputs,
        signature_expires_after: Option<Duration>,
        now: u64,
    ) {
        self.prune_expired(now);
        let expires_at = signature_expires_after.map(|d| now.saturating_add(d.as_nanos() as u64));
        self.put(sig_inputs.seed, sig_inputs.message_hash(), expires_at);
    }

    /// The number of queued signature expirations. Note that signatures added
    /// without an expiration are not counted.
    pub fn len(&self) -> usize {
        self.expiration_queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.expiration_queue.is_empty()
    }

    pub fn root_hash(&self) -> Hash {
        self.store.root_hash()
    }

    pub fn witness(&self, seed: &[u8], message_hash: Hash) -> Option<HashTree> {
        self.store.witness(&hash_bytes(seed), &message_hash)
    }
}

// copied from ic_cdk::api::data_certificate to avoid dependency on ic_cdk
fn data_certificate() -> Option<Vec<u8>> {
    if ic0::data_certificate_present() == 0 {
        return None;
    }
    let n = ic0::data_certificate_size();
    let mut buf = vec![0u8; n];
    ic0::data_certificate_copy(&mut buf, 0);
    Some(buf)
}

#[cfg(test)]
mod test;
