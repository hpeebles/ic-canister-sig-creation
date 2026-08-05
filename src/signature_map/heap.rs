//! Heap-based implementations of [SignatureStore] and [ExpirationQueue].
use super::{ExpirationQueue, SignatureStore};
use ic_certification::{leaf, leaf_hash, AsHashTree, Hash, HashTree, RbTree};
use std::borrow::Cow;
use std::collections::BinaryHeap;

#[derive(Default)]
struct Unit;

impl AsHashTree for Unit {
    fn root_hash(&self) -> Hash {
        leaf_hash(&b""[..])
    }
    fn as_hash_tree(&self) -> HashTree {
        leaf(Cow::from(&b""[..]))
    }
}

/// The default [SignatureStore], keeping all signatures on the heap in nested
/// red-black trees.
#[derive(Default)]
pub struct HeapSignatureStore {
    certified_map: RbTree<Hash, RbTree<Hash, Unit>>,
}

impl SignatureStore for HeapSignatureStore {
    fn insert(&mut self, seed_hash: Hash, message_hash: Hash) {
        if self.certified_map.get(&seed_hash[..]).is_none() {
            let mut submap = RbTree::new();
            submap.insert(message_hash, Unit);
            self.certified_map.insert(seed_hash, submap);
        } else {
            self.certified_map.modify(&seed_hash[..], |submap| {
                submap.insert(message_hash, Unit);
            });
        }
    }

    fn delete(&mut self, seed_hash: Hash, message_hash: Hash) {
        let mut is_empty = false;
        self.certified_map.modify(&seed_hash[..], |m| {
            m.delete(&message_hash[..]);
            is_empty = m.is_empty();
        });
        if is_empty {
            self.certified_map.delete(&seed_hash[..]);
        }
    }

    fn contains(&self, seed_hash: &Hash, message_hash: &Hash) -> bool {
        self.certified_map
            .get(&seed_hash[..])
            .is_some_and(|submap| submap.get(&message_hash[..]).is_some())
    }

    fn root_hash(&self) -> Hash {
        self.certified_map.root_hash()
    }

    fn witness(&self, seed_hash: &Hash, message_hash: &Hash) -> Option<HashTree> {
        self.certified_map
            .get(&seed_hash[..])?
            .get(&message_hash[..])?;
        let witness = self
            .certified_map
            .nested_witness(&seed_hash[..], |nested| nested.witness(&message_hash[..]));
        Some(witness)
    }
}

#[derive(PartialEq, Eq)]
struct SigExpiration {
    expires_at: u64,
    seed_hash: Hash,
    msg_hash: Hash,
}

impl Ord for SigExpiration {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // BinaryHeap is a max heap, but we want expired entries
        // first, hence the inversed order.
        other.expires_at.cmp(&self.expires_at)
    }
}

impl PartialOrd for SigExpiration {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The default [ExpirationQueue], keeping all entries on the heap in a binary heap.
#[derive(Default)]
pub struct HeapExpirationQueue {
    queue: BinaryHeap<SigExpiration>,
}

impl ExpirationQueue for HeapExpirationQueue {
    fn push(&mut self, expires_at: u64, seed_hash: Hash, message_hash: Hash) {
        self.queue.push(SigExpiration {
            expires_at,
            seed_hash,
            msg_hash: message_hash,
        });
    }

    fn peek_expires_at(&self) -> Option<u64> {
        self.queue.peek().map(|e| e.expires_at)
    }

    fn pop(&mut self) -> Option<(Hash, Hash)> {
        self.queue.pop().map(|e| (e.seed_hash, e.msg_hash))
    }

    fn len(&self) -> usize {
        self.queue.len()
    }
}
