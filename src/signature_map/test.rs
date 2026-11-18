use super::*;
use assert_matches::assert_matches;
use ic_certification::hash_tree::SubtreeLookupResult::Found;
use ic_certification::{Hash, LookupResult};
use sha2::{Digest, Sha256};

const MINUTE_NS: u64 = 60 * 1_000_000_000;

fn hash_bytes(value: impl AsRef<[u8]>) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(value.as_ref());
    hasher.finalize().into()
}

fn seed(x: u64) -> Hash {
    hash_bytes(x.to_be_bytes())
}

fn message(x: u64) -> Hash {
    hash_bytes(x.to_le_bytes())
}

#[test]
fn test_signature_lookup() {
    let mut map = SignatureMap::default();
    map.put(&seed(1), message(1), Some(10));
    assert_eq!(
        map.witness(&seed(1), message(1))
            .expect("failed to get a witness")
            .digest(),
        map.root_hash()
    );
    assert!(map.witness(&seed(1), message(2)).is_none());
    assert!(map.witness(&seed(2), message(1)).is_none());

    map.delete(hash_bytes(seed(1)), message(1));
    assert!(map.witness(&seed(1), message(1)).is_none());
}

#[test]
fn test_signature_expiration() {
    let mut map = SignatureMap::default();

    map.put(&seed(1), message(1), Some(10));
    map.put(&seed(1), message(2), Some(20));
    map.put(&seed(2), message(1), Some(15));
    map.put(&seed(2), message(2), Some(25));

    assert_eq!(2, map.prune_expired(/*time now*/ 19));
    assert!(map.witness(&seed(1), message(1)).is_none());
    assert!(map.witness(&seed(2), message(1)).is_none());

    assert!(map.witness(&seed(1), message(2)).is_some());
    assert!(map.witness(&seed(2), message(2)).is_some());
}

#[test]
fn test_signature_expiration_limit() {
    let mut map = SignatureMap::default();

    for i in 0..100 {
        map.put(&seed(i), message(i), Some(10 + i));
    }

    assert_eq!(50, map.prune_expired(/*time now*/ 100));

    for i in 0..50 {
        assert!(map.witness(&seed(i), message(i)).is_none());
    }
    for i in 50..100 {
        assert!(map.witness(&seed(i), message(i)).is_some());
    }
}

#[test]
fn test_random_modifications() {
    use rand::prelude::*;

    let mut map = SignatureMap::default();
    let mut rng = rand::rng();
    let window_size = 5;

    let mut pairs = Vec::new();

    for round in 1..100 {
        let n_seeds = rng.random_range(0..5);
        for _i in 0..n_seeds {
            let mut seed = Hash::default();
            rng.fill_bytes(&mut seed);

            let n_messages = rng.random_range(0..5);
            for _k in 0..n_messages {
                let mut message_hash = Hash::default();
                rng.fill_bytes(&mut message_hash);

                pairs.push((seed, message_hash));
                map.put(seed.as_slice(), message_hash, Some(round));
            }
        }

        map.prune_expired(round.saturating_sub(window_size));

        for (k, v) in pairs.iter() {
            if let Some(witness) = map.witness(k, *v) {
                assert_eq!(
                    witness.digest(),
                    map.root_hash(),
                    "produced a bad witness: {witness:?}"
                );
            }
        }
    }
}

#[test]
fn test_signatures_pruned_on_add() {
    const TIME_NOW: u64 = 100;
    let mut map = SignatureMap::default();

    let sig_inputs = CanisterSigInputs {
        domain: b"ic-request-auth-delegation",
        seed: &[1, 2, 3],
        message: &[4, 5, 6],
    };

    for i in 0..50 {
        map.add_signature_internal(&sig_inputs, Some(Duration::from_secs(60)), TIME_NOW + i);
    }

    assert_eq!(map.len(), 50);

    // Pruning timeout is one minute
    map.add_signature_internal(
        &sig_inputs,
        Some(Duration::from_secs(60)),
        TIME_NOW + 2 * MINUTE_NS,
    );
    assert_eq!(map.len(), 1);
}

const DOMAIN: &[u8] = b"ic-request-auth-delegation";

fn add(map: &mut SignatureMap, seed: &[u8], message: &[u8], expires: Option<Duration>, now: u64) {
    let sig_inputs = CanisterSigInputs {
        domain: DOMAIN,
        seed,
        message,
    };
    map.add_signature_internal(&sig_inputs, expires, now);
}

fn held(map: &SignatureMap, seed: &[u8], message: &[u8]) -> bool {
    map.witness(seed, hash_with_domain(DOMAIN, message))
        .is_some()
}

#[test]
fn test_replace_signature() {
    const TIME_NOW: u64 = 100;
    let mut map = SignatureMap::default();
    add(&mut map, &[1], &[1], None, TIME_NOW);
    add(&mut map, &[2], &[1], None, TIME_NOW);

    map.replace_signature_internal(DOMAIN, &[1], &[1], &[2], None, TIME_NOW);
    assert!(!held(&map, &[1], &[1]));
    assert!(held(&map, &[1], &[2]));
    // The same message under another seed is another signature.
    assert!(held(&map, &[2], &[1]));

    // What a map that only ever held these two certifies.
    let mut added = SignatureMap::default();
    add(&mut added, &[1], &[2], None, TIME_NOW);
    add(&mut added, &[2], &[1], None, TIME_NOW);
    assert_eq!(map.root_hash(), added.root_hash());

    // One that isn't held is replaced all the same.
    map.replace_signature_internal(DOMAIN, &[1], &[9], &[3], None, TIME_NOW);
    assert!(held(&map, &[1], &[2]));
    assert!(held(&map, &[1], &[3]));
}

#[test]
fn test_replace_leaves_what_delete_then_insert_leaves() {
    use rand::prelude::*;

    let mut rng = rand::rng();
    let mut replaced = HeapSignatureStore::default();
    let mut rewritten = HeapSignatureStore::default();
    for _ in 0..500 {
        let seed_hash = seed(rng.random_range(0..4));
        let previous = message(rng.random_range(0..4));
        let new = message(rng.random_range(0..4));
        if rng.random_bool(0.25) {
            replaced.delete(seed_hash, previous);
            rewritten.delete(seed_hash, previous);
        } else {
            replaced.replace(seed_hash, previous, new);
            rewritten.delete(seed_hash, previous);
            rewritten.insert(seed_hash, new);
        }
        for s in (0..4).map(seed) {
            for m in (0..4).map(message) {
                let witness = replaced.witness(&s, &m);
                assert_eq!(witness.is_some(), rewritten.contains(&s, &m));
                if let Some(witness) = witness {
                    assert_eq!(witness.digest(), replaced.root_hash());
                }
            }
        }
    }
}

#[test]
fn test_replace_signature_prunes_and_expires() {
    const TIME_NOW: u64 = 100;
    let mut map = SignatureMap::default();
    add(
        &mut map,
        &[9],
        &[9],
        Some(Duration::from_secs(60)),
        TIME_NOW,
    );
    add(&mut map, &[1], &[1], None, TIME_NOW);

    // Replacing prunes what has expired, and queues the new one's expiry.
    map.replace_signature_internal(
        DOMAIN,
        &[1],
        &[1],
        &[2],
        Some(Duration::from_secs(60)),
        TIME_NOW + 2 * MINUTE_NS,
    );
    assert!(!held(&map, &[9], &[9]));
    assert!(held(&map, &[1], &[2]));
    assert_eq!(map.len(), 1);

    map.replace_signature_internal(DOMAIN, &[1], &[1], &[3], None, TIME_NOW + 4 * MINUTE_NS);
    assert!(!held(&map, &[1], &[2]));
    assert!(held(&map, &[1], &[3]));
    assert_eq!(map.len(), 0);
}

#[test]
fn test_replace_signature_with_one_whose_expiry_has_passed() {
    const TIME_NOW: u64 = 100;
    let mut map = SignatureMap::default();
    add(&mut map, &[1], &[1], None, TIME_NOW);
    add(
        &mut map,
        &[1],
        &[2],
        Some(Duration::from_secs(60)),
        TIME_NOW,
    );

    // The pruning takes the second out and the replacing puts it back, held
    // from now on with no expiry.
    map.replace_signature_internal(DOMAIN, &[1], &[1], &[2], None, TIME_NOW + 2 * MINUTE_NS);
    assert!(!held(&map, &[1], &[1]));
    assert!(held(&map, &[1], &[2]));
    assert_eq!(map.len(), 0);
}

#[test]
fn test_signature_round_trip() {
    const TIME_NOW: u64 = 100;
    let certificate = vec![1u8, 2, 3];
    let sig_inputs = CanisterSigInputs {
        domain: b"ic-request-auth-delegation",
        seed: &[1, 2, 3],
        message: &[4, 5, 6],
    };

    let mut map = SignatureMap::default();
    map.add_signature_internal(&sig_inputs, Some(Duration::from_secs(60)), TIME_NOW);
    let result = map
        .get_signature_as_cbor_internal(&sig_inputs, certificate.clone(), None)
        .expect("failed to get signature");

    let sig: CanisterSig =
        serde_cbor::from_slice(&result).expect("failed to deserialize signature");
    assert_eq!(sig.certificate.as_slice(), certificate.as_slice());
    let Found(subtree) = sig.tree.lookup_subtree([b"sig"]) else {
        panic!("expected to find a subtree");
    };
    assert_eq!(subtree.digest(), map.root_hash());
    // canister sig path as per spec: /sig/<seed_hash>/<message_hash>
    let path: &[&[u8]] = &[
        b"sig",
        &hash_bytes(sig_inputs.seed),
        &sig_inputs.message_hash(),
    ];
    assert_matches!(sig.tree.lookup_path(path), LookupResult::Found(_));
}

#[test]
fn test_signature_error_non_existing() {
    let map = SignatureMap::default();

    let sig_inputs = CanisterSigInputs {
        domain: b"ic-request-auth-delegation",
        seed: &[1, 2, 3],
        message: &[4, 5, 6],
    };

    let certificate = vec![1u8, 2, 3];
    let result = map.get_signature_as_cbor_internal(&sig_inputs, certificate, None);
    assert_matches!(result, Err(CanisterSigError::NoSignature));
}
