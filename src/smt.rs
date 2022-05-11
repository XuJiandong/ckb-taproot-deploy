use ckb_hash::{Blake2b, Blake2bBuilder, BLAKE2B_LEN};
use lazy_static::lazy_static;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::traits::Hasher;
use sparse_merkle_tree::{CompiledMerkleProof, SparseMerkleTree, H256 as SmtH256};

pub const BLAKE2B_KEY: &[u8] = &[];
pub const PERSONALIZATION: &[u8] = b"ckb-default-hash";

lazy_static! {
    pub static ref SMT_EXISTING: SmtH256 = SmtH256::from([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]);
}

pub struct CKBBlake2bHasher(Blake2b);

impl Default for CKBBlake2bHasher {
    fn default() -> Self {
        let blake2b = Blake2bBuilder::new(BLAKE2B_LEN)
            .personal(PERSONALIZATION)
            .key(BLAKE2B_KEY)
            .build();
        CKBBlake2bHasher(blake2b)
    }
}

impl Hasher for CKBBlake2bHasher {
    fn write_h256(&mut self, h: &SmtH256) {
        self.0.update(h.as_slice());
    }
    fn write_byte(&mut self, b: u8) {
        self.0.update(&[b][..]);
    }
    fn finish(self) -> SmtH256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
}

pub type SMT = SparseMerkleTree<CKBBlake2bHasher, SmtH256, DefaultStore<SmtH256>>;

pub fn new_smt(pairs: Vec<(SmtH256, SmtH256)>) -> SMT {
    let mut smt = SMT::default();
    for (key, value) in pairs {
        smt.update(key, value).unwrap();
    }
    smt
}

// return smt root and proof
pub fn build_smt_on_wl(hashes: &Vec<[u8; 32]>) -> (SmtH256, Vec<u8>) {
    let existing_pairs: Vec<(SmtH256, SmtH256)> = hashes
        .clone()
        .into_iter()
        .map(|hash| (hash.into(), SMT_EXISTING.clone()))
        .collect();

    // this is the hash on white list, and "hashes" are on that.
    let key_on_wl1: SmtH256 = [
        111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let key_on_wl2: SmtH256 = [
        222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let mut pairs = vec![
        (key_on_wl1, SMT_EXISTING.clone()),
        (key_on_wl2, SMT_EXISTING.clone()),
    ];
    pairs.extend(existing_pairs.clone());

    let smt = new_smt(pairs);
    let root = smt.root();

    let proof = smt
        .merkle_proof(existing_pairs.clone().into_iter().map(|(k, _)| k).collect())
        .expect("gen proof");
    let compiled_proof = proof
        .clone()
        .compile(existing_pairs.clone())
        .expect("compile proof");
    let test_on = compiled_proof
        .verify::<CKBBlake2bHasher>(root, existing_pairs.clone())
        .expect("verify compiled proof");
    assert!(test_on);

    return (root.clone(), compiled_proof.into());
}

pub fn verify_smt_on_wl(hashes: &Vec<[u8; 32]>, root: SmtH256, proof: Vec<u8>) -> bool {
    let existing_pairs: Vec<(SmtH256, SmtH256)> = hashes
        .clone()
        .into_iter()
        .map(|hash| (hash.into(), SMT_EXISTING.clone()))
        .collect();

    let compiled_proof = CompiledMerkleProof(proof);
    compiled_proof
        .verify::<CKBBlake2bHasher>(&root, existing_pairs)
        .unwrap()
}
