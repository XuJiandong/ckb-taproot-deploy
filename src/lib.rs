pub mod config;
pub mod schnorr;
pub mod smt;
pub mod taproot_molecule;
pub mod tx_builder;
pub mod unlock_secp256k1;
pub mod unlock_taproot;
pub mod utils;

use ckb_types::H256;
use secp256k1::schnorrsig::{KeyPair, PublicKey};
use secp256k1::{Secp256k1, SecretKey};
use std::error::Error;
use std::fmt::Display;

pub const IDENTITY_FLAGS_SCHNORR: u8 = 6;

#[derive(Clone)]
pub struct Auth {
    pub flags: u8,
    pub blake160: Vec<u8>,
}

impl From<Auth> for [u8; 21] {
    fn from(id: Auth) -> Self {
        let mut res = [0u8; 21];
        res[0] = id.flags;
        res[1..].copy_from_slice(&id.blake160);
        res
    }
}

impl From<Auth> for Vec<u8> {
    fn from(id: Auth) -> Self {
        let mut bytes = vec![id.flags];
        bytes.extend(id.blake160.clone());
        bytes
    }
}

impl Display for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v: Vec<u8> = self.clone().into();
        for i in v {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

pub fn blake160(message: &[u8]) -> Vec<u8> {
    ckb_hash::blake2b_256(message)[0..20].into()
}

pub fn create_auth(secret_key: &H256) -> Result<Auth, Box<dyn Error>> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(secret_key.as_ref()).expect("private key");
    let key_pair = KeyPair::from_secret_key(&secp, secret_key);
    let pubkey = PublicKey::from_keypair(&secp, &key_pair);
    let blake160_hash = blake160(&pubkey.serialize()[..]);
    let identity = Auth {
        flags: IDENTITY_FLAGS_SCHNORR,
        blake160: blake160_hash,
    };

    Ok(identity)
}
