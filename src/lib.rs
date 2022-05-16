pub mod config;
pub mod key_path_spending;
pub mod schnorr;
pub mod script_path_spending;
pub mod smt;
pub mod taproot_molecule;
pub mod tx_builder;
pub mod unlock_secp256k1;
pub mod unlock_taproot;
pub mod utils;

use ckb_types::bytes::Bytes;
use ckb_types::H256;
use secp256k1::schnorrsig::{KeyPair, PublicKey};
use secp256k1::{Secp256k1, SecretKey};
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

impl From<Auth> for Bytes {
    fn from(id: Auth) -> Self {
        let v: Vec<u8> = id.into();
        v.into()
    }
}

impl TryFrom<H256> for Auth {
    type Error = String;
    fn try_from(secret_key: H256) -> Result<Self, Self::Error> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(secret_key.as_ref())
            .map_err(|_| String::from("SecretKey::from_slice"))?;

        let key_pair = KeyPair::from_secret_key(&secp, secret_key);
        let pubkey = PublicKey::from_keypair(&secp, &key_pair);
        let blake160_hash = blake160(&pubkey.serialize()[..]);
        let identity = Auth {
            flags: IDENTITY_FLAGS_SCHNORR,
            blake160: blake160_hash,
        };

        Ok(identity)
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
