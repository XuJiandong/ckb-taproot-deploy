use std::str::FromStr;

use ckb_types::H256;
use lazy_static::lazy_static;
use uint::construct_uint;

// reference python implementation: https://github.com/XuJiandong/taproot-playground/blob/d5f48c5d5797395ce3f2e209cca29b01695a3d48/py/ckb.py#L40-L47

lazy_static! {
    static ref SECP256K1_ORDER: H256 =
        H256::from_str("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").unwrap();
}

construct_uint! {
    pub struct U512(8);
}

impl From<H256> for U512 {
    fn from(h: H256) -> Self {
        U512::from_big_endian(h.as_ref())
    }
}

pub fn taproot_tweak_secret(secret: H256, tweak: H256) -> H256 {
    let s: U512 = secret.into();
    let t: U512 = tweak.into();
    let n: U512 = SECP256K1_ORDER.clone().into();

    let result = (s + t) % n;
    let mut buf = [0u8; 64];
    result.to_big_endian(&mut buf[..]);
    H256::from_slice(&buf[32..]).unwrap()
}
