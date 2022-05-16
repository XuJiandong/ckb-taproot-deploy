use std::error::Error;

pub(crate) const DICT_HEX_ERROR: u8 = u8::max_value();
pub(crate) static DICT_HEX_LO: [u8; 256] = {
    const ____: u8 = DICT_HEX_ERROR;
    [
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, ____, ____,
        ____, ____, ____, ____, ____, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____,
    ]
};
pub(crate) static DICT_HEX_HI: [u8; 256] = {
    const ____: u8 = DICT_HEX_ERROR;
    [
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, ____, ____,
        ____, ____, ____, ____, ____, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
        ____,
    ]
};

pub fn hex2bin(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let len = input.as_bytes().len();
    if len % 2 != 0 {
        return Err(format!("Invalid length {}", len).into());
    }
    let mut ret: Vec<u8> = vec![];
    ret.resize(len / 2, 0);
    for (idx, chr) in input.bytes().enumerate() {
        let val = if idx % 2 == 0 {
            DICT_HEX_HI[usize::from(chr)]
        } else {
            DICT_HEX_LO[usize::from(chr)]
        };
        if val == DICT_HEX_ERROR {
            return Err(format!("Invalid code: {}, {}", chr, idx).into());
        }
        ret[idx / 2] |= val;
    }
    Ok(ret)
}

pub fn bin2hex(bin: &[u8]) -> String {
    let mut res = String::new();
    for i in bin {
        res += format!("{:02x}", i).as_str();
    }
    res
}

pub fn ckb_tagged_hash_tweak(msg: &[u8]) -> Vec<u8> {
    let mut m: Vec<u8> = vec![];
    let tag = b"TapTweak";
    m.extend_from_slice(&tag[..]);
    m.extend_from_slice(msg);
    let hash = ckb_hash::blake2b_256(m.as_slice());
    hash.into()
}

pub fn as_hex(msg: &[u8]) -> String {
    let mut res: String = String::new();
    for i in msg {
        res += format!("{:02x}", i).as_str();
    }
    res
}

pub fn as_hex_switch_endian(msg: &[u8]) -> String {
    let mut res: String = String::new();
    let len = msg.len();
    for i in 0..len {
        res += format!("{:02x}", msg[len - 1 - i]).as_str();
    }
    res
}
