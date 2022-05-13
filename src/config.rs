use std::{error::Error, fs::File, io::BufReader, path::Path};

use bytes::Bytes;
use ckb_types::H256;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct JsonConfig {
    pub ckb_rpc: String,
    pub ckb_indexer: String,
    pub execscript_code_hash: H256,
    pub execscript_hash_type: u8,
    pub execscript_celldep_tx: H256,
    pub execscript_celldep_index: u32,

    pub taproot_code_hash: H256,
    pub taproot_hash_type: u8,
    pub taproot_celldep_tx: H256,
    pub taproot_celldep_index: u32,
}

pub struct Config {
    pub ckb_rpc: String,
    pub ckb_indexer: String,
    pub execscript_code_hash: H256,
    pub execscript_hash_type: u8,
    pub execscript_args: Bytes,
    pub execscript_celldep_tx: H256,
    pub execscript_celldep_index: u32,

    pub taproot_code_hash: H256,
    pub taproot_hash_type: u8,
    pub taproot_celldep_tx: H256,
    pub taproot_celldep_index: u32,

    pub dry_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ckb_rpc: Default::default(),
            ckb_indexer: Default::default(),
            execscript_code_hash: Default::default(),
            execscript_hash_type: 1,
            execscript_args: Default::default(),
            execscript_celldep_index: 0,
            execscript_celldep_tx: Default::default(),
            taproot_code_hash: Default::default(),
            taproot_hash_type: 1,
            taproot_celldep_tx: Default::default(),
            taproot_celldep_index: 0,
            dry_run: false,
        }
    }
}

impl JsonConfig {
    pub fn load(path: String) -> Result<Self, Box<dyn Error>> {
        let path = Path::new(&path);
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let json = serde_json::from_reader(reader)?;
        Ok(json)
    }
    pub fn convert(self) -> Config {
        Config {
            ckb_rpc: self.ckb_rpc,
            ckb_indexer: self.ckb_indexer,
            execscript_code_hash: self.execscript_code_hash,
            execscript_hash_type: self.execscript_hash_type,
            execscript_celldep_tx: self.execscript_celldep_tx,
            execscript_celldep_index: self.execscript_celldep_index,
            taproot_code_hash: self.taproot_code_hash,
            taproot_hash_type: self.taproot_hash_type,
            taproot_celldep_tx: self.taproot_celldep_tx,
            taproot_celldep_index: self.taproot_celldep_index,
            ..Default::default()
        }
    }
}
