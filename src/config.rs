pub struct Config {
    pub ckb_rpc: String,
    pub ckb_indexer: String,
    pub dry_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ckb_rpc: String::from("https://testnet.ckbapp.dev/rpc"),
            ckb_indexer: String::from("https://testnet.ckbapp.dev/indexer"),
            dry_run: false,
        }
    }
}
