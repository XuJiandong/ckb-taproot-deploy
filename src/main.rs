use ckb_taproot_deploy::utils::hex2bin;
use env_logger;
use log::info;

use rand::prelude::thread_rng;
use rand::Rng;
use std::{error::Error, str::FromStr};

use ckb_sdk::HumanCapacity;
use ckb_types::H256;
use clap::{ArgEnum, Args, Parser, Subcommand};

use ckb_taproot_deploy::unlock_secp256k1::unlock_secp256k1;
use ckb_taproot_deploy::{config::Config, unlock_taproot::create_taproot_script};
use ckb_taproot_deploy::{create_auth, create_pubkey};
use secp256k1::schnorrsig::{KeyPair, PublicKey};
use secp256k1::{Secp256k1, SecretKey};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
    #[clap(long)]
    /// Dry run, don't send tx
    dry_run: bool,
    /// CKB rpc url
    #[clap(
        long,
        value_name = "URL",
        default_value = "https://testnet.ckbapp.dev/rpc"
    )]
    ckb_rpc: String,
    /// CKB indexer rpc url
    #[clap(
        long,
        value_name = "URL",
        default_value = "https://testnet.ckbapp.dev/indexer"
    )]
    ckb_indexer: String,
}

#[derive(Subcommand)]
enum Commands {
    GenerateKeys(GenerateKeys),
    TransferTaproot(TransferTaproot),
    SchnorrOperation(SchnorrOperation),
    TransferSecp256k1(TransferSecp256k1),
}

#[derive(Args)]
#[clap(long_about = "Generate Schnorr secret/public keys")]
struct GenerateKeys {}

#[derive(Args)]
#[clap(long_about = "Transfer CKB from taproot cells to Secp256k1 cells")]
struct TransferSecp256k1 {
    #[clap(long, value_name = "SECRET_KEY")]
    secret_key: H256,
}

#[derive(Args)]
#[clap(long_about = "Operations on schnorr keys, e.g. generate public key/address")]
struct SchnorrOperation {
    #[clap(long, value_name = "SECRET_KEY")]
    secret_key: H256,
    #[clap(long, arg_enum)]
    mode: OperationMode,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
enum OperationMode {
    Address,
    Pubkey,
}

#[derive(Args)]
#[clap(long_about = "Transfer CKB from Secp256k1 cells to taproot cells")]
struct TransferTaproot {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,

    /// The capacity to transfer (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    capacity: HumanCapacity,
    // this is the example taproot script
    // TODO: use default one on testnet
    #[clap(long, default_value_t = H256::from_str("0123456789012345678901234567890123456789012345678901234567890123").unwrap())]
    execscript_code_hash: H256,
    #[clap(long, default_value_t = 1)]
    execscript_hash_type: u8,
    #[clap(long, value_name = "ARGS")]
    execscript_args: String,
    #[clap(long, value_name = "PUBLIC KEY")]
    taproot_internal_key: H256,

    // this is the taproot itself
    // TODO: use default one on testnet
    #[clap(long, default_value_t = H256::from_str("0123456789012345678901234567890123456789012345678901234567890123").unwrap())]
    taproot_code_hash: H256,
    #[clap(long, default_value_t = 1)]
    taproot_hash_type: u8,
    // we don't need taproot_args: it's calculated from `execscript_code_hash`,
    // `execscript_hash_type`, `execscript_args` and `taproot_internal_key`
}

fn main() -> Result<(), Box<dyn Error>> {
    drop(env_logger::init());
    let cli = Cli::parse();
    let config = Config {
        dry_run: cli.dry_run,
        ckb_indexer: cli.ckb_indexer,
        ckb_rpc: cli.ckb_rpc,
    };
    if config.dry_run {
        println!("dry_run enabled. The tx won't be sent.");
    }
    match &cli.command {
        Commands::TransferTaproot(c) => {
            let execscript_args = hex2bin(c.execscript_args.as_ref())?;
            let receiver_script = create_taproot_script(
                &c.execscript_code_hash,
                c.execscript_hash_type,
                execscript_args.into(),
                &c.taproot_internal_key,
                &c.taproot_code_hash,
                c.taproot_hash_type,
            )?;
            info!("Transfer to Script = {}", receiver_script);
            unlock_secp256k1(&config, c.sender_key.clone(), receiver_script, c.capacity.0)?;
            info!("unlock_secp256k1 done.");
            return Ok(());
        }
        Commands::SchnorrOperation(op) => match op.mode {
            OperationMode::Address => {
                let addr = create_auth(&op.secret_key)?;
                println!("Address = {}", addr);
            }
            OperationMode::Pubkey => {
                let pubkey = create_pubkey(&op.secret_key)?;
                println!("Public Key = {:x}", pubkey);
            }
        },
        Commands::TransferSecp256k1(_c) => {}
        Commands::GenerateKeys(_) => {
            let mut rng = thread_rng();
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            let secp = Secp256k1::new();
            let secret_key = SecretKey::from_slice(&buf).expect("secret key");
            let key_pair = KeyPair::from_secret_key(&secp, secret_key);
            let pubkey = PublicKey::from_keypair(&secp, &key_pair);
            println!("!!! It's not safe to use these keys in production use. !!!");
            println!("Secret Key = {}", secret_key);
            println!("Public Key = {}", pubkey);
        }
    }
    Ok(())
}
