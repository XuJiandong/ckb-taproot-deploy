use rand::prelude::thread_rng;
use rand::Rng;
use std::{error::Error, str::FromStr};

use ckb_sdk::HumanCapacity;
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType, TransactionView},
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
    H256,
};
use clap::{ArgEnum, Args, Parser, Subcommand};

use ckb_taproot_deploy::smt::build_smt_on_wl;
use ckb_taproot_deploy::{
    blake160,
    utils::{ckb_tagged_hash_tweak, hex2bin},
    Identity, IDENTITY_FLAGS_SCHNORR,
};
use ckb_taproot_deploy::{create_auth_address, create_pubkey};
use secp256k1::schnorrsig::{KeyPair, PublicKey, Signature};
use secp256k1::{All, Message, Secp256k1, SecretKey};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenerateKeys(GenerateKeys),
    TransferTaproot(TransferTaproot),
    SchnorrOperation(SchnorrOperation),
    TransferSighashall(TransferSighashall),
}

#[derive(Args)]
#[clap(long_about = "Generate Schnorr secret/public keys")]
struct GenerateKeys {}

#[derive(Args)]
#[clap(long_about = "Transfer CKB from taproot cells to sighash_all cells")]
struct TransferSighashall {
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
#[clap(long_about = "Transfer CKB from sighash_all cells to taproot cells")]
struct TransferTaproot {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,

    /// The capacity to transfer (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    capacity: HumanCapacity,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,

    /// CKB indexer rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8116")]
    ckb_indexer: String,

    // this is the example taproot script
    // TODO: use default one on testnet
    #[clap(long, default_value_t = H256::from_str("0123456789012345678901234567890123456789012345678901234567890123").unwrap())]
    example_code_hash: H256,
    #[clap(long, default_value_t = 1)]
    example_hash_type: u8,
    #[clap(long, value_name = "ARGS")]
    example_args: String,
    #[clap(long, value_name = "PUBLIC KEY")]
    taproot_internal_key: H256,

    // this is the taproot itself
    // TODO: use default one on testnet
    #[clap(long, default_value_t = H256::from_str("0123456789012345678901234567890123456789012345678901234567890123").unwrap())]
    taproot_code_hash: H256,
    #[clap(long, default_value_t = 1)]
    taproot_hash_type: u8,
    // we don't need taproot_args: it's calculated from `example_code_hash`,
    // `example_hash_type`, `example_args` and `taproot_internal_key`
}

fn create_taproot_script(c: &TransferTaproot) -> Result<Script, Box<dyn Error>> {
    let secp = Secp256k1::new();
    let code_hash = &c.example_code_hash;
    let hash_type: ScriptHashType = c.example_hash_type.try_into()?;
    let args = hex2bin(&c.example_args)?;
    let args: Bytes = args.into();
    let script = Script::new_builder()
        .args(args.pack())
        .code_hash(code_hash.pack())
        .hash_type(hash_type.into())
        .build();
    let hash = script.calc_script_hash();
    let mut hash32 = [0u8; 32];
    hash32.copy_from_slice(hash.as_slice());
    let (smt_root, _smt_proof) = build_smt_on_wl(&vec![hash32]);

    let mut tagged_msg = [0u8; 64];
    tagged_msg[..32].copy_from_slice(c.taproot_internal_key.as_ref());
    tagged_msg[32..].copy_from_slice(smt_root.as_slice());

    let real_tweak32 = ckb_tagged_hash_tweak(&tagged_msg);
    let mut taproot_output_key = PublicKey::from_slice(c.taproot_internal_key.as_ref())?;

    let _y_parity = taproot_output_key.tweak_add_assign(&secp, real_tweak32.as_ref())?;

    let args = blake160(&taproot_output_key.serialize());
    let identity = Identity {
        flags: IDENTITY_FLAGS_SCHNORR,
        blake160: args,
    };
    let args: Vec<u8> = identity.into();
    let args: Bytes = args.into();

    let code_hash = &c.taproot_code_hash;
    let hash_type: ScriptHashType = c.taproot_hash_type.try_into()?;

    let script = Script::new_builder()
        .args(args.pack())
        .code_hash(code_hash.pack())
        .hash_type(hash_type.into())
        .build();
    Ok(script)
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::TransferTaproot(c) => {
            let script = create_taproot_script(&c)?;
            println!("Transfer to Script = {}", script);
        }
        Commands::SchnorrOperation(op) => match op.mode {
            OperationMode::Address => {
                let addr = create_auth_address(&op.secret_key)?;
                println!("Address = {}", addr);
            }
            OperationMode::Pubkey => {
                let pubkey = create_pubkey(&op.secret_key)?;
                println!("Public Key = {:x}", pubkey);
            }
        },
        Commands::TransferSighashall(_c) => {}
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
