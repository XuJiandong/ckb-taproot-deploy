use ckb_taproot_deploy::config::JsonConfig;
use ckb_taproot_deploy::unlock_taproot::{unlock_taproot, unlock_taproot2};
use ckb_taproot_deploy::utils::{as_hex, as_hex_switch_endian, hex2bin};
use ckb_taproot_deploy::Auth;
use env_logger;
use log::info;

use rand::prelude::thread_rng;
use rand::Rng;
use std::error::Error;

use ckb_sdk::{Address, HumanCapacity};
use ckb_types::H256;
use clap::{ArgEnum, Args, Parser, Subcommand};

use ckb_taproot_deploy::script_path_spending::create_pubkey;
use ckb_taproot_deploy::unlock_secp256k1::unlock_secp256k1;
use ckb_taproot_deploy::{config::Config, unlock_taproot::create_taproot_script};

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

    #[clap(long, default_value_t = String::from("taproot-config.json"))]
    /// config file path in json format
    config: String,
}

#[derive(Subcommand)]
enum Commands {
    GenerateKeys(GenerateKeys),
    TransferTaproot(TransferTaproot),
    SchnorrOperation(SchnorrOperation),
    TransferSecp256k1(TransferSecp256k1),
    TransferSecp256k1_2(TransferSecp256k1_2),
}

#[derive(Args)]
#[clap(long_about = "Generate Schnorr secret/public keys")]
struct GenerateKeys {}

#[derive(Args)]
#[clap(long_about = "Operations on schnorr keys, e.g. generate public key/address")]
struct SchnorrOperation {
    #[clap(long, value_name = "SECRET_KEY")]
    secret_key: H256,

    #[clap(long)]
    tweak: Option<H256>,

    #[clap(long, arg_enum)]
    mode: OperationMode,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
enum OperationMode {
    LockScriptArgs,
    Pubkey,
    GenerateTaprootOutputKey,
}

#[derive(Args)]
#[clap(
    long_about = "Transfer CKB from taproot cells to Secp256k1 cells, using script path spending"
)]
struct TransferSecp256k1 {
    /// the secret key used in exec script. Schnorr secret key
    #[clap(long, value_name = "KEY")]
    execscript_key: H256,

    #[clap(long)]
    execscript_args: String,

    #[clap(long, value_name = "SMT ROOT")]
    smt_root: H256,

    #[clap(long, value_name = "SMT PROOF")]
    smt_proof: String,

    #[clap(long, value_name = "TAPROOT INTERNAL KEY")]
    taproot_internal_key: H256,

    /// The receiver CKB address
    #[clap(long, value_name = "ADDRESS")]
    receiver: Address,

    /// The capacity to transfer (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    capacity: HumanCapacity,
}

#[derive(Args)]
#[clap(long_about = "Transfer CKB from taproot cells to Secp256k1 cells, using key path spending")]
struct TransferSecp256k1_2 {
    #[clap(long, value_name = "SCHNORR SECRET KEY")]
    sender_key: H256,

    /// The receiver CKB address
    #[clap(long, value_name = "ADDRESS")]
    receiver: Address,

    /// The capacity to transfer (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    capacity: HumanCapacity,
}

#[derive(Args)]
#[clap(long_about = "Transfer CKB from Secp256k1 cells to taproot cells")]
struct TransferTaproot {
    /// The sender's secp256k1 private key(e.g. 0AEF01...)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,

    /// The 21-byte auth(receiver's schnorr public key hash)
    /// Use `SchnorrOperation` lock-script-args` to get this address
    #[clap(long, value_name = "ARGS")]
    execscript_args: String,

    /// taproot internal key (schnorr public key)
    #[clap(long, value_name = "PUBLIC KEY")]
    taproot_internal_key: H256,

    /// The capacity to transfer (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    capacity: HumanCapacity,
}

fn main() -> Result<(), Box<dyn Error>> {
    drop(env_logger::init());
    let cli = Cli::parse();
    let json_config = JsonConfig::load(cli.config)?;
    let mut config: Config = json_config.convert();
    // override from command line
    config.dry_run = cli.dry_run;

    if config.dry_run {
        println!("dry_run enabled. The tx won't be sent.");
    }
    match &cli.command {
        Commands::TransferTaproot(c) => {
            let execscript_args = hex2bin(c.execscript_args.as_ref())?;
            let receiver_script = create_taproot_script(
                &config.execscript_code_hash,
                config.execscript_hash_type,
                execscript_args.into(),
                &c.taproot_internal_key,
                &config.taproot_code_hash,
                config.taproot_hash_type,
                true,
            )?;
            info!("Transfer to Script = {}", receiver_script);
            unlock_secp256k1(&config, c.sender_key.clone(), receiver_script, c.capacity.0)?;
            info!("unlock_secp256k1 done.");
            return Ok(());
        }
        Commands::SchnorrOperation(op) => match op.mode {
            OperationMode::LockScriptArgs => {
                let addr: Auth = op.secret_key.clone().try_into()?;
                println!("Lock script args = {}", addr);
            }
            OperationMode::Pubkey => {
                let pubkey = create_pubkey(&op.secret_key)?;
                println!("Public Key = {:x}", pubkey);
            }
            OperationMode::GenerateTaprootOutputKey => {
                if op.tweak.is_none() {
                    println!("error, must provide tweak");
                }
                let secp = Secp256k1::new();
                let secret_key = SecretKey::from_slice(op.secret_key.as_ref()).expect("secret key");
                let mut key_pair = KeyPair::from_secret_key(&secp, secret_key);
                let tweak = op.tweak.as_ref();
                key_pair
                    .tweak_add_assign(&secp, tweak.unwrap().as_ref())
                    .unwrap();

                let pubkey = PublicKey::from_keypair(&secp, &key_pair);

                let key_pair = unsafe { (*key_pair.as_ptr()).underlying_bytes() };
                // let res = taproot_tweak_secret(op.secret_key.clone(), tweak.unwrap().clone());
                // println!("(Manually) Taproot Output Secret Key = {}", res);
                // double check it
                println!("Taproot Output Secret Key = {}", as_hex(&key_pair[0..32]));
                println!(
                    "Taproot Output Public Key (x, y) = {}",
                    as_hex_switch_endian(&key_pair[32..64])
                );
                // pubkey.serialize() is in big endian
                println!(
                    "Taproot Output Public Key (x-only)= {}",
                    as_hex(&pubkey.serialize())
                );
            }
        },
        Commands::TransferSecp256k1(c) => {
            info!("Transfer to Address = {}", c.receiver);
            config.execscript_args = hex2bin(&c.execscript_args).unwrap().into();

            let smt_proof = hex2bin(&c.smt_proof).unwrap();
            unlock_taproot(
                &config,
                c.execscript_key.clone(),
                c.smt_root.clone(),
                smt_proof.into(),
                c.taproot_internal_key.clone(),
                c.receiver.clone(),
                c.capacity.0,
            )?;
            info!("unlock_taproot done.");
            return Ok(());
        }
        Commands::TransferSecp256k1_2(c) => {
            info!("Transfer to Address = {}", c.receiver);
            unlock_taproot2(&config, &c.sender_key, c.receiver.clone(), c.capacity.0)?;
            info!("unlock_taproot2 done.");
            return Ok(());
        }
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
