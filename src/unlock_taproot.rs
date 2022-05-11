use std::{collections::HashMap, error::Error};

use ckb_sdk::{
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, Signer,
    },
    tx_builder::{transfer::CapacityTransferBuilder, CapacityBalancer, TxBuilder},
    unlock::ScriptUnlocker,
    Address, CkbRpcClient, ScriptId,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType, TransactionView},
    h256,
    packed::{Byte32, CellOutput, Script, WitnessArgs},
    prelude::*,
    H256,
};
use log::error;
use secp256k1::{
    schnorrsig::{KeyPair, PublicKey},
    Secp256k1,
};

use crate::{
    blake160,
    config::Config,
    create_auth,
    schnorr::{SchnorrSigner, ScriptPathSpendingSigner, TaprootScriptUnlocker},
    smt::{build_smt_on_wl, verify_smt_on_wl},
    taproot_molecule,
    utils::ckb_tagged_hash_tweak,
    Auth, IDENTITY_FLAGS_SCHNORR,
};

// TODO:
pub const TAPROOT_CODE_HASH: H256 =
    h256!("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8");
pub const TAPROOT_HASH_TYPE: u8 = 1;

pub fn script_path_spending(
    config: &Config,
    execscript_code_hash: H256,
    execscript_hash_type: u8,
    execscript_args: Bytes,
    execscript_key: H256,
    smt_root: H256,
    smt_proof: Bytes,
    taproot_internal_key: H256,

    receiver: Address,
    capacity: u64,
) -> Result<TransactionView, Box<dyn Error>> {
    let secp = Secp256k1::new();
    let key_pair = KeyPair::from_seckey_slice(&secp, execscript_key.as_ref())?;
    let auth = create_auth(&execscript_key)?;
    let auth: Vec<u8> = auth.into();
    let auth: Bytes = auth.into();
    if auth != execscript_args {
        error!(
            "auth != execscript_args: {:?} vs {:?}",
            auth, execscript_args
        );
        return Err(format!("Incorrect execscript key or execscript args").into());
    }

    let signer = SchnorrSigner::new_with_secret_keys(vec![key_pair], secp);
    let script_path_sending_signer = ScriptPathSpendingSigner::new(
        Box::new(signer),
        execscript_code_hash.clone(),
        execscript_hash_type,
        execscript_args.clone(),
        taproot_internal_key.clone(),
        smt_root,
        smt_proof.clone(),
    );
    let taproot_unlocker = TaprootScriptUnlocker::from(script_path_sending_signer);

    let script_id = ScriptId::new_type(TAPROOT_CODE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        script_id,
        Box::new(taproot_unlocker) as Box<dyn ScriptUnlocker>,
    );

    let sender = create_taproot_script(
        &execscript_code_hash,
        execscript_hash_type,
        execscript_args,
        &taproot_internal_key,
        &TAPROOT_CODE_HASH,
        TAPROOT_HASH_TYPE,
    )?;

    let witness_lock_placeholder = generate_witness_lock_placeholder(&smt_proof);
    // Build CapacityBalancer
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(witness_lock_placeholder).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let mut ckb_client = CkbRpcClient::new(config.ckb_rpc.as_str());
    let cell_dep_resolver = {
        let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
        // TODO: add taproot script and execscript script
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(config.ckb_rpc.as_str());
    let mut cell_collector =
        DefaultCellCollector::new(config.ckb_indexer.as_str(), config.ckb_rpc.as_str());
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(config.ckb_rpc.as_str(), 10);

    // Build the transaction
    let output = CellOutput::new_builder()
        .lock(Script::from(&receiver))
        .capacity(capacity.pack())
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
    let (tx, still_locked_groups) = builder.build_unlocked(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;
    assert!(still_locked_groups.is_empty());
    Ok(tx)
}

pub fn taproot_script_path_spending(
    execscript_code_hash: H256,
    execscript_hash_type: u8,
    execscript_args: Bytes,
    taproot_internal_key: H256,
    smt_root: H256,
    smt_proof: Bytes,
    args2: Bytes,
) -> Result<Bytes, Box<dyn Error>> {
    let secp = Secp256k1::new();

    let script = Script::new_builder()
        .args(execscript_args.pack())
        .code_hash(execscript_code_hash.pack())
        .hash_type(execscript_hash_type.try_into()?)
        .build();
    let hash = script.calc_script_hash();
    let mut hash32 = [0u8; 32];
    hash32.copy_from_slice(hash.as_slice());

    let success = verify_smt_on_wl(&vec![hash32], smt_root.0.into(), smt_proof.clone().to_vec());
    if !success {
        error!("SMT verify failed, {} is not on SMT tree", script);
        return Err(format!("SMT verify failed").into());
    }

    let mut tagged_msg = [0u8; 64];
    tagged_msg[..32].copy_from_slice(taproot_internal_key.as_ref());
    tagged_msg[32..].copy_from_slice(smt_root.as_ref());

    let real_tweak32 = ckb_tagged_hash_tweak(&tagged_msg);
    let mut taproot_output_key = PublicKey::from_slice(taproot_internal_key.as_ref())?;
    let y_parity = taproot_output_key.tweak_add_assign(&secp, real_tweak32.as_ref())?;
    let y_parity: u8 = if y_parity { 1 } else { 0 };
    let taproot_output_key: H256 = taproot_output_key.serialize().into();

    let exec_script = Script::new_builder()
        .code_hash(execscript_code_hash.pack())
        .hash_type(execscript_hash_type.into())
        .args(execscript_args.pack())
        .build();

    let script_path = taproot_molecule::TaprootScriptPath::new_builder()
        .taproot_output_key(taproot_output_key.pack())
        .taproot_internal_key(taproot_internal_key.pack())
        .smt_root(Byte32::from_slice(smt_root.as_ref()).unwrap())
        .smt_proof(smt_proof.pack())
        .y_parity(y_parity.into())
        .exec_script(exec_script)
        .args2(args2.pack())
        .build();
    let script_path2 = taproot_molecule::TaprootScriptPathOpt::new_builder()
        .set(Some(script_path))
        .build();
    let builder = taproot_molecule::TaprootLockWitnessLock::new_builder().script_path(script_path2);
    Ok(builder.build().as_bytes())
}

/**
args -> exec_script.args: it should be 21 bytes long (auth).
args2: place signature for exec_script. The signature is 32+64 bytes

table TaprootScriptPath {
    taproot_output_key: Byte32,
    taproot_internal_key: Byte32,
    smt_root: Byte32,
    smt_proof: Bytes,
    y_parity: byte,
    exec_script: Script,
    args2: Bytes,
}

Only the smt_proof is with variable length.
*/
pub fn generate_witness_lock_placeholder(smt_proof: &Bytes) -> Bytes {
    let args: Bytes = vec![0; 21].into();
    let args2: Bytes = vec![0; 32 + 64].into();

    let smt_root = Byte32::default();
    let y_parity = 0u8;

    let exec_script = Script::new_builder()
        .code_hash(Byte32::default())
        .hash_type(0.into())
        .args(args.pack())
        .build();

    let script_path = taproot_molecule::TaprootScriptPath::new_builder()
        .taproot_output_key(Byte32::default())
        .taproot_internal_key(Byte32::default())
        .smt_root(smt_root)
        .smt_proof(smt_proof.pack())
        .y_parity(y_parity.into())
        .exec_script(exec_script)
        .args2(args2.pack())
        .build();
    let script_path2 = taproot_molecule::TaprootScriptPathOpt::new_builder()
        .set(Some(script_path))
        .build();
    let builder = taproot_molecule::TaprootLockWitnessLock::new_builder().script_path(script_path2);
    builder.build().as_bytes()
}

pub fn create_taproot_script(
    execscript_code_hash: &H256,
    execscript_hash_type: u8,
    execscript_args: Bytes,
    taproot_internal_key: &H256,
    taproot_code_hash: &H256,
    taproot_hash_type: u8,
) -> Result<Script, Box<dyn Error>> {
    let secp = Secp256k1::new();
    let code_hash = &execscript_code_hash;
    let hash_type: ScriptHashType = execscript_hash_type.try_into()?;
    let script = Script::new_builder()
        .args(execscript_args.pack())
        .code_hash(code_hash.pack())
        .hash_type(hash_type.into())
        .build();
    let hash = script.calc_script_hash();
    let mut hash32 = [0u8; 32];
    hash32.copy_from_slice(hash.as_slice());
    let (smt_root, _smt_proof) = build_smt_on_wl(&vec![hash32]);

    let mut tagged_msg = [0u8; 64];
    tagged_msg[..32].copy_from_slice(taproot_internal_key.as_ref());
    tagged_msg[32..].copy_from_slice(smt_root.as_slice());

    let real_tweak32 = ckb_tagged_hash_tweak(&tagged_msg);
    let mut taproot_output_key = PublicKey::from_slice(taproot_internal_key.as_ref())?;

    let _y_parity = taproot_output_key.tweak_add_assign(&secp, real_tweak32.as_ref())?;

    let args = blake160(&taproot_output_key.serialize());
    let identity = Auth {
        flags: IDENTITY_FLAGS_SCHNORR,
        blake160: args,
    };
    let args: Vec<u8> = identity.into();
    let args: Bytes = args.into();

    let code_hash = &taproot_code_hash;
    let hash_type: ScriptHashType = taproot_hash_type.try_into()?;

    let script = Script::new_builder()
        .args(args.pack())
        .code_hash(code_hash.pack())
        .hash_type(hash_type.into())
        .build();
    Ok(script)
}
