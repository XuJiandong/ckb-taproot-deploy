use log::info;

use crate::config::Config;
use crate::utils::dump_tx;
use std::collections::HashMap;
use std::error::Error;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::CkbRpcClient,
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{transfer::CapacityTransferBuilder, CapacityBalancer, TxBuilder},
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType, TransactionView},
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
    H256,
};

pub fn unlock_secp256k1(
    config: &Config,
    sender_key: H256,
    receiver_script: Script,
    capacity: u64,
) -> Result<(), Box<dyn Error>> {
    let sender_key = secp256k1::SecretKey::from_slice(sender_key.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))?;
    let sender = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(hash160).pack())
            .build()
    };

    let tx = build_transfer_tx(config, sender, sender_key, receiver_script, capacity)?;

    // Send transaction
    let json_tx = json_types::TransactionView::from(tx);
    if config.dry_run {
        dump_tx("tx.json".into(), json_tx.inner)?;
        println!("written to tx.json");
        println!("You can invoke ckb-debugger to run it locally. For example:");
        println!("$ ckb-cli mock-tx dump --tx-file tx.json --output-file mock-tx.json");
        println!("$ ckb-debugger --tx-file mock-tx.json --cell-index 0 --cell-type input --script-group-type lock")
    } else {
        info!("tx = {}", serde_json::to_string_pretty(&json_tx).unwrap());
        info!("Begin sending tx ...");
        let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
        let tx_hash = CkbRpcClient::new(config.ckb_rpc.as_str())
            .send_transaction(json_tx.inner, outputs_validator)
            .expect("send transaction");
        println!(">>> tx ({})sent! <<<", tx_hash);
    }
    Ok(())
}

fn build_transfer_tx(
    config: &Config,
    sender: Script,
    sender_key: secp256k1::SecretKey,
    receiver_script: Script,
    capacity: u64,
) -> Result<TransactionView, Box<dyn Error>> {
    // Build ScriptUnlocker
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    // Build CapacityBalancer
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(sender.clone(), placeholder_witness, 1000);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let mut ckb_client = CkbRpcClient::new(config.ckb_rpc.as_str());
    let cell_dep_resolver = {
        let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(config.ckb_rpc.as_str());
    let mut cell_collector =
        DefaultCellCollector::new(config.ckb_indexer.as_str(), config.ckb_rpc.as_str());
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(config.ckb_rpc.as_str(), 10);

    // Build the transaction
    let output = CellOutput::new_builder()
        .lock(receiver_script)
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
