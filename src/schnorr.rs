use std::{collections::HashMap, error::Error};

use ckb_sdk::{
    traits::{Signer, SignerError, TransactionDependencyProvider},
    unlock::{
        fill_witness_lock, generate_message, ScriptSignError, ScriptSigner, ScriptUnlocker,
        UnlockError,
    },
    ScriptGroup,
};
use ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    packed::{self, WitnessArgs},
    prelude::*,
    H256,
};
use log::error;
use secp256k1::{
    schnorrsig::{KeyPair, PublicKey},
    All, Secp256k1, SecretKey,
};

use crate::unlock_taproot::{build_taproot_signature, generate_witness_lock_placeholder};

/// A signer use schnorr raw key, the id is `Auth`.
#[derive(Default, Clone)]
pub struct SchnorrSigner {
    keys: HashMap<Bytes, KeyPair>,
    secp: Secp256k1<All>,
}

impl SchnorrSigner {
    pub fn new(keys: HashMap<Bytes, KeyPair>, secp: Secp256k1<All>) -> Self {
        Self { keys, secp }
    }
    pub fn new_with_secret_key(key: KeyPair, args: Bytes, secp: Secp256k1<All>) -> SchnorrSigner {
        let mut signer = SchnorrSigner::default();
        signer.secp = secp;
        signer.add_secret_key(key, args);
        signer
    }
    pub fn add_secret_key(&mut self, key: KeyPair, args: Bytes) {
        self.keys.insert(args, key);
    }
}

impl Signer for SchnorrSigner {
    fn match_id(&self, id: &[u8]) -> bool {
        let id = Bytes::copy_from_slice(id);
        self.keys.contains_key(&id)
    }

    fn sign(
        &self,
        id: &[u8],
        message: &[u8],
        _recoverable: bool,
        _tx: &TransactionView,
    ) -> Result<Bytes, SignerError> {
        if !self.match_id(id) {
            return Err(SignerError::IdNotFound);
        }
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected length: 32, got: {}",
                message.len()
            )));
        }
        let msg = secp256k1::Message::from_slice(message).expect("Convert to message failed");
        let id = Bytes::copy_from_slice(id);
        let key_pair = self.keys.get(&id).unwrap();
        let sig = self.secp.schnorrsig_sign_no_aux_rand(&msg, key_pair);
        let pubkey = PublicKey::from_keypair(&self.secp, &key_pair);

        let mut final_sig = vec![];
        final_sig.extend(pubkey.serialize());
        final_sig.extend(sig.as_ref());
        assert_eq!(final_sig.len(), 32 + 64);
        Ok(final_sig.into())
    }
}

/// Signer for taproot script path spending
pub struct ScriptPathSpendingSigner {
    signer: Box<dyn Signer>,

    execscript_code_hash: H256,
    execscript_hash_type: u8,
    execscript_args: Bytes,
    taproot_internal_key: H256,
    smt_root: H256,
    smt_proof: Bytes,
}

impl ScriptPathSpendingSigner {
    pub fn new(
        signer: Box<dyn Signer>,
        execscript_code_hash: H256,
        execscript_hash_type: u8,
        execscript_args: Bytes,
        taproot_internal_key: H256,
        smt_root: H256,
        smt_proof: Bytes,
    ) -> ScriptPathSpendingSigner {
        ScriptPathSpendingSigner {
            signer,
            execscript_code_hash,
            execscript_hash_type,
            execscript_args,
            taproot_internal_key,
            smt_root,
            smt_proof,
        }
    }

    pub fn signer(&self) -> &dyn Signer {
        self.signer.as_ref()
    }

    fn sign_tx_script_path_spending(
        &self,
        owner_id: &[u8],
        tx: &TransactionView,
        script_group: &ScriptGroup,
        witness_lock_placeholder: Bytes,
    ) -> Result<TransactionView, ScriptSignError> {
        let witness_idx = script_group.input_indices[0];
        let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
        while witnesses.len() <= witness_idx {
            witnesses.push(Default::default());
        }
        let tx_new = tx
            .as_advanced_builder()
            .set_witnesses(witnesses.clone())
            .build();
        let placeholder_length = witness_lock_placeholder.len();
        let message = generate_message(&tx_new, script_group, witness_lock_placeholder)?;
        let signature = self.signer.sign(owner_id, message.as_ref(), false, tx)?;

        let witness_lock = build_taproot_signature(
            self.execscript_code_hash.clone(),
            self.execscript_hash_type,
            self.execscript_args.clone(),
            self.taproot_internal_key.clone(),
            self.smt_root.clone(),
            self.smt_proof.clone(),
            signature,
        )
        .unwrap();
        if placeholder_length != witness_lock.len() {
            error!("The length of witness lock and its placeholder are not same: witness_lock_placeholder.len() = {} vs witness_lock.len() = {}", placeholder_length, witness_lock.len());
            return Err(ScriptSignError::Other(
                format!(
                    "placeholder length mismatched: {} vs {}",
                    placeholder_length,
                    witness_lock.len()
                )
                .into(),
            ));
        }
        // Put signature into witness
        let witness_data = witnesses[witness_idx].raw_data();
        let mut current_witness: WitnessArgs = if witness_data.is_empty() {
            WitnessArgs::default()
        } else {
            WitnessArgs::from_slice(witness_data.as_ref())?
        };
        current_witness = current_witness
            .as_builder()
            .lock(Some(witness_lock).pack())
            .build();
        witnesses[witness_idx] = current_witness.as_bytes().pack();
        Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
    }
}

impl ScriptSigner for ScriptPathSpendingSigner {
    fn match_args(&self, args: &[u8]) -> bool {
        self.signer.match_id(args)
    }

    fn sign_tx(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError> {
        let args = script_group.script.args().raw_data();
        let placeholder = generate_witness_lock_placeholder(&self.smt_proof);
        self.sign_tx_script_path_spending(args.as_ref(), tx, script_group, placeholder)
    }
}

pub struct TaprootScriptUnlocker {
    signer: ScriptPathSpendingSigner,
    // TODO: key path spending
}

impl TaprootScriptUnlocker {
    pub fn new(signer: ScriptPathSpendingSigner) -> TaprootScriptUnlocker {
        TaprootScriptUnlocker { signer }
    }
}

impl From<ScriptPathSpendingSigner> for TaprootScriptUnlocker {
    fn from(signer: ScriptPathSpendingSigner) -> TaprootScriptUnlocker {
        TaprootScriptUnlocker::new(signer)
    }
}

impl ScriptUnlocker for TaprootScriptUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        self.signer.match_args(args)
    }

    fn unlock(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        Ok(self.signer.sign_tx(tx, script_group)?)
    }

    fn fill_placeholder_witness(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        let placeholder = generate_witness_lock_placeholder(&self.signer.smt_proof);
        fill_witness_lock(tx, script_group, placeholder)
    }
}

pub fn create_pubkey(secret_key: &H256) -> Result<PublicKey, Box<dyn Error>> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(secret_key.as_ref()).expect("private key");
    let key_pair = KeyPair::from_secret_key(&secp, secret_key);
    Ok(PublicKey::from_keypair(&secp, &key_pair))
}
