use crate::unlock_taproot::{build_taproot_signature2, generate_witness_lock_placeholder2};
use ckb_sdk::{
    traits::{Signer, TransactionDependencyProvider},
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
};
use log::error;

/// Signer for taproot script path spending
pub struct KeyPathSpending {
    signer: Box<dyn Signer>,
}

impl KeyPathSpending {
    pub fn new(signer: Box<dyn Signer>) -> KeyPathSpending {
        KeyPathSpending { signer }
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

        let witness_lock = build_taproot_signature2(signature).unwrap();
        if placeholder_length != witness_lock.len() {
            error!("The length of witness lock and its placeholder are not same: witness_lock_placeholder.len() = {} vs witness_lock.len() = {}", placeholder_length, witness_lock.len());
            let msg = format!(
                "placeholder length mismatched: {} vs {}",
                placeholder_length,
                witness_lock.len()
            );
            return Err(ScriptSignError::Other(msg.into()));
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

impl ScriptSigner for KeyPathSpending {
    fn match_args(&self, args: &[u8]) -> bool {
        self.signer.match_id(args)
    }

    fn sign_tx(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError> {
        let args = script_group.script.args().raw_data();
        let placeholder = generate_witness_lock_placeholder2();
        self.sign_tx_script_path_spending(args.as_ref(), tx, script_group, placeholder)
    }
}

pub struct TaprootScriptUnlocker {
    signer: KeyPathSpending,
}

impl TaprootScriptUnlocker {
    pub fn new(signer: KeyPathSpending) -> TaprootScriptUnlocker {
        TaprootScriptUnlocker { signer }
    }
}

impl From<KeyPathSpending> for TaprootScriptUnlocker {
    fn from(signer: KeyPathSpending) -> TaprootScriptUnlocker {
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
        let placeholder = generate_witness_lock_placeholder2();
        fill_witness_lock(tx, script_group, placeholder)
    }
}
