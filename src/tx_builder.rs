use std::collections::HashSet;

use ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::{CellDep, CellOutput},
    prelude::*,
};

use ckb_sdk::traits::{
    CellCollector, CellDepResolver, HeaderDepResolver, TransactionDependencyProvider,
};
use ckb_sdk::tx_builder::{TxBuilder, TxBuilderError};
use ckb_sdk::types::ScriptId;

pub struct TaprootTransferBuilder {
    pub outputs: Vec<(CellOutput, Bytes)>,
    pub extra_celldeps: Vec<CellDep>,
}

impl TaprootTransferBuilder {
    pub fn new(
        outputs: Vec<(CellOutput, Bytes)>,
        extra_celldeps: Vec<CellDep>,
    ) -> TaprootTransferBuilder {
        TaprootTransferBuilder {
            outputs,
            extra_celldeps,
        }
    }
}

impl TxBuilder for TaprootTransferBuilder {
    fn build_base(
        &self,
        _cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        _header_dep_resolver: &dyn HeaderDepResolver,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        #[allow(clippy::mutable_key_type)]
        let mut cell_deps = HashSet::new();
        let mut outputs = Vec::new();
        let mut outputs_data = Vec::new();
        for (output, output_data) in &self.outputs {
            outputs.push(output.clone());
            outputs_data.push(output_data.pack());
            if let Some(type_script) = output.type_().to_opt() {
                let script_id = ScriptId::from(&type_script);
                if !script_id.is_type_id() {
                    let cell_dep = cell_dep_resolver
                        .resolve(&type_script)
                        .ok_or(TxBuilderError::ResolveCellDepFailed(type_script))?;
                    cell_deps.insert(cell_dep);
                }
            }
        }
        cell_deps.extend(self.extra_celldeps.clone());
        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .build())
    }
}
