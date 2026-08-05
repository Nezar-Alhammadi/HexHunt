use super::{
    ReconAssetKind, ReconCapability, ReconConfidence, ReconHypothesisKind, ReconHypothesisStatus,
    RunId, StructuredData,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconMemoryAsset {
    pub kind: ReconAssetKind,
    pub canonical_value: String,
    pub confidence: ReconConfidence,
    pub source_run_ids: Vec<RunId>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconMemoryAction {
    pub capability: ReconCapability,
    pub target_values: Vec<String>,
    pub arguments: StructuredData,
    pub source_run_id: RunId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconMemoryHypothesis {
    pub kind: Option<ReconHypothesisKind>,
    pub statement: String,
    pub status: ReconHypothesisStatus,
    pub source_run_id: RunId,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconMemory {
    pub source_run_ids: Vec<RunId>,
    pub assets: Vec<ReconMemoryAsset>,
    pub prior_actions: Vec<ReconMemoryAction>,
    pub hypotheses: Vec<ReconMemoryHypothesis>,
}

impl ReconMemory {
    pub fn is_empty(&self) -> bool {
        self.source_run_ids.is_empty()
    }
}
