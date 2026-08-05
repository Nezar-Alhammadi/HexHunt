use super::{
    ReconAsset, ReconAssetKind, ReconConfidence, ReconCoverageSummary, ReconCritic, ReconCritique,
    ReconHypothesis, ReconHypothesisId, ReconHypothesisKind, ReconHypothesisStatus,
    ReconInformationGain, ReconMemory, ReconSnapshot, RunId, CORE_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const RECON_BASELINE_ID: &str = "hexhunt-recon-v1";
pub const RECON_BASELINE_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconAssetChange {
    pub kind: ReconAssetKind,
    pub canonical_value: String,
    pub previous_confidence: ReconConfidence,
    pub current_confidence: ReconConfidence,
    pub added_tags: Vec<String>,
    pub removed_tags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconHypothesisChange {
    pub hypothesis_id: ReconHypothesisId,
    pub kind: Option<ReconHypothesisKind>,
    pub previous_status: ReconHypothesisStatus,
    pub current_status: ReconHypothesisStatus,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconSnapshotDelta {
    pub schema_version: u32,
    pub baseline_id: String,
    pub baseline_run_id: RunId,
    pub current_run_id: RunId,
    pub generated_at_ms: u64,
    pub added_assets: Vec<ReconAsset>,
    pub removed_assets: Vec<ReconAsset>,
    pub changed_assets: Vec<ReconAssetChange>,
    pub new_hypotheses: Vec<ReconHypothesis>,
    pub removed_hypothesis_ids: Vec<ReconHypothesisId>,
    pub hypothesis_status_changes: Vec<ReconHypothesisChange>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconPriorityFinding {
    pub hypothesis_id: ReconHypothesisId,
    pub kind: Option<ReconHypothesisKind>,
    pub status: ReconHypothesisStatus,
    pub priority: Option<ReconInformationGain>,
    pub statement: String,
    pub asset_values: Vec<String>,
    pub evidence_count: usize,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconReport {
    pub schema_version: u32,
    pub baseline_id: String,
    pub baseline_version: u32,
    pub run_id: RunId,
    pub generated_at_ms: u64,
    pub executive_summary: String,
    pub coverage: Option<ReconCoverageSummary>,
    pub asset_counts: BTreeMap<String, usize>,
    pub priority_findings: Vec<ReconPriorityFinding>,
    pub unresolved_findings: usize,
    pub review_ready: bool,
    pub limitations: Vec<String>,
    pub recommended_next_actions: Vec<String>,
    pub critic: ReconCritique,
    pub memory_source_runs: usize,
}

pub struct ReconAnalyzer;

impl ReconAnalyzer {
    pub fn compare(
        baseline: &ReconSnapshot,
        current: &ReconSnapshot,
        generated_at_ms: u64,
    ) -> ReconSnapshotDelta {
        let before = baseline
            .assets
            .iter()
            .map(|asset| (asset_key(asset), asset))
            .collect::<BTreeMap<_, _>>();
        let after = current
            .assets
            .iter()
            .map(|asset| (asset_key(asset), asset))
            .collect::<BTreeMap<_, _>>();
        let added_assets = after
            .iter()
            .filter(|(key, _)| !before.contains_key(*key))
            .map(|(_, asset)| (*asset).clone())
            .collect();
        let removed_assets = before
            .iter()
            .filter(|(key, _)| !after.contains_key(*key))
            .map(|(_, asset)| (*asset).clone())
            .collect();
        let mut changed_assets = Vec::new();
        for (key, current_asset) in &after {
            let Some(previous_asset) = before.get(key) else {
                continue;
            };
            let previous_tags = previous_asset.tags.iter().cloned().collect::<BTreeSet<_>>();
            let current_tags = current_asset.tags.iter().cloned().collect::<BTreeSet<_>>();
            let added_tags = current_tags
                .difference(&previous_tags)
                .cloned()
                .collect::<Vec<_>>();
            let removed_tags = previous_tags
                .difference(&current_tags)
                .cloned()
                .collect::<Vec<_>>();
            if previous_asset.confidence != current_asset.confidence
                || !added_tags.is_empty()
                || !removed_tags.is_empty()
            {
                changed_assets.push(ReconAssetChange {
                    kind: current_asset.kind,
                    canonical_value: current_asset.canonical_value.clone(),
                    previous_confidence: previous_asset.confidence,
                    current_confidence: current_asset.confidence,
                    added_tags,
                    removed_tags,
                });
            }
        }
        let before_hypotheses = baseline
            .hypotheses
            .iter()
            .map(|hypothesis| (hypothesis.id.0.clone(), hypothesis))
            .collect::<BTreeMap<_, _>>();
        let after_hypotheses = current
            .hypotheses
            .iter()
            .map(|hypothesis| (hypothesis.id.0.clone(), hypothesis))
            .collect::<BTreeMap<_, _>>();
        let new_hypotheses = after_hypotheses
            .iter()
            .filter(|(id, _)| !before_hypotheses.contains_key(*id))
            .map(|(_, hypothesis)| (*hypothesis).clone())
            .collect();
        let removed_hypothesis_ids = before_hypotheses
            .keys()
            .filter(|id| !after_hypotheses.contains_key(*id))
            .cloned()
            .map(ReconHypothesisId)
            .collect();
        let hypothesis_status_changes = after_hypotheses
            .iter()
            .filter_map(|(id, current_hypothesis)| {
                let previous = before_hypotheses.get(id)?;
                (previous.status != current_hypothesis.status).then(|| ReconHypothesisChange {
                    hypothesis_id: current_hypothesis.id.clone(),
                    kind: current_hypothesis.kind,
                    previous_status: previous.status,
                    current_status: current_hypothesis.status,
                })
            })
            .collect();
        ReconSnapshotDelta {
            schema_version: CORE_SCHEMA_VERSION,
            baseline_id: RECON_BASELINE_ID.into(),
            baseline_run_id: baseline.run_id.clone(),
            current_run_id: current.run_id.clone(),
            generated_at_ms,
            added_assets,
            removed_assets,
            changed_assets,
            new_hypotheses,
            removed_hypothesis_ids,
            hypothesis_status_changes,
        }
    }

    pub fn report(
        snapshot: &ReconSnapshot,
        memory: &ReconMemory,
        generated_at_ms: u64,
    ) -> ReconReport {
        let coverage = snapshot
            .decisions
            .iter()
            .rev()
            .find_map(|decision| decision.coverage.clone());
        let mut asset_counts = BTreeMap::new();
        for asset in &snapshot.assets {
            *asset_counts.entry(asset_kind_name(asset.kind)).or_insert(0) += 1;
        }
        let mut priority_findings = snapshot
            .hypotheses
            .iter()
            .map(|hypothesis| {
                let asset_values = hypothesis
                    .subject_asset_ids
                    .iter()
                    .filter_map(|id| snapshot.assets.iter().find(|asset| asset.id == *id))
                    .map(|asset| asset.canonical_value.clone())
                    .collect();
                ReconPriorityFinding {
                    hypothesis_id: hypothesis.id.clone(),
                    kind: hypothesis.kind,
                    status: hypothesis.status,
                    priority: hypothesis.priority,
                    statement: hypothesis.statement.clone(),
                    asset_values,
                    evidence_count: hypothesis.supporting_observation_ids.len(),
                }
            })
            .collect::<Vec<_>>();
        priority_findings.sort_by(|left, right| {
            priority_rank(right.priority)
                .cmp(&priority_rank(left.priority))
                .then_with(|| left.hypothesis_id.0.cmp(&right.hypothesis_id.0))
        });
        let unresolved_findings = priority_findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.status,
                    ReconHypothesisStatus::Proposed
                        | ReconHypothesisStatus::Testing
                        | ReconHypothesisStatus::Inconclusive
                )
            })
            .count();
        let review_ready = coverage
            .as_ref()
            .is_some_and(|coverage| coverage.review_ready);
        let limitations = [
            (!review_ready).then_some("Automated Recon still has actionable gaps or unresolved validation work.".into()),
            snapshot.assets.iter().any(|asset| asset.tags.iter().any(|tag| tag == "dns:dangling_candidate")).then_some("Dangling-DNS signals require manual provider ownership confirmation and are not vulnerability proof.".into()),
            snapshot.hypotheses.iter().any(|hypothesis| hypothesis.status == ReconHypothesisStatus::Inconclusive).then_some("Some observations remain inconclusive because safe metadata checks could not establish current behavior.".into()),
        ].into_iter().flatten().collect::<Vec<_>>();
        let recommended_next_actions = if review_ready {
            vec!["Review supported and inconclusive hypotheses against their stored evidence before moving beyond Recon.".into()]
        } else {
            vec!["Continue with the highest-scoring authorized Recon action from the latest decision.".into()]
        };
        let critic = ReconCritic::review(snapshot, memory);
        ReconReport {
            schema_version: CORE_SCHEMA_VERSION,
            baseline_id: RECON_BASELINE_ID.into(),
            baseline_version: RECON_BASELINE_VERSION,
            run_id: snapshot.run_id.clone(),
            generated_at_ms,
            executive_summary: format!(
                "Recon mapped {} assets and {} hypotheses; {} findings remain unresolved. Review ready: {}.",
                snapshot.assets.len(), snapshot.hypotheses.len(), unresolved_findings, review_ready
            ),
            coverage,
            asset_counts,
            priority_findings,
            unresolved_findings,
            review_ready,
            limitations,
            recommended_next_actions,
            critic,
            memory_source_runs: memory.source_run_ids.len(),
        }
    }
}

fn asset_key(asset: &ReconAsset) -> String {
    format!(
        "{}:{}",
        asset_kind_name(asset.kind),
        asset.canonical_value.to_ascii_lowercase()
    )
}

fn asset_kind_name(kind: ReconAssetKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn priority_rank(priority: Option<ReconInformationGain>) -> u8 {
    match priority {
        Some(ReconInformationGain::Critical) => 4,
        Some(ReconInformationGain::High) => 3,
        Some(ReconInformationGain::Medium) => 2,
        Some(ReconInformationGain::Low) => 1,
        None => 0,
    }
}
