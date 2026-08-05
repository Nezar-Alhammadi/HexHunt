use super::{
    ReconHypothesisStatus, ReconInformationGain, ReconMemory, ReconScopeClassification,
    ReconSnapshot, CORE_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconCriticVerdict {
    Ready,
    NeedsEvidence,
    Blocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconCriticIssueCode {
    UnsupportedClaim,
    SingleSourceClaim,
    MissingOwnershipCoverage,
    MissingActiveValidation,
    ScopeReviewRequired,
    PriorRunConflict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconCriticFinding {
    pub code: ReconCriticIssueCode,
    pub message: String,
    pub hypothesis_id: Option<String>,
    pub asset_values: Vec<String>,
    pub recommended_action: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconCritique {
    pub schema_version: u32,
    pub verdict: ReconCriticVerdict,
    pub findings: Vec<ReconCriticFinding>,
    pub checked_hypotheses: usize,
    pub checked_assets: usize,
    pub summary: String,
}

pub struct ReconCritic;

impl ReconCritic {
    pub fn review(snapshot: &ReconSnapshot, memory: &ReconMemory) -> ReconCritique {
        let mut findings = Vec::new();
        for hypothesis in &snapshot.hypotheses {
            if hypothesis.status == ReconHypothesisStatus::Supported
                && hypothesis.supporting_observation_ids.is_empty()
            {
                findings.push(ReconCriticFinding {
                    code: ReconCriticIssueCode::UnsupportedClaim,
                    message: "A supported hypothesis has no linked observation.".into(),
                    hypothesis_id: Some(hypothesis.id.0.clone()),
                    asset_values: subject_values(snapshot, &hypothesis.subject_asset_ids),
                    recommended_action:
                        "Downgrade the claim or collect a stored observation before relying on it."
                            .into(),
                });
            }
            if matches!(
                hypothesis.priority,
                Some(ReconInformationGain::Critical | ReconInformationGain::High)
            ) && hypothesis.status == ReconHypothesisStatus::Supported
            {
                let sources = hypothesis
                    .supporting_observation_ids
                    .iter()
                    .filter_map(|id| {
                        snapshot
                            .observations
                            .iter()
                            .find(|observation| observation.id == *id)
                    })
                    .map(|observation| observation.source)
                    .collect::<BTreeSet<_>>();
                if sources.len() < 2 {
                    findings.push(ReconCriticFinding {
                        code: ReconCriticIssueCode::SingleSourceClaim,
                        message: "A high-priority supported hypothesis relies on fewer than two independent observation sources.".into(),
                        hypothesis_id: Some(hypothesis.id.0.clone()),
                        asset_values: subject_values(snapshot, &hypothesis.subject_asset_ids),
                        recommended_action: "Seek independent corroboration or keep the conclusion explicitly limited.".into(),
                    });
                }
            }
            if memory.hypotheses.iter().any(|previous| {
                previous.kind == hypothesis.kind
                    && previous.statement == hypothesis.statement
                    && previous.status != hypothesis.status
            }) {
                findings.push(ReconCriticFinding {
                    code: ReconCriticIssueCode::PriorRunConflict,
                    message: "The same hypothesis had a different status in a previous Run.".into(),
                    hypothesis_id: Some(hypothesis.id.0.clone()),
                    asset_values: subject_values(snapshot, &hypothesis.subject_asset_ids),
                    recommended_action: "Review the Snapshot delta and identify which new observation changed the conclusion.".into(),
                });
            }
        }
        if snapshot
            .assets
            .iter()
            .any(|asset| asset.scope == ReconScopeClassification::RequiresReview)
        {
            findings.push(ReconCriticFinding {
                code: ReconCriticIssueCode::ScopeReviewRequired,
                message: "One or more graph assets require a human scope decision.".into(),
                hypothesis_id: None,
                asset_values: snapshot
                    .assets
                    .iter()
                    .filter(|asset| asset.scope == ReconScopeClassification::RequiresReview)
                    .take(20)
                    .map(|asset| asset.canonical_value.clone())
                    .collect(),
                recommended_action:
                    "Do not test these assets until their program scope is confirmed.".into(),
            });
        }
        if let Some(coverage) = snapshot
            .decisions
            .iter()
            .rev()
            .find_map(|decision| decision.coverage.as_ref())
        {
            if coverage.dns_ownership_observed_hosts < coverage.host_assets {
                findings.push(ReconCriticFinding {
                    code: ReconCriticIssueCode::MissingOwnershipCoverage,
                    message: "DNS ownership coverage is incomplete for the current host graph."
                        .into(),
                    hypothesis_id: None,
                    asset_values: vec![],
                    recommended_action:
                        "Prioritize ownership inspection for unobserved in-scope hosts.".into(),
                });
            }
            if coverage.validated_candidates < coverage.validation_candidates {
                findings.push(ReconCriticFinding {
                    code: ReconCriticIssueCode::MissingActiveValidation,
                    message: "Evidence-derived URL candidates remain unvalidated.".into(),
                    hypothesis_id: None,
                    asset_values: vec![],
                    recommended_action:
                        "Validate the highest-priority candidate with a safe metadata request."
                            .into(),
                });
            }
        }
        let verdict = if findings
            .iter()
            .any(|finding| finding.code == ReconCriticIssueCode::ScopeReviewRequired)
        {
            ReconCriticVerdict::Blocked
        } else if findings.is_empty() {
            ReconCriticVerdict::Ready
        } else {
            ReconCriticVerdict::NeedsEvidence
        };
        ReconCritique {
            schema_version: CORE_SCHEMA_VERSION,
            verdict,
            checked_hypotheses: snapshot.hypotheses.len(),
            checked_assets: snapshot.assets.len(),
            summary: format!(
                "Recon Critic found {} issue(s); verdict: {:?}.",
                findings.len(),
                verdict
            ),
            findings,
        }
    }
}

fn subject_values(snapshot: &ReconSnapshot, ids: &[super::ReconAssetId]) -> Vec<String> {
    ids.iter()
        .filter_map(|id| snapshot.assets.iter().find(|asset| asset.id == *id))
        .map(|asset| asset.canonical_value.clone())
        .collect()
}
