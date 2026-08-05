use super::{
    ReconAsset, ReconAssetId, ReconAssetKind, ReconCapability, ReconConfidence, ReconHypothesis,
    ReconHypothesisId, ReconHypothesisKind, ReconHypothesisStatus, ReconInformationGain,
    ReconObservationId, ReconObservationSource, ReconSnapshot, RunId, RunService, RunServiceError,
    CORE_SCHEMA_VERSION,
};
use std::collections::BTreeSet;

const MAX_DERIVED_HYPOTHESES: usize = 300;

pub struct ReconCorrelator;

impl ReconCorrelator {
    pub fn refresh(service: &RunService, run_id: &RunId) -> Result<(), RunServiceError> {
        let snapshot = service.get_recon_snapshot(run_id)?;
        for hypothesis in Self::derive(&snapshot)
            .into_iter()
            .take(MAX_DERIVED_HYPOTHESES)
        {
            if snapshot
                .hypotheses
                .iter()
                .any(|stored| stored.id == hypothesis.id)
            {
                service.update_recon_hypothesis(run_id, hypothesis)?;
            } else {
                service.append_recon_hypothesis(run_id, hypothesis)?;
            }
        }
        Ok(())
    }

    pub fn derive(snapshot: &ReconSnapshot) -> Vec<ReconHypothesis> {
        let mut hypotheses = Vec::new();
        Self::undocumented_endpoints(snapshot, &mut hypotheses);
        Self::public_sensitive_operations(snapshot, &mut hypotheses);
        Self::authentication_surfaces(snapshot, &mut hypotheses);
        Self::historical_surfaces(snapshot, &mut hypotheses);
        Self::source_maps(snapshot, &mut hypotheses);
        Self::client_secret_indicators(snapshot, &mut hypotheses);
        Self::client_security_signals(snapshot, &mut hypotheses);
        Self::high_value_parameters(snapshot, &mut hypotheses);
        Self::unverified_assets(snapshot, &mut hypotheses);
        Self::potential_dangling_dns(snapshot, &mut hypotheses);
        hypotheses.sort_by(|left, right| {
            priority_value(right.priority)
                .cmp(&priority_value(left.priority))
                .then_with(|| left.id.0.cmp(&right.id.0))
        });
        hypotheses
    }

    fn undocumented_endpoints(snapshot: &ReconSnapshot, output: &mut Vec<ReconHypothesis>) {
        let documented = snapshot
            .assets
            .iter()
            .filter(|asset| {
                asset.kind == ReconAssetKind::Endpoint
                    && asset.tags.iter().any(|tag| tag == "source:api_description")
            })
            .collect::<Vec<_>>();
        for asset in snapshot.assets.iter().filter(|asset| {
            asset.kind == ReconAssetKind::Endpoint
                && asset.tags.iter().any(|tag| tag == "source:javascript")
        }) {
            let validation = validation_outcome(snapshot, &asset.canonical_value);
            let javascript_methods = endpoint_methods(asset);
            let same_path = documented
                .iter()
                .filter(|documented_asset| {
                    endpoint_identity(&documented_asset.canonical_value)
                        == endpoint_identity(&asset.canonical_value)
                })
                .collect::<Vec<_>>();
            let documented_methods = same_path
                .iter()
                .flat_map(|documented_asset| endpoint_methods(documented_asset))
                .collect::<BTreeSet<_>>();
            let missing_methods = javascript_methods
                .difference(&documented_methods)
                .cloned()
                .collect::<Vec<_>>();
            let documented_now = !same_path.is_empty()
                && (javascript_methods.is_empty()
                    || documented_methods.is_empty()
                    || missing_methods.is_empty());
            let mut supporting = observations_for(
                snapshot,
                &[asset.id.clone()],
                Some(ReconObservationSource::JavascriptAnalysis),
            );
            if matches!(validation, Some(ValidationOutcome::Responded)) {
                supporting.extend(validation_observations_for_identity(
                    snapshot,
                    &asset.canonical_value,
                ));
            }
            let mut contradicting = if documented_now {
                observations_for_identity(
                    snapshot,
                    &endpoint_identity(&asset.canonical_value),
                    ReconObservationSource::ApiDescription,
                )
            } else {
                vec![]
            };
            if matches!(validation, Some(ValidationOutcome::NotFound)) {
                contradicting.extend(validation_observations_for_identity(
                    snapshot,
                    &asset.canonical_value,
                ));
            }
            output.push(hypothesis(
                ReconHypothesisKind::UndocumentedEndpoint,
                &[asset],
                if documented_now {
                    format!("{} is now represented by API metadata.", endpoint_identity(&asset.canonical_value))
                } else if !missing_methods.is_empty() {
                    format!(
                        "{} uses JavaScript method(s) {} that are absent from the observed API metadata.",
                        endpoint_identity(&asset.canonical_value),
                        missing_methods.join(", ")
                    )
                } else {
                    format!("{} appears in client JavaScript but is absent from the observed API metadata.", endpoint_identity(&asset.canonical_value))
                },
                if documented_now { ReconHypothesisStatus::Rejected } else { validation_status(validation) },
                "Client-side routes and API descriptions were correlated by normalized endpoint identity; this is a Recon discrepancy, not a vulnerability claim.",
                if documented_now { ReconConfidence::High } else { ReconConfidence::Medium },
                ReconInformationGain::High,
                Some(ReconCapability::ValidateUrlMetadata),
                supporting,
                contradicting,
            ));
        }
    }

    fn public_sensitive_operations(snapshot: &ReconSnapshot, output: &mut Vec<ReconHypothesis>) {
        for asset in snapshot.assets.iter().filter(|asset| {
            asset.kind == ReconAssetKind::Endpoint
                && asset.tags.iter().any(|tag| tag == "api:public_operation")
                && (is_sensitive_surface(asset) || has_sensitive_parameter(snapshot, &asset.id))
        }) {
            output.push(hypothesis(
                ReconHypothesisKind::PublicSensitiveOperation,
                &[asset],
                format!("{} is declared without authentication and has a security-relevant path or parameter.", endpoint_identity(&asset.canonical_value)),
                ReconHypothesisStatus::Supported,
                "The API description explicitly marks the operation as public. This records declared exposure only and does not assert exploitability.",
                ReconConfidence::High,
                ReconInformationGain::Critical,
                None,
                observations_for(snapshot, &[asset.id.clone()], Some(ReconObservationSource::ApiDescription)),
                vec![],
            ));
        }
    }

    fn authentication_surfaces(snapshot: &ReconSnapshot, output: &mut Vec<ReconHypothesis>) {
        for asset in snapshot
            .assets
            .iter()
            .filter(|asset| asset.kind == ReconAssetKind::AuthenticationSurface)
        {
            let source_count = asset
                .tags
                .iter()
                .filter(|tag| tag.starts_with("source:"))
                .collect::<BTreeSet<_>>()
                .len();
            output.push(hypothesis(
                ReconHypothesisKind::AuthenticationSurface,
                &[asset],
                format!("{} is an authentication or session boundary worth deeper mapping.", endpoint_identity(&asset.canonical_value)),
                if source_count >= 2 { ReconHypothesisStatus::Supported } else { ReconHypothesisStatus::Proposed },
                "Authentication boundaries are high-value Recon pivots; confidence increases when independent page, JavaScript, API, or visual sources agree.",
                if source_count >= 2 { ReconConfidence::High } else { ReconConfidence::Medium },
                ReconInformationGain::High,
                None,
                observations_for(snapshot, &[asset.id.clone()], None),
                vec![],
            ));
        }
    }

    fn historical_surfaces(snapshot: &ReconSnapshot, output: &mut Vec<ReconHypothesis>) {
        for asset in snapshot
            .assets
            .iter()
            .filter(|asset| asset.kind == ReconAssetKind::HistoricalUrl)
        {
            let validation = validation_outcome(snapshot, &asset.canonical_value);
            let mut supporting = observations_for(
                snapshot,
                &[asset.id.clone()],
                Some(ReconObservationSource::WebArchive),
            );
            if matches!(validation, Some(ValidationOutcome::Responded)) {
                supporting.extend(validation_observations_for_identity(
                    snapshot,
                    &asset.canonical_value,
                ));
            }
            output.push(hypothesis(
                ReconHypothesisKind::HistoricalSurface,
                &[asset],
                format!("{} is a historical surface whose current state is unverified.", endpoint_identity(&asset.canonical_value)),
                validation_status(validation),
                "Archive metadata is treated as a clue until a separate current observation corroborates it.",
                if validation.is_some() { ReconConfidence::High } else { ReconConfidence::Low },
                ReconInformationGain::Medium,
                Some(ReconCapability::ValidateUrlMetadata),
                supporting,
                if matches!(validation, Some(ValidationOutcome::NotFound)) { validation_observations_for_identity(snapshot, &asset.canonical_value) } else { vec![] },
            ));
        }
    }

    fn source_maps(snapshot: &ReconSnapshot, output: &mut Vec<ReconHypothesis>) {
        for asset in snapshot.assets.iter().filter(|asset| {
            asset.kind == ReconAssetKind::Url
                && asset.tags.iter().any(|tag| {
                    matches!(tag.as_str(), "web:source_map" | "web:source_map_candidate")
                })
        }) {
            let validation = validation_outcome(snapshot, &asset.canonical_value);
            let mut supporting = observations_for(
                snapshot,
                &[asset.id.clone()],
                Some(ReconObservationSource::JavascriptAnalysis),
            );
            if matches!(validation, Some(ValidationOutcome::Responded)) {
                supporting.extend(validation_observations_for_identity(
                    snapshot,
                    &asset.canonical_value,
                ));
            }
            output.push(hypothesis(
                ReconHypothesisKind::SourceMapExposure,
                &[asset],
                format!("{} is a JavaScript-derived source-map candidate.", endpoint_identity(&asset.canonical_value)),
                validation_status(validation),
                "A source-map reference may improve application understanding, but its current availability has not been verified.",
                if validation.is_some() { ReconConfidence::High } else { ReconConfidence::Medium },
                ReconInformationGain::High,
                Some(ReconCapability::ValidateUrlMetadata),
                supporting,
                if matches!(validation, Some(ValidationOutcome::NotFound)) { validation_observations_for_identity(snapshot, &asset.canonical_value) } else { vec![] },
            ));
        }
    }

    fn client_secret_indicators(snapshot: &ReconSnapshot, output: &mut Vec<ReconHypothesis>) {
        for asset in snapshot.assets.iter().filter(|asset| {
            asset.kind == ReconAssetKind::JavascriptBundle
                && asset
                    .tags
                    .iter()
                    .any(|tag| tag == "javascript:secret_indicator")
        }) {
            output.push(hypothesis(
                ReconHypothesisKind::ClientSecretIndicator,
                &[asset],
                format!(
                    "{} contains one or more redacted secret-like client patterns.",
                    endpoint_identity(&asset.canonical_value)
                ),
                ReconHypothesisStatus::Inconclusive,
                "Only indicator categories and counts are retained. This is a high-priority review clue, not proof that a live credential was exposed.",
                ReconConfidence::Medium,
                ReconInformationGain::Critical,
                None,
                observations_for(
                    snapshot,
                    &[asset.id.clone()],
                    Some(ReconObservationSource::JavascriptAnalysis),
                ),
                vec![],
            ));
        }
    }

    fn client_security_signals(snapshot: &ReconSnapshot, output: &mut Vec<ReconHypothesis>) {
        for asset in snapshot
            .assets
            .iter()
            .filter(|asset| asset.kind == ReconAssetKind::JavascriptBundle)
        {
            let signals = asset
                .tags
                .iter()
                .filter_map(|tag| tag.strip_prefix("javascript:security_signal:"))
                .chain(
                    asset
                        .tags
                        .iter()
                        .any(|tag| tag == "javascript:graphql_operations")
                        .then_some("graphql_operations"),
                )
                .chain(
                    asset
                        .tags
                        .iter()
                        .any(|tag| tag == "javascript:websocket")
                        .then_some("websocket_endpoint"),
                )
                .collect::<BTreeSet<_>>();
            if signals.is_empty() {
                continue;
            }
            output.push(hypothesis(
                ReconHypothesisKind::ClientSecuritySignal,
                &[asset],
                format!(
                    "{} contains security-relevant client behavior: {}.",
                    endpoint_identity(&asset.canonical_value),
                    signals.into_iter().collect::<Vec<_>>().join(", ")
                ),
                ReconHypothesisStatus::Supported,
                "Static JavaScript evidence confirms that the behavior exists, but data flow and exploitability still require focused human or later capability review.",
                ReconConfidence::High,
                ReconInformationGain::High,
                None,
                observations_for(
                    snapshot,
                    &[asset.id.clone()],
                    Some(ReconObservationSource::JavascriptAnalysis),
                ),
                vec![],
            ));
        }
    }

    fn high_value_parameters(snapshot: &ReconSnapshot, output: &mut Vec<ReconHypothesis>) {
        for asset in snapshot.assets.iter().filter(|asset| {
            asset.kind == ReconAssetKind::Parameter
                && asset
                    .tags
                    .iter()
                    .any(|tag| tag.starts_with("parameter:sensitivity:"))
        }) {
            output.push(hypothesis(
                ReconHypothesisKind::HighValueParameter,
                &[asset],
                format!("{} is a security-relevant input boundary discovered during Recon.", asset.display_name.as_deref().unwrap_or(&asset.canonical_value)),
                ReconHypothesisStatus::Proposed,
                "The parameter name and location suggest an authorization, authentication, redirect, file, or object-selection boundary; no payload has been sent.",
                ReconConfidence::Medium,
                ReconInformationGain::High,
                None,
                observations_for(snapshot, &[asset.id.clone()], None),
                vec![],
            ));
        }
    }

    fn unverified_assets(snapshot: &ReconSnapshot, output: &mut Vec<ReconHypothesis>) {
        for asset in snapshot.assets.iter().filter(|asset| {
            matches!(
                asset.kind,
                ReconAssetKind::RootDomain | ReconAssetKind::Subdomain
            ) && asset.tags.iter().any(|tag| tag == "dns:wildcard_match")
        }) {
            let source_count = asset
                .tags
                .iter()
                .filter(|tag| tag.starts_with("source:"))
                .collect::<BTreeSet<_>>()
                .len();
            output.push(hypothesis(
                ReconHypothesisKind::UnverifiedAsset,
                &[asset],
                format!("{} may be a wildcard-DNS artifact rather than a distinct live asset.", asset.canonical_value),
                if source_count >= 2 { ReconHypothesisStatus::Rejected } else { ReconHypothesisStatus::Proposed },
                "Wildcard DNS alone is insufficient evidence; an independent source is required before prioritizing the hostname.",
                if source_count >= 2 { ReconConfidence::High } else { ReconConfidence::Low },
                ReconInformationGain::Medium,
                Some(ReconCapability::ProbeHttp),
                observations_for(snapshot, &[asset.id.clone()], Some(ReconObservationSource::DnsQuery)),
                vec![],
            ));
        }
    }

    fn potential_dangling_dns(snapshot: &ReconSnapshot, output: &mut Vec<ReconHypothesis>) {
        for asset in snapshot.assets.iter().filter(|asset| {
            matches!(
                asset.kind,
                ReconAssetKind::RootDomain | ReconAssetKind::Subdomain
            ) && asset.tags.iter().any(|tag| tag == "dns:dangling_candidate")
        }) {
            let probed = !observations_for(
                snapshot,
                &[asset.id.clone()],
                Some(ReconObservationSource::HttpProbe),
            )
            .is_empty();
            output.push(hypothesis(
                ReconHypothesisKind::PotentialDanglingDns,
                &[asset],
                format!("{} has an external alias without an observed address record.", asset.canonical_value),
                if probed { ReconHypothesisStatus::Inconclusive } else { ReconHypothesisStatus::Proposed },
                "This is an ownership-review signal only. DNS metadata alone cannot prove that a resource is claimable.",
                ReconConfidence::Medium,
                ReconInformationGain::Critical,
                Some(ReconCapability::ProbeHttp),
                observations_for(snapshot, &[asset.id.clone()], Some(ReconObservationSource::DnsOwnership)),
                vec![],
            ));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn hypothesis(
    kind: ReconHypothesisKind,
    assets: &[&ReconAsset],
    statement: String,
    status: ReconHypothesisStatus,
    rationale: &str,
    confidence: ReconConfidence,
    priority: ReconInformationGain,
    recommended_capability: Option<ReconCapability>,
    supporting_observation_ids: Vec<ReconObservationId>,
    contradicting_observation_ids: Vec<ReconObservationId>,
) -> ReconHypothesis {
    let mut subject_asset_ids = assets
        .iter()
        .map(|asset| asset.id.clone())
        .collect::<Vec<_>>();
    subject_asset_ids.sort_by(|left, right| left.0.cmp(&right.0));
    ReconHypothesis {
        schema_version: CORE_SCHEMA_VERSION,
        id: stable_hypothesis_id(kind, &subject_asset_ids),
        kind: Some(kind),
        statement,
        status,
        subject_asset_ids,
        rationale: rationale.into(),
        confidence,
        priority: Some(priority),
        recommended_capability,
        supporting_observation_ids,
        contradicting_observation_ids,
    }
}

fn observations_for(
    snapshot: &ReconSnapshot,
    asset_ids: &[ReconAssetId],
    source: Option<ReconObservationSource>,
) -> Vec<ReconObservationId> {
    let mut observations = snapshot
        .observations
        .iter()
        .filter(|observation| source.map_or(true, |expected| observation.source == expected))
        .filter(|observation| {
            observation
                .subject_asset_ids
                .iter()
                .any(|asset_id| asset_ids.contains(asset_id))
        })
        .map(|observation| observation.id.clone())
        .collect::<Vec<_>>();
    observations.sort_by(|left, right| left.0.cmp(&right.0));
    observations.dedup();
    observations
}

#[derive(Clone, Copy)]
enum ValidationOutcome {
    Responded,
    NotFound,
    Inconclusive,
}

fn validation_status(outcome: Option<ValidationOutcome>) -> ReconHypothesisStatus {
    match outcome {
        Some(ValidationOutcome::Responded) => ReconHypothesisStatus::Supported,
        Some(ValidationOutcome::NotFound) => ReconHypothesisStatus::Rejected,
        Some(ValidationOutcome::Inconclusive) => ReconHypothesisStatus::Inconclusive,
        None => ReconHypothesisStatus::Proposed,
    }
}

fn validation_outcome(snapshot: &ReconSnapshot, identity: &str) -> Option<ValidationOutcome> {
    let normalized = endpoint_identity(identity);
    snapshot.observations.iter().rev().find_map(|observation| {
        if observation.source != ReconObservationSource::ActiveValidation {
            return None;
        }
        let url = observation
            .facts
            .get("url")
            .and_then(serde_json::Value::as_str)?;
        if endpoint_identity(url) != normalized {
            return None;
        }
        match observation
            .facts
            .get("status_code")
            .and_then(serde_json::Value::as_u64)
        {
            Some(404 | 410) => Some(ValidationOutcome::NotFound),
            Some(405 | 501) | None => Some(ValidationOutcome::Inconclusive),
            Some(_) => Some(ValidationOutcome::Responded),
        }
    })
}

fn validation_observations_for_identity(
    snapshot: &ReconSnapshot,
    identity: &str,
) -> Vec<ReconObservationId> {
    let normalized = endpoint_identity(identity);
    snapshot
        .observations
        .iter()
        .filter(|observation| observation.source == ReconObservationSource::ActiveValidation)
        .filter(|observation| {
            observation
                .facts
                .get("url")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|url| endpoint_identity(url) == normalized)
        })
        .map(|observation| observation.id.clone())
        .collect()
}

fn observations_for_identity(
    snapshot: &ReconSnapshot,
    identity: &str,
    source: ReconObservationSource,
) -> Vec<ReconObservationId> {
    let assets = snapshot
        .assets
        .iter()
        .filter(|asset| endpoint_identity(&asset.canonical_value) == identity)
        .map(|asset| asset.id.clone())
        .collect::<Vec<_>>();
    observations_for(snapshot, &assets, Some(source))
}

fn endpoint_identity(value: &str) -> String {
    value.split("#hexhunt-").next().unwrap_or(value).to_string()
}

fn endpoint_methods(asset: &ReconAsset) -> BTreeSet<String> {
    asset
        .tags
        .iter()
        .filter_map(|tag| tag.strip_prefix("http:method:"))
        .map(|method| method.to_ascii_uppercase())
        .collect()
}

fn is_sensitive_surface(asset: &ReconAsset) -> bool {
    let value = asset.canonical_value.to_ascii_lowercase();
    [
        "admin",
        "account",
        "user",
        "role",
        "permission",
        "auth",
        "login",
        "session",
        "token",
        "billing",
        "payment",
        "upload",
        "file",
        "internal",
    ]
    .iter()
    .any(|needle| value.contains(needle))
        || asset
            .tags
            .iter()
            .any(|tag| tag.starts_with("parameter:sensitivity:"))
}

fn has_sensitive_parameter(snapshot: &ReconSnapshot, asset_id: &ReconAssetId) -> bool {
    snapshot
        .relations
        .iter()
        .filter(|relation| relation.from_asset_id == *asset_id)
        .filter_map(|relation| {
            snapshot
                .assets
                .iter()
                .find(|asset| asset.id == relation.to_asset_id)
        })
        .any(|asset| {
            asset.kind == ReconAssetKind::Parameter
                && asset
                    .tags
                    .iter()
                    .any(|tag| tag.starts_with("parameter:sensitivity:"))
        })
}

fn stable_hypothesis_id(
    kind: ReconHypothesisKind,
    asset_ids: &[ReconAssetId],
) -> ReconHypothesisId {
    let mut state = 0xcbf29ce484222325_u64;
    let identity = format!(
        "{kind:?}:{}",
        asset_ids
            .iter()
            .map(|id| id.0.as_str())
            .collect::<Vec<_>>()
            .join("|")
    );
    for byte in identity.bytes() {
        state = (state ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    ReconHypothesisId(format!("recon-hypothesis-{state:016x}"))
}

fn priority_value(priority: Option<ReconInformationGain>) -> u8 {
    match priority {
        Some(ReconInformationGain::Critical) => 4,
        Some(ReconInformationGain::High) => 3,
        Some(ReconInformationGain::Medium) => 2,
        Some(ReconInformationGain::Low) => 1,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        ReconObservation, ReconScopeClassification, ReconSnapshotId, StructuredData,
    };

    fn asset(id: &str, kind: ReconAssetKind, value: &str, tags: &[&str]) -> ReconAsset {
        ReconAsset {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconAssetId(id.into()),
            kind,
            canonical_value: value.into(),
            display_name: None,
            scope: ReconScopeClassification::InScope,
            scope_reason: "Authorized.".into(),
            confidence: ReconConfidence::High,
            first_seen_at_ms: 1,
            last_seen_at_ms: 1,
            tags: tags.iter().map(|tag| (*tag).into()).collect(),
        }
    }

    fn observation(
        id: &str,
        run_id: &RunId,
        source: ReconObservationSource,
        asset_id: &str,
    ) -> ReconObservation {
        ReconObservation {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconObservationId(id.into()),
            run_id: run_id.clone(),
            source,
            subject_asset_ids: vec![ReconAssetId(asset_id.into())],
            summary: "Observed.".into(),
            facts: StructuredData::new(),
            confidence: ReconConfidence::High,
            evidence_ids: vec![],
            observed_at_ms: 1,
        }
    }

    #[test]
    fn correlation_rejects_undocumented_hypothesis_after_api_corroboration() {
        let run_id = RunId("run-correlation".into());
        let mut snapshot = ReconSnapshot::empty(
            ReconSnapshotId("snapshot-correlation".into()),
            run_id.clone(),
            1,
        );
        snapshot.assets = vec![
            asset(
                "js-endpoint",
                ReconAssetKind::Endpoint,
                "https://example.test/api/users",
                &["source:javascript", "http:method:get"],
            ),
            asset(
                "api-operation",
                ReconAssetKind::Endpoint,
                "https://example.test/api/users#hexhunt-method-get",
                &["source:api_description", "http:method:get"],
            ),
        ];
        snapshot.observations = vec![
            observation(
                "js-observation",
                &run_id,
                ReconObservationSource::JavascriptAnalysis,
                "js-endpoint",
            ),
            observation(
                "api-observation",
                &run_id,
                ReconObservationSource::ApiDescription,
                "api-operation",
            ),
        ];

        let hypotheses = ReconCorrelator::derive(&snapshot);
        let hypothesis = hypotheses
            .iter()
            .find(|hypothesis| hypothesis.kind == Some(ReconHypothesisKind::UndocumentedEndpoint))
            .unwrap();
        assert_eq!(hypothesis.status, ReconHypothesisStatus::Rejected);
        assert_eq!(hypothesis.contradicting_observation_ids.len(), 1);

        snapshot.assets[0].tags = vec!["source:javascript".into(), "http:method:post".into()];
        let hypotheses = ReconCorrelator::derive(&snapshot);
        let hypothesis = hypotheses
            .iter()
            .find(|hypothesis| hypothesis.kind == Some(ReconHypothesisKind::UndocumentedEndpoint))
            .unwrap();
        assert_eq!(hypothesis.status, ReconHypothesisStatus::Proposed);
        assert!(hypothesis.statement.contains("POST"));
    }

    #[test]
    fn high_value_parameter_and_public_operation_become_prioritized_hypotheses() {
        let run_id = RunId("run-priority".into());
        let mut snapshot =
            ReconSnapshot::empty(ReconSnapshotId("snapshot-priority".into()), run_id, 1);
        snapshot.assets = vec![
            asset(
                "public-operation",
                ReconAssetKind::Endpoint,
                "https://example.test/admin/users#hexhunt-method-get",
                &["source:api_description", "api:public_operation"],
            ),
            asset(
                "parameter",
                ReconAssetKind::Parameter,
                "https://example.test/admin/users#hexhunt-parameter-query-user_id",
                &["parameter:sensitivity:object_reference"],
            ),
        ];

        let hypotheses = ReconCorrelator::derive(&snapshot);
        assert!(hypotheses.iter().any(|hypothesis| {
            hypothesis.kind == Some(ReconHypothesisKind::PublicSensitiveOperation)
                && hypothesis.priority == Some(ReconInformationGain::Critical)
        }));
        assert!(hypotheses.iter().any(|hypothesis| {
            hypothesis.kind == Some(ReconHypothesisKind::HighValueParameter)
        }));
    }
}
