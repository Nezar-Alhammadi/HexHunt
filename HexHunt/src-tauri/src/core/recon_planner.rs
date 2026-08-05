use super::{
    AgentAction, ReconAction, ReconActionId, ReconActionScore, ReconAsset, ReconAssetKind,
    ReconCapability, ReconConfidence, ReconCoverageSummary, ReconDecision, ReconHypothesis,
    ReconHypothesisStatus, ReconInformationGain, ReconKnowledgeGap, ReconKnowledgeGapId,
    ReconMemory, ReconMode, ReconObservationSource, ReconRisk, ReconScopeClassification,
    ReconSnapshot, ReconStopReasonCode, StructuredData, Task, CORE_SCHEMA_VERSION,
};
use serde_json::Value;
use std::collections::BTreeSet;
use url::Url;

const MAX_CANDIDATE_ACTIONS: usize = 24;
const MIN_ACTION_SCORE: i32 = 180;

pub struct ReconPlanner;

impl ReconPlanner {
    pub fn plan(task: &Task, snapshot: &ReconSnapshot, step: u64) -> Option<ReconDecision> {
        Self::plan_with_memory(task, snapshot, &ReconMemory::default(), step)
    }

    pub fn plan_with_memory(
        task: &Task,
        snapshot: &ReconSnapshot,
        memory: &ReconMemory,
        step: u64,
    ) -> Option<ReconDecision> {
        if !task.available_tools.iter().any(|tool| is_recon_tool(tool)) {
            return None;
        }

        let mut proposals = Vec::new();
        Self::add_hypothesis_candidates(task, snapshot, step, &mut proposals);
        for asset in &snapshot.assets {
            if !matches!(asset.scope, ReconScopeClassification::InScope) {
                continue;
            }
            match asset.kind {
                ReconAssetKind::RootDomain => {
                    Self::add_external_candidate(snapshot, step, asset, &mut proposals);
                    if !observed(snapshot, &asset.id, ReconObservationSource::Rdap) {
                        proposals.push(candidate(
                            snapshot,
                            step,
                            &proposals,
                            ReconCapability::InspectRdap,
                            asset,
                            StructuredData::from([("target".into(), Value::String(asset.canonical_value.clone()))]),
                            "Map public registration and ownership metadata without retaining contact entities.",
                            ReconInformationGain::Medium,
                            ReconRisk::Passive,
                        ));
                    }
                    if !observed(
                        snapshot,
                        &asset.id,
                        ReconObservationSource::CertificateTransparency,
                    ) {
                        proposals.push(candidate(
                            snapshot,
                            step,
                            &proposals,
                            ReconCapability::SearchCertificateTransparency,
                            asset,
                            StructuredData::from([(
                                "domain".into(),
                                Value::String(asset.canonical_value.clone()),
                            )]),
                            "Search passive certificate records for additional authorized candidates.",
                            ReconInformationGain::High,
                            ReconRisk::Passive,
                        ));
                    }
                    if !observed(snapshot, &asset.id, ReconObservationSource::WebArchive) {
                        proposals.push(candidate(
                            snapshot,
                            step,
                            &proposals,
                            ReconCapability::LookupWebArchive,
                            asset,
                            StructuredData::from([(
                                "domain".into(),
                                Value::String(asset.canonical_value.clone()),
                            )]),
                            "Search passive archive indexes for historical paths, JavaScript, endpoints, and hostnames that are absent from the current graph.",
                            ReconInformationGain::High,
                            ReconRisk::Passive,
                        ));
                    }
                    Self::add_dns_ownership_candidate(snapshot, step, asset, &mut proposals);
                    Self::add_host_candidates(task, snapshot, step, asset, &mut proposals);
                }
                ReconAssetKind::Subdomain => {
                    Self::add_external_candidate(snapshot, step, asset, &mut proposals);
                    Self::add_dns_ownership_candidate(snapshot, step, asset, &mut proposals);
                    Self::add_host_candidates(task, snapshot, step, asset, &mut proposals);
                }
                ReconAssetKind::HistoricalUrl | ReconAssetKind::Endpoint => {
                    Self::add_validation_candidate(snapshot, step, asset, &mut proposals);
                }
                ReconAssetKind::IpAddress => {
                    Self::add_external_candidate(snapshot, step, asset, &mut proposals);
                    if !observed(snapshot, &asset.id, ReconObservationSource::Rdap) {
                        proposals.push(candidate(
                            snapshot,
                            step,
                            &proposals,
                            ReconCapability::InspectRdap,
                            asset,
                            StructuredData::from([("target".into(), Value::String(asset.canonical_value.clone()))]),
                            "Map the authorized address to public network-range and ASN ownership metadata.",
                            ReconInformationGain::High,
                            ReconRisk::Passive,
                        ));
                    }
                    Self::add_tcp_candidates(task, snapshot, step, asset, &mut proposals);
                    for url in probe_urls(task, &asset.canonical_value)
                        .into_iter()
                        .filter(|url| !http_origin_observed(snapshot, &asset.id, url))
                    {
                        proposals.push(candidate(
                            snapshot,
                            step,
                            &proposals,
                            ReconCapability::ProbeHttp,
                            asset,
                            StructuredData::from([("url".into(), Value::String(url))]),
                            "Verify whether the authorized address exposes an HTTP service.",
                            ReconInformationGain::High,
                            ReconRisk::LowImpact,
                        ));
                    }
                }
                ReconAssetKind::HttpService => {
                    if !observed(
                        snapshot,
                        &asset.id,
                        ReconObservationSource::ContentDiscovery,
                    ) {
                        let paths = content_discovery_paths(snapshot, asset);
                        if !paths.is_empty() {
                            proposals.push(candidate(
                                snapshot,
                                step,
                                &proposals,
                                ReconCapability::DiscoverContent,
                                asset,
                                StructuredData::from([
                                    ("base_url".into(), Value::String(asset.canonical_value.clone())),
                                    ("paths".into(), Value::Array(paths.into_iter().map(Value::String).collect())),
                                ]),
                                "Check a bounded set of evidence-guided paths using bodyless requests.",
                                ReconInformationGain::High,
                                ReconRisk::LowImpact,
                            ));
                        }
                    }
                    if !observed(snapshot, &asset.id, ReconObservationSource::Sitemap) {
                        proposals.push(candidate(
                            snapshot,
                            step,
                            &proposals,
                            ReconCapability::FetchSitemap,
                            asset,
                            StructuredData::from([(
                                "base_url".into(),
                                Value::String(asset.canonical_value.clone()),
                            )]),
                            "Read the declared sitemap to expand known paths without crawling.",
                            ReconInformationGain::High,
                            ReconRisk::LowImpact,
                        ));
                    }
                    if !observed(snapshot, &asset.id, ReconObservationSource::RobotsTxt) {
                        proposals.push(candidate(
                            snapshot,
                            step,
                            &proposals,
                            ReconCapability::FetchRobotsTxt,
                            asset,
                            StructuredData::from([(
                                "base_url".into(),
                                Value::String(asset.canonical_value.clone()),
                            )]),
                            "Read robots.txt for explicitly disclosed paths.",
                            ReconInformationGain::Medium,
                            ReconRisk::LowImpact,
                        ));
                    }
                }
                ReconAssetKind::Url => {
                    if is_source_map_candidate(asset) {
                        Self::add_validation_candidate(snapshot, step, asset, &mut proposals);
                    }
                    if (asset.tags.iter().any(|tag| tag == "web:discovered_link")
                        || (asset.tags.iter().any(|tag| tag == "http:observed")
                            && is_successful_web_page(asset)))
                        && !observed(snapshot, &asset.id, ReconObservationSource::WebPageAnalysis)
                    {
                        proposals.push(candidate(
                            snapshot,
                            step,
                            &proposals,
                            ReconCapability::AnalyzeWebPage,
                            asset,
                            StructuredData::from([(
                                "url".into(),
                                Value::String(asset.canonical_value.clone()),
                            )]),
                            "Analyze this discovered page for in-scope links, forms, scripts, and security-relevant surface signals without retaining raw HTML.",
                            ReconInformationGain::High,
                            ReconRisk::LowImpact,
                        ));
                    }
                    if observed(snapshot, &asset.id, ReconObservationSource::WebPageAnalysis)
                        && !observed(snapshot, &asset.id, ReconObservationSource::AdaptiveBrowser)
                    {
                        proposals.push(candidate(
                            snapshot,
                            step,
                            &proposals,
                            ReconCapability::AdaptiveBrowserRecon,
                            asset,
                            StructuredData::from([("url".into(), Value::String(asset.canonical_value.clone()))]),
                            "Observe the rendered DOM, SPA state, and scope-filtered network metadata for this authorized page.",
                            ReconInformationGain::High,
                            ReconRisk::LowImpact,
                        ));
                    }
                    if (observed(snapshot, &asset.id, ReconObservationSource::HttpProbe)
                        || observed(snapshot, &asset.id, ReconObservationSource::WebPageAnalysis))
                        && !observed(snapshot, &asset.id, ReconObservationSource::VisualAnalysis)
                    {
                        proposals.push(candidate(
                            snapshot,
                            step,
                            &proposals,
                            ReconCapability::AnalyzeVisualPage,
                            asset,
                            StructuredData::from([(
                                "url".into(),
                                Value::String(asset.canonical_value.clone()),
                            )]),
                            "Use the visible page structure to classify authentication, administration, documentation, and error surfaces.",
                            ReconInformationGain::Medium,
                            ReconRisk::LowImpact,
                        ));
                    }
                }
                ReconAssetKind::JavascriptBundle => {
                    if !observed(
                        snapshot,
                        &asset.id,
                        ReconObservationSource::JavascriptAnalysis,
                    ) {
                        proposals.push(candidate(
                            snapshot,
                            step,
                            &proposals,
                            ReconCapability::AnalyzeJavascript,
                            asset,
                            StructuredData::from([(
                                "url".into(),
                                Value::String(asset.canonical_value.clone()),
                            )]),
                            "Analyze a discovered JavaScript bundle for endpoint methods, parameters, authentication signals, GraphQL operations, imported chunks, technologies, source maps, and redacted secret indicators.",
                            ReconInformationGain::High,
                            ReconRisk::LowImpact,
                        ));
                    }
                }
                ReconAssetKind::Api => {
                    if is_api_description_candidate(&asset.canonical_value)
                        && !observed(snapshot, &asset.id, ReconObservationSource::ApiDescription)
                    {
                        proposals.push(candidate(
                            snapshot,
                            step,
                            &proposals,
                            ReconCapability::DescribeApi,
                            asset,
                            StructuredData::from([(
                                "url".into(),
                                Value::String(asset.canonical_value.clone()),
                            )]),
                            "Read discovered API metadata and map operations, parameters, authentication requirements, schemas, servers, and GraphQL structure without invoking business operations.",
                            ReconInformationGain::High,
                            ReconRisk::LowImpact,
                        ));
                    }
                }
                _ => {}
            }
            if proposals.len() >= MAX_CANDIDATE_ACTIONS * 2 {
                break;
            }
        }

        proposals = deduplicate_actions(proposals);

        let knowledge_gaps = proposals
            .iter()
            .enumerate()
            .map(|(index, action)| {
                let tool_available = tool_allowed(task, tool_for_capability(action.capability));
                let repeated = action_was_selected(snapshot, action);
                let blocked_reason = if repeated {
                    Some("The same action was already selected and cannot be repeated without new evidence.".into())
                } else if !tool_available {
                    Some(format!(
                        "Required capability '{}' is not available for this task.",
                        tool_for_capability(action.capability)
                    ))
                } else {
                    None
                };
                ReconKnowledgeGap {
                    schema_version: CORE_SCHEMA_VERSION,
                    id: ReconKnowledgeGapId(format!(
                        "recon-gap-{}-{step}-{}",
                        snapshot.run_id.0,
                        index + 1
                    )),
                    asset_id: action.target_asset_ids[0].clone(),
                    capability: action.capability,
                    description: action.reason.clone(),
                    priority: action.expected_information_gain,
                    actionable: blocked_reason.is_none(),
                    blocked_reason,
                }
            })
            .collect::<Vec<_>>();

        let mut candidates = proposals
            .into_iter()
            .filter(|action| {
                tool_allowed(task, tool_for_capability(action.capability))
                    && !action_was_selected(snapshot, action)
            })
            .take(MAX_CANDIDATE_ACTIONS)
            .collect::<Vec<_>>();
        let mut action_scores = candidates
            .iter()
            .map(|action| score_action(snapshot, memory, action))
            .collect::<Vec<_>>();
        action_scores.sort_by(|left, right| {
            right
                .total
                .cmp(&left.total)
                .then_with(|| left.action_id.0.cmp(&right.action_id.0))
        });
        candidates.sort_by(|left, right| {
            score_for(&action_scores, right)
                .cmp(&score_for(&action_scores, left))
                .then_with(|| left.id.0.cmp(&right.id.0))
        });

        let recommended_action_id = action_scores
            .first()
            .filter(|score| score.total >= MIN_ACTION_SCORE)
            .map(|score| score.action_id.clone());
        let active_hypotheses = snapshot
            .hypotheses
            .iter()
            .filter(|hypothesis| {
                matches!(
                    hypothesis.status,
                    ReconHypothesisStatus::Proposed | ReconHypothesisStatus::Testing
                )
            })
            .count();
        let unresolved_actionable_hypotheses = snapshot
            .hypotheses
            .iter()
            .filter(|hypothesis| {
                matches!(
                    hypothesis.status,
                    ReconHypothesisStatus::Proposed | ReconHypothesisStatus::Testing
                ) && hypothesis.recommended_capability.is_some()
            })
            .count();
        let review_only_hypotheses =
            active_hypotheses.saturating_sub(unresolved_actionable_hypotheses);
        let stop_reason_code = if candidates.is_empty() {
            if knowledge_gaps.is_empty() && unresolved_actionable_hypotheses == 0 {
                Some(ReconStopReasonCode::CoverageComplete)
            } else {
                Some(ReconStopReasonCode::RequiredCapabilityUnavailable)
            }
        } else if recommended_action_id.is_none() {
            Some(ReconStopReasonCode::MarginalInformationGainTooLow)
        } else {
            None
        };
        let hypothesis_id = recommended_action_id
            .as_ref()
            .and_then(|action_id| {
                candidates
                    .iter()
                    .find(|candidate| candidate.id == *action_id)
            })
            .and_then(|action| prioritized_hypothesis(snapshot, Some(action)))
            .or_else(|| prioritized_hypothesis(snapshot, None))
            .map(|hypothesis| hypothesis.id.clone());
        let mode = if stop_reason_code.is_some() {
            ReconMode::Stop
        } else if hypothesis_id.is_some() {
            ReconMode::Verify
        } else if candidates.iter().any(|action| {
            matches!(
                action.capability,
                ReconCapability::SearchCertificateTransparency
                    | ReconCapability::LookupWebArchive
                    | ReconCapability::ResolveDns
            )
        }) {
            ReconMode::Breadth
        } else if candidates
            .iter()
            .any(|action| action.capability == ReconCapability::ProbeHttp)
        {
            ReconMode::Verify
        } else {
            ReconMode::Depth
        };

        let in_scope_assets = snapshot
            .assets
            .iter()
            .filter(|asset| asset.scope == ReconScopeClassification::InScope)
            .count();
        let verified_in_scope_assets = snapshot
            .assets
            .iter()
            .filter(|asset| {
                asset.scope == ReconScopeClassification::InScope
                    && (asset.confidence == ReconConfidence::Confirmed
                        || asset.tags.iter().any(|tag| {
                            matches!(
                                tag.as_str(),
                                "http:live" | "dns:resolved" | "validation:responded"
                            )
                        }))
            })
            .count();
        let host_assets = snapshot
            .assets
            .iter()
            .filter(|asset| {
                asset.scope == ReconScopeClassification::InScope
                    && matches!(
                        asset.kind,
                        ReconAssetKind::RootDomain | ReconAssetKind::Subdomain
                    )
            })
            .count();
        let dns_ownership_observed_hosts = snapshot
            .assets
            .iter()
            .filter(|asset| {
                asset.scope == ReconScopeClassification::InScope
                    && matches!(
                        asset.kind,
                        ReconAssetKind::RootDomain | ReconAssetKind::Subdomain
                    )
                    && observed(snapshot, &asset.id, ReconObservationSource::DnsOwnership)
            })
            .count();
        let validation_candidates = snapshot
            .assets
            .iter()
            .filter(|asset| {
                asset.scope == ReconScopeClassification::InScope
                    && (matches!(
                        asset.kind,
                        ReconAssetKind::HistoricalUrl | ReconAssetKind::Endpoint
                    ) || is_source_map_candidate(asset))
            })
            .count();
        let validated_candidates = snapshot
            .assets
            .iter()
            .filter(|asset| {
                asset.scope == ReconScopeClassification::InScope
                    && (matches!(
                        asset.kind,
                        ReconAssetKind::HistoricalUrl | ReconAssetKind::Endpoint
                    ) || is_source_map_candidate(asset))
                    && active_validation_observed(
                        snapshot,
                        asset
                            .canonical_value
                            .split("#hexhunt-")
                            .next()
                            .unwrap_or(&asset.canonical_value),
                    )
            })
            .count();
        let observed_assets = snapshot
            .assets
            .iter()
            .filter(|asset| {
                asset.scope == ReconScopeClassification::InScope
                    && snapshot
                        .observations
                        .iter()
                        .any(|observation| observation.subject_asset_ids.contains(&asset.id))
            })
            .count();
        let coverage = ReconCoverageSummary {
            in_scope_assets,
            observed_assets,
            actionable_gaps: knowledge_gaps.iter().filter(|gap| gap.actionable).count(),
            blocked_gaps: knowledge_gaps.iter().filter(|gap| !gap.actionable).count(),
            coverage_percent: if in_scope_assets == 0 {
                0
            } else {
                ((observed_assets * 100) / in_scope_assets).min(100) as u8
            },
            active_hypotheses,
            supported_hypotheses: snapshot
                .hypotheses
                .iter()
                .filter(|hypothesis| hypothesis.status == ReconHypothesisStatus::Supported)
                .count(),
            verified_in_scope_assets,
            unresolved_actionable_hypotheses,
            review_only_hypotheses,
            host_assets,
            dns_ownership_observed_hosts,
            validation_candidates,
            validated_candidates,
            review_ready: recommended_action_id.is_none() && unresolved_actionable_hypotheses == 0,
        };
        let stop_reason = stop_reason_code.map(|code| match code {
            ReconStopReasonCode::CoverageComplete => {
                "No unresolved Recon knowledge gap remains for the current graph.".into()
            }
            ReconStopReasonCode::RequiredCapabilityUnavailable => {
                "Knowledge gaps remain, but none can be acted on with the authorized tools.".into()
            }
            ReconStopReasonCode::MarginalInformationGainTooLow => {
                "The remaining actions do not meet the minimum expected information gain.".into()
            }
        });
        let decision_summary = if let Some(action_id) = &recommended_action_id {
            let score = action_scores
                .iter()
                .find(|score| score.action_id == *action_id)
                .map(|score| score.total)
                .unwrap_or_default();
            format!(
                "Recommended '{}' with score {score}; {} actionable gaps, {} blocked gaps, {} actionable hypotheses, and {} review-only hypotheses remain.",
                action_id.0, coverage.actionable_gaps, coverage.blocked_gaps, coverage.unresolved_actionable_hypotheses, coverage.review_only_hypotheses
            )
        } else {
            stop_reason
                .clone()
                .unwrap_or_else(|| "No safe Recon action is currently recommended.".into())
        };
        Some(ReconDecision {
            schema_version: CORE_SCHEMA_VERSION,
            run_id: snapshot.run_id.clone(),
            step,
            mode,
            hypothesis_id,
            knowledge_gaps,
            candidate_actions: candidates,
            action_scores,
            recommended_action_id,
            selected_action_id: None,
            coverage: Some(coverage),
            decision_summary,
            stop_reason_code,
            stop_reason,
        })
    }

    pub fn record_selection(decision: &mut ReconDecision, action: &AgentAction) {
        let Some(capability) = capability_for_tool(&action.name) else {
            return;
        };
        decision.selected_action_id = decision
            .candidate_actions
            .iter()
            .find(|candidate| {
                candidate.capability == capability
                    && candidate.arguments.iter().all(|(key, expected)| {
                        action
                            .arguments
                            .get(key)
                            .is_some_and(|actual| actual == expected)
                    })
            })
            .map(|candidate| candidate.id.clone());
        decision.decision_summary = if decision.selected_action_id.is_some() {
            let score = decision
                .action_scores
                .iter()
                .find(|score| Some(&score.action_id) == decision.selected_action_id.as_ref())
                .map(|score| score.total)
                .unwrap_or_default();
            let recommendation = if decision.selected_action_id == decision.recommended_action_id {
                "the recommended action"
            } else {
                "an allowed alternative"
            };
            format!(
                "The agent selected {recommendation} '{}' with score {score}.",
                action.name
            )
        } else {
            format!(
                "The agent selected '{}' outside the current suggested candidates.",
                action.name
            )
        };
    }

    pub fn selection_rejection_reason(
        snapshot: &ReconSnapshot,
        action: &AgentAction,
    ) -> Option<String> {
        let capability = capability_for_tool(&action.name)?;
        snapshot
            .decisions
            .iter()
            .filter_map(selected_action)
            .any(|selected| {
                selected.capability == capability && selected.arguments == action.arguments
            })
            .then(|| {
                format!(
                    "Recon action '{}' exactly repeats a previously selected action without new evidence.",
                    action.name
                )
            })
    }

    fn add_host_candidates(
        _task: &Task,
        snapshot: &ReconSnapshot,
        step: u64,
        asset: &ReconAsset,
        candidates: &mut Vec<ReconAction>,
    ) {
        if !observed(snapshot, &asset.id, ReconObservationSource::DnsQuery) {
            candidates.push(candidate(
                snapshot,
                step,
                candidates,
                ReconCapability::ResolveDns,
                asset,
                StructuredData::from([(
                    "hostname".into(),
                    Value::String(asset.canonical_value.clone()),
                )]),
                "Resolve the in-scope hostname and connect it to observed addresses.",
                ReconInformationGain::Medium,
                ReconRisk::Passive,
            ));
        }
        Self::add_tcp_candidates(_task, snapshot, step, asset, candidates);
        for url in probe_urls(_task, &asset.canonical_value)
            .into_iter()
            .filter(|url| !http_origin_observed(snapshot, &asset.id, url))
        {
            candidates.push(candidate(
                snapshot,
                step,
                candidates,
                ReconCapability::ProbeHttp,
                asset,
                StructuredData::from([("url".into(), Value::String(url))]),
                "Verify whether the in-scope host exposes an HTTP service.",
                ReconInformationGain::High,
                ReconRisk::LowImpact,
            ));
        }
    }

    fn add_tcp_candidates(
        task: &Task,
        snapshot: &ReconSnapshot,
        step: u64,
        asset: &ReconAsset,
        candidates: &mut Vec<ReconAction>,
    ) {
        for port in task.scope.allowed_ports.iter().copied().take(8) {
            if tcp_port_observed(snapshot, &asset.id, port) {
                continue;
            }
            candidates.push(candidate(
                snapshot,
                step,
                candidates,
                ReconCapability::ProbeTcpService,
                asset,
                StructuredData::from([
                    ("hostname".into(), Value::String(asset.canonical_value.clone())),
                    ("port".into(), Value::from(port)),
                ]),
                "Confirm reachability of one explicitly authorized port without requesting a banner.",
                ReconInformationGain::Medium,
                ReconRisk::LowImpact,
            ));
        }
    }

    fn add_dns_ownership_candidate(
        snapshot: &ReconSnapshot,
        step: u64,
        asset: &ReconAsset,
        candidates: &mut Vec<ReconAction>,
    ) {
        if !observed(snapshot, &asset.id, ReconObservationSource::DnsOwnership) {
            candidates.push(candidate(
                snapshot,
                step,
                candidates,
                ReconCapability::InspectDnsOwnership,
                asset,
                StructuredData::from([("hostname".into(), Value::String(asset.canonical_value.clone()))]),
                "Map DNS aliases, ownership boundaries, and cloud-provider hints while keeping TXT values redacted.",
                ReconInformationGain::High,
                ReconRisk::Passive,
            ));
        }
    }

    fn add_external_candidate(
        snapshot: &ReconSnapshot,
        step: u64,
        asset: &ReconAsset,
        candidates: &mut Vec<ReconAction>,
    ) {
        if super::external_sources_configured()
            && !observed(
                snapshot,
                &asset.id,
                ReconObservationSource::ExternalIntelligence,
            )
        {
            candidates.push(candidate(
                snapshot,
                step,
                candidates,
                ReconCapability::QueryExternalIntelligence,
                asset,
                StructuredData::from([(
                    "target".into(),
                    Value::String(asset.canonical_value.clone()),
                )]),
                "Query configured passive external sources and retain only normalized metadata.",
                ReconInformationGain::High,
                ReconRisk::Passive,
            ));
        }
    }

    fn add_validation_candidate(
        snapshot: &ReconSnapshot,
        step: u64,
        asset: &ReconAsset,
        candidates: &mut Vec<ReconAction>,
    ) {
        let target = asset
            .canonical_value
            .split("#hexhunt-")
            .next()
            .unwrap_or(&asset.canonical_value);
        if Url::parse(target).is_ok() && !active_validation_observed(snapshot, target) {
            candidates.push(candidate(
                snapshot,
                step,
                candidates,
                ReconCapability::ValidateUrlMetadata,
                asset,
                StructuredData::from([("url".into(), Value::String(target.to_string()))]),
                "Verify the current state of this evidence-derived candidate with one bodyless, scope-checked HEAD request.",
                ReconInformationGain::High,
                ReconRisk::LowImpact,
            ));
        }
    }

    fn add_hypothesis_candidates(
        task: &Task,
        snapshot: &ReconSnapshot,
        step: u64,
        candidates: &mut Vec<ReconAction>,
    ) {
        for hypothesis in snapshot
            .hypotheses
            .iter()
            .filter(|hypothesis| {
                matches!(
                    hypothesis.status,
                    ReconHypothesisStatus::Proposed | ReconHypothesisStatus::Testing
                )
            })
            .take(16)
        {
            for asset in hypothesis.subject_asset_ids.iter().filter_map(|id| {
                snapshot.assets.iter().find(|asset| {
                    asset.id == *id && asset.scope == ReconScopeClassification::InScope
                })
            }) {
                match hypothesis.recommended_capability {
                    Some(ReconCapability::ValidateUrlMetadata) => {
                        Self::add_validation_candidate(snapshot, step, asset, candidates);
                    }
                    Some(ReconCapability::ProbeHttp) => {
                        let urls = if Url::parse(&asset.canonical_value).is_ok() {
                            vec![asset.canonical_value.clone()]
                        } else {
                            probe_urls(task, &asset.canonical_value)
                        };
                        for url in urls {
                            candidates.push(candidate(
                                snapshot,
                                step,
                                candidates,
                                ReconCapability::ProbeHttp,
                                asset,
                                StructuredData::from([("url".into(), Value::String(url))]),
                                "Test the highest-priority unresolved Recon hypothesis with one scope-checked HTTP metadata request.",
                                hypothesis.priority.unwrap_or(ReconInformationGain::High),
                                ReconRisk::LowImpact,
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn candidate(
    snapshot: &ReconSnapshot,
    step: u64,
    existing: &[ReconAction],
    capability: ReconCapability,
    asset: &ReconAsset,
    arguments: StructuredData,
    reason: &str,
    expected_information_gain: ReconInformationGain,
    risk: ReconRisk,
) -> ReconAction {
    ReconAction {
        schema_version: CORE_SCHEMA_VERSION,
        id: ReconActionId(format!(
            "recon-action-{}-{step}-{}",
            snapshot.run_id.0,
            existing.len() + 1
        )),
        capability,
        target_asset_ids: vec![asset.id.clone()],
        arguments,
        reason: reason.into(),
        expected_information_gain,
        risk,
    }
}

fn score_for(scores: &[ReconActionScore], action: &ReconAction) -> i32 {
    scores
        .iter()
        .find(|score| score.action_id == action.id)
        .map(|score| score.total)
        .unwrap_or(i32::MIN)
}

fn score_action(
    snapshot: &ReconSnapshot,
    memory: &ReconMemory,
    action: &ReconAction,
) -> ReconActionScore {
    let information_gain = match action.expected_information_gain {
        ReconInformationGain::Low => 25,
        ReconInformationGain::Medium => 50,
        ReconInformationGain::High => 75,
        ReconInformationGain::Critical => 100,
    };
    let base_relevance: u16 = match action.capability {
        ReconCapability::ResolveDns
        | ReconCapability::InspectDnsOwnership
        | ReconCapability::InspectRdap
        | ReconCapability::ProbeTcpService
        | ReconCapability::ProbeHttp
        | ReconCapability::ValidateUrlMetadata
        | ReconCapability::DiscoverContent
        | ReconCapability::AdaptiveBrowserRecon => 95,
        ReconCapability::QueryExternalIntelligence => 90,
        ReconCapability::SearchCertificateTransparency
        | ReconCapability::AnalyzeJavascript
        | ReconCapability::DescribeApi
        | ReconCapability::AnalyzeWebPage => 90,
        ReconCapability::FetchSitemap => 85,
        ReconCapability::LookupWebArchive | ReconCapability::AnalyzeVisualPage => 80,
        ReconCapability::FetchRobotsTxt => 70,
        _ => 65,
    };
    let wildcard_uncorroborated = action.target_asset_ids.iter().any(|asset_id| {
        snapshot
            .assets
            .iter()
            .find(|asset| asset.id == *asset_id)
            .is_some_and(|asset| {
                let source_count = asset
                    .tags
                    .iter()
                    .filter(|tag| tag.starts_with("source:"))
                    .collect::<BTreeSet<_>>()
                    .len();
                asset.tags.iter().any(|tag| tag == "dns:wildcard_match") && source_count < 2
            })
    });
    let relevance = base_relevance.saturating_sub(if wildcard_uncorroborated { 40 } else { 0 });
    let confidence_values = action
        .target_asset_ids
        .iter()
        .filter_map(|asset_id| snapshot.assets.iter().find(|asset| asset.id == *asset_id))
        .map(|asset| match asset.confidence {
            ReconConfidence::Low => 40_u16,
            ReconConfidence::Medium => 60,
            ReconConfidence::High => 80,
            ReconConfidence::Confirmed => 100,
        })
        .collect::<Vec<_>>();
    let confidence = if confidence_values.is_empty() {
        40
    } else {
        confidence_values.iter().copied().sum::<u16>() / confidence_values.len() as u16
    };
    let similar_selections = snapshot
        .decisions
        .iter()
        .filter_map(selected_action)
        .filter(|selected| {
            selected.capability == action.capability
                && selected.target_asset_ids == action.target_asset_ids
        })
        .count()
        + memory
            .prior_actions
            .iter()
            .filter(|remembered| {
                remembered.capability == action.capability
                    && normalized_arguments(action.capability, &remembered.arguments)
                        == normalized_action_arguments(action)
            })
            .count();
    let novelty = 100_u16.saturating_sub((similar_selections as u16).saturating_mul(25));
    let repetition_penalty = (similar_selections as u16).saturating_mul(35).min(100);
    let estimated_cost = match action.capability {
        ReconCapability::ResolveDns
        | ReconCapability::InspectDnsOwnership
        | ReconCapability::InspectRdap => 10,
        ReconCapability::ProbeTcpService => 20,
        ReconCapability::QueryExternalIntelligence => 20,
        ReconCapability::SearchCertificateTransparency | ReconCapability::FetchRobotsTxt => 15,
        ReconCapability::FetchSitemap => 20,
        ReconCapability::LookupWebArchive => 30,
        ReconCapability::ProbeHttp
        | ReconCapability::ValidateUrlMetadata
        | ReconCapability::DescribeApi
        | ReconCapability::AnalyzeWebPage => 35,
        ReconCapability::DiscoverContent => 40,
        ReconCapability::AnalyzeJavascript => 45,
        ReconCapability::AnalyzeVisualPage => 60,
        ReconCapability::AdaptiveBrowserRecon => 60,
        _ => 40,
    };
    let risk_penalty = match action.risk {
        ReconRisk::Passive => 0,
        ReconRisk::LowImpact => 15,
        ReconRisk::Active => 50,
    };
    let hypothesis_bonus = prioritized_hypothesis(snapshot, Some(action))
        .map(|hypothesis| match hypothesis.priority {
            Some(ReconInformationGain::Critical) => 50,
            Some(ReconInformationGain::High) => 35,
            Some(ReconInformationGain::Medium) => 20,
            Some(ReconInformationGain::Low) => 10,
            None => 0,
        })
        .unwrap_or(0);
    let total = i32::from(information_gain)
        + i32::from(relevance)
        + i32::from(confidence)
        + i32::from(novelty)
        - i32::from(estimated_cost)
        - i32::from(risk_penalty)
        - i32::from(repetition_penalty)
        + i32::from(hypothesis_bonus);
    let hypothesis_rationale = if hypothesis_bonus > 0 {
        format!("Active Recon hypothesis bonus: {hypothesis_bonus}/50.")
    } else {
        "No active Recon hypothesis bonus applied.".into()
    };
    ReconActionScore {
        schema_version: CORE_SCHEMA_VERSION,
        action_id: action.id.clone(),
        information_gain,
        relevance,
        confidence,
        novelty,
        estimated_cost,
        risk_penalty,
        repetition_penalty,
        total,
        rationale: vec![
            format!("Expected information gain: {information_gain}/100."),
            format!("Target relevance: {relevance}/100."),
            format!("Evidence confidence: {confidence}/100."),
            format!("Estimated execution cost: {estimated_cost}/100."),
            hypothesis_rationale,
            if wildcard_uncorroborated {
                "Relevance reduced because the hostname only matches an uncorroborated wildcard DNS baseline."
                    .into()
            } else {
                "No uncorroborated wildcard DNS penalty applied.".into()
            },
        ],
    }
}

fn prioritized_hypothesis<'a>(
    snapshot: &'a ReconSnapshot,
    action: Option<&ReconAction>,
) -> Option<&'a ReconHypothesis> {
    snapshot
        .hypotheses
        .iter()
        .filter(|hypothesis| {
            matches!(
                hypothesis.status,
                ReconHypothesisStatus::Proposed | ReconHypothesisStatus::Testing
            )
        })
        .filter(|hypothesis| {
            action.map_or(true, |action| {
                hypothesis
                    .recommended_capability
                    .map_or(true, |capability| capability == action.capability)
                    && hypothesis.subject_asset_ids.iter().any(|asset_id| {
                        action
                            .target_asset_ids
                            .iter()
                            .any(|target| target == asset_id)
                    })
            })
        })
        .max_by(|left, right| {
            hypothesis_priority(left)
                .cmp(&hypothesis_priority(right))
                .then_with(|| right.id.0.cmp(&left.id.0))
        })
}

fn hypothesis_priority(hypothesis: &ReconHypothesis) -> u8 {
    match hypothesis.priority {
        Some(ReconInformationGain::Critical) => 4,
        Some(ReconInformationGain::High) => 3,
        Some(ReconInformationGain::Medium) => 2,
        Some(ReconInformationGain::Low) => 1,
        None => 0,
    }
}

fn selected_action(decision: &ReconDecision) -> Option<&ReconAction> {
    let selected_id = decision.selected_action_id.as_ref()?;
    decision
        .candidate_actions
        .iter()
        .find(|candidate| candidate.id == *selected_id)
}

fn action_was_selected(snapshot: &ReconSnapshot, action: &ReconAction) -> bool {
    snapshot
        .decisions
        .iter()
        .filter_map(selected_action)
        .any(|selected| actions_equivalent(selected, action))
}

fn deduplicate_actions(actions: Vec<ReconAction>) -> Vec<ReconAction> {
    let mut unique = Vec::new();
    for action in actions {
        if !unique
            .iter()
            .any(|existing| actions_equivalent(existing, &action))
        {
            unique.push(action);
        }
    }
    unique
}

fn actions_equivalent(left: &ReconAction, right: &ReconAction) -> bool {
    left.capability == right.capability
        && normalized_action_arguments(left) == normalized_action_arguments(right)
}

fn normalized_action_arguments(action: &ReconAction) -> Vec<(String, String)> {
    normalized_arguments(action.capability, &action.arguments)
}

fn normalized_arguments(
    capability: ReconCapability,
    arguments: &StructuredData,
) -> Vec<(String, String)> {
    arguments
        .iter()
        .map(|(key, value)| {
            let normalized = match value {
                Value::String(value) => normalize_action_string(capability, key, value),
                Value::Array(values) => {
                    let mut values = values
                        .iter()
                        .map(|value| match value {
                            Value::String(value) => normalize_action_string(capability, key, value),
                            _ => value.to_string(),
                        })
                        .collect::<Vec<_>>();
                    values.sort();
                    values.dedup();
                    values.join("|")
                }
                _ => value.to_string(),
            };
            (key.clone(), normalized)
        })
        .collect()
}

fn normalize_action_string(capability: ReconCapability, key: &str, value: &str) -> String {
    let value = value.trim();
    if matches!(key, "domain" | "hostname" | "target") {
        return value.trim_end_matches('.').to_ascii_lowercase();
    }
    if matches!(key, "url" | "base_url") {
        if let Ok(mut url) = Url::parse(value) {
            url.set_fragment(None);
            if url.path().is_empty() {
                url.set_path("/");
            }
            if matches!(
                capability,
                ReconCapability::AnalyzeWebPage
                    | ReconCapability::AnalyzeVisualPage
                    | ReconCapability::AdaptiveBrowserRecon
            ) {
                let _ = url.set_scheme("web");
            }
            return url.to_string().trim_end_matches('/').to_ascii_lowercase();
        }
    }
    value.to_ascii_lowercase()
}

fn observed(
    snapshot: &ReconSnapshot,
    asset_id: &super::ReconAssetId,
    source: ReconObservationSource,
) -> bool {
    snapshot.observations.iter().any(|observation| {
        observation.source == source && observation.subject_asset_ids.contains(asset_id)
    })
}

fn is_successful_web_page(asset: &ReconAsset) -> bool {
    let successful_status = asset.tags.iter().any(|tag| {
        tag.strip_prefix("http:status:")
            .and_then(|status| status.parse::<u16>().ok())
            .is_some_and(|status| (200..300).contains(&status))
    });
    let explicitly_non_html = asset.tags.iter().any(|tag| {
        matches!(
            tag.as_str(),
            "http:content:json" | "http:content:javascript"
        )
    });
    successful_status && !explicitly_non_html
}

fn is_source_map_candidate(asset: &ReconAsset) -> bool {
    asset
        .tags
        .iter()
        .any(|tag| matches!(tag.as_str(), "web:source_map" | "web:source_map_candidate"))
}

fn active_validation_observed(snapshot: &ReconSnapshot, target: &str) -> bool {
    let target = target.split('#').next().unwrap_or(target);
    snapshot.observations.iter().any(|observation| {
        observation.source == ReconObservationSource::ActiveValidation
            && observation
                .facts
                .get("url")
                .and_then(Value::as_str)
                .is_some_and(|url| url.split('#').next().unwrap_or(url) == target)
    })
}

fn tcp_port_observed(snapshot: &ReconSnapshot, asset_id: &super::ReconAssetId, port: u16) -> bool {
    snapshot.observations.iter().any(|observation| {
        observation.source == ReconObservationSource::TcpProbe
            && observation.subject_asset_ids.contains(asset_id)
            && observation.facts.get("port").and_then(Value::as_u64) == Some(u64::from(port))
    })
}

fn content_discovery_paths(snapshot: &ReconSnapshot, service: &ReconAsset) -> Vec<String> {
    let Ok(base) = Url::parse(&service.canonical_value) else {
        return vec![];
    };
    let mut paths = BTreeSet::from([
        "/.well-known/security.txt".to_string(),
        "/.well-known/openid-configuration".to_string(),
    ]);
    if snapshot
        .assets
        .iter()
        .any(|asset| asset.kind == ReconAssetKind::AuthenticationSurface)
    {
        paths.extend(["/login".into(), "/auth".into(), "/oauth/authorize".into()]);
    }
    if snapshot
        .assets
        .iter()
        .any(|asset| asset.kind == ReconAssetKind::Api)
    {
        paths.extend([
            "/openapi.json".into(),
            "/swagger.json".into(),
            "/graphql".into(),
        ]);
    }
    for technology in snapshot
        .assets
        .iter()
        .filter(|asset| asset.kind == ReconAssetKind::Technology)
    {
        let technology = technology.canonical_value.to_ascii_lowercase();
        if technology.contains("wordpress") {
            paths.extend(["/wp-json/".into(), "/wp-admin/".into()]);
        }
        if technology.contains("next") {
            paths.insert("/_next/static/".into());
        }
    }
    for asset in snapshot
        .assets
        .iter()
        .filter(|asset| asset.kind == ReconAssetKind::HistoricalUrl)
    {
        let Ok(url) = Url::parse(&asset.canonical_value) else {
            continue;
        };
        if url.origin() == base.origin() && !url.path().is_empty() {
            paths.insert(url.path().to_string());
        }
        if paths.len() >= 32 {
            break;
        }
    }
    paths.into_iter().take(32).collect()
}

fn probe_urls(task: &Task, hostname: &str) -> Vec<String> {
    let mut urls = BTreeSet::new();
    let mut primary_port = None;
    if let Ok(mut primary) = Url::parse(&task.primary_target) {
        if primary
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case(hostname))
        {
            primary_port = primary.port_or_known_default();
            primary.set_query(None);
            primary.set_fragment(None);
            urls.insert(primary.to_string());
        }
    }
    for port in task.scope.allowed_ports.iter().copied().take(8) {
        if primary_port == Some(port) {
            continue;
        }
        let scheme = if port == 80 { "http" } else { "https" };
        let value = if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
            format!("{scheme}://{hostname}/")
        } else {
            format!("{scheme}://{hostname}:{port}/")
        };
        urls.insert(value);
    }
    if urls.is_empty() {
        urls.insert(format!("https://{hostname}/"));
    }
    urls.into_iter().collect()
}

fn http_origin_observed(
    snapshot: &ReconSnapshot,
    asset_id: &super::ReconAssetId,
    url: &str,
) -> bool {
    let candidate_origin = origin_key(url);
    snapshot.observations.iter().any(|observation| {
        observation.source == ReconObservationSource::HttpProbe
            && observation.subject_asset_ids.contains(asset_id)
            && observation
                .facts
                .get("url")
                .and_then(Value::as_str)
                .is_some_and(|observed_url| origin_key(observed_url) == candidate_origin)
    })
}

fn origin_key(value: &str) -> Option<(String, String, u16)> {
    let url = Url::parse(value).ok()?;
    Some((
        url.scheme().to_string(),
        url.host_str()?.to_ascii_lowercase(),
        url.port_or_known_default()?,
    ))
}

fn tool_allowed(task: &Task, name: &str) -> bool {
    task.available_tools.iter().any(|tool| tool == name)
}

fn tool_for_capability(capability: ReconCapability) -> &'static str {
    match capability {
        ReconCapability::ReadProgramPolicy => "read_program_policy",
        ReconCapability::SearchCertificateTransparency => "search_certificate_transparency",
        ReconCapability::QueryPassiveDns => "query_passive_dns",
        ReconCapability::ResolveDns => "resolve_dns",
        ReconCapability::InspectDnsOwnership => "inspect_dns_ownership",
        ReconCapability::InspectRdap => "inspect_rdap",
        ReconCapability::ProbeTcpService => "probe_tcp_service",
        ReconCapability::ProbeHttp => "probe_http",
        ReconCapability::ValidateUrlMetadata => "validate_url_metadata",
        ReconCapability::DiscoverContent => "discover_content",
        ReconCapability::InspectTls => "inspect_tls",
        ReconCapability::FetchRobotsTxt => "fetch_robots_txt",
        ReconCapability::FetchSitemap => "fetch_sitemap",
        ReconCapability::LookupWebArchive => "lookup_web_archive",
        ReconCapability::AnalyzeJavascript => "analyze_javascript",
        ReconCapability::DescribeApi => "describe_api",
        ReconCapability::AnalyzeWebPage => "analyze_web_page",
        ReconCapability::AnalyzeVisualPage => "analyze_visual_page",
        ReconCapability::AdaptiveBrowserRecon => "adaptive_browser_recon",
        ReconCapability::QueryExternalIntelligence => "query_external_intelligence",
        ReconCapability::CompareSnapshot => "compare_snapshot",
    }
}

fn is_recon_tool(name: &str) -> bool {
    capability_for_tool(name).is_some()
}

fn capability_for_tool(name: &str) -> Option<ReconCapability> {
    match name {
        "search_certificate_transparency" => Some(ReconCapability::SearchCertificateTransparency),
        "resolve_dns" => Some(ReconCapability::ResolveDns),
        "inspect_dns_ownership" => Some(ReconCapability::InspectDnsOwnership),
        "inspect_rdap" => Some(ReconCapability::InspectRdap),
        "probe_tcp_service" => Some(ReconCapability::ProbeTcpService),
        "probe_http" => Some(ReconCapability::ProbeHttp),
        "validate_url_metadata" => Some(ReconCapability::ValidateUrlMetadata),
        "discover_content" => Some(ReconCapability::DiscoverContent),
        "fetch_robots_txt" => Some(ReconCapability::FetchRobotsTxt),
        "fetch_sitemap" => Some(ReconCapability::FetchSitemap),
        "lookup_web_archive" => Some(ReconCapability::LookupWebArchive),
        "analyze_javascript" => Some(ReconCapability::AnalyzeJavascript),
        "describe_api" => Some(ReconCapability::DescribeApi),
        "analyze_web_page" => Some(ReconCapability::AnalyzeWebPage),
        "analyze_visual_page" => Some(ReconCapability::AnalyzeVisualPage),
        "adaptive_browser_recon" => Some(ReconCapability::AdaptiveBrowserRecon),
        "query_external_intelligence" => Some(ReconCapability::QueryExternalIntelligence),
        _ => None,
    }
}

fn is_api_description_candidate(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("openapi") || value.contains("swagger") || value.contains("graphql")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{
            ReconAssetId, ReconConfidence, ReconObservation, ReconObservationId,
            ReconScopeClassification, ReconSnapshotId, RunId, TaskBudget, TaskId,
        },
        scope_guard::ScopeProject,
    };

    fn task() -> Task {
        Task {
            schema_version: CORE_SCHEMA_VERSION,
            id: TaskId("task-plan".into()),
            objective: "Adaptive passive Recon".into(),
            primary_target: "https://example.test".into(),
            scope: ScopeProject {
                id: "scope-plan".into(),
                allowed_domains: vec!["example.test".into(), "*.example.test".into()],
                excluded_domains: vec![],
                allowed_ports: vec![80, 443],
                request_rate: 5,
                authorized: true,
            },
            budget: TaskBudget {
                max_steps: 0,
                max_http_requests: 0,
                max_model_calls: 0,
                max_input_tokens: 0,
                max_output_tokens: 0,
                max_duration_ms: 0,
            },
            available_tools: vec![
                "search_certificate_transparency".into(),
                "resolve_dns".into(),
                "probe_http".into(),
            ],
            memory_policy: Default::default(),
        }
    }

    fn snapshot() -> ReconSnapshot {
        let mut snapshot = ReconSnapshot::empty(
            ReconSnapshotId("snapshot-plan".into()),
            RunId("run-plan".into()),
            1,
        );
        snapshot.assets.push(ReconAsset {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconAssetId("asset-root".into()),
            kind: ReconAssetKind::RootDomain,
            canonical_value: "example.test".into(),
            display_name: None,
            scope: ReconScopeClassification::InScope,
            scope_reason: "Authorized.".into(),
            confidence: ReconConfidence::Confirmed,
            first_seen_at_ms: 1,
            last_seen_at_ms: 1,
            tags: vec![],
        });
        snapshot
    }

    #[test]
    fn plan_changes_when_graph_knowledge_changes() {
        let mut snapshot = snapshot();
        let first = ReconPlanner::plan(&task(), &snapshot, 1).unwrap();
        assert!(first
            .candidate_actions
            .iter()
            .any(|action| { action.capability == ReconCapability::SearchCertificateTransparency }));

        snapshot.observations.push(ReconObservation {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconObservationId("observation-ct".into()),
            run_id: snapshot.run_id.clone(),
            source: ReconObservationSource::CertificateTransparency,
            subject_asset_ids: vec![ReconAssetId("asset-root".into())],
            summary: "CT searched.".into(),
            facts: StructuredData::new(),
            confidence: ReconConfidence::High,
            evidence_ids: vec![],
            observed_at_ms: 2,
        });
        let second = ReconPlanner::plan(&task(), &snapshot, 2).unwrap();
        assert!(!second
            .candidate_actions
            .iter()
            .any(|action| { action.capability == ReconCapability::SearchCertificateTransparency }));
        assert!(second
            .candidate_actions
            .iter()
            .any(|action| action.capability == ReconCapability::ResolveDns));
    }

    #[test]
    fn probed_page_becomes_visual_candidate_until_it_is_observed() {
        let mut task = task();
        task.available_tools.push("analyze_visual_page".into());
        let mut snapshot = snapshot();
        let page_id = ReconAssetId("asset-page".into());
        snapshot.assets.push(ReconAsset {
            schema_version: CORE_SCHEMA_VERSION,
            id: page_id.clone(),
            kind: ReconAssetKind::Url,
            canonical_value: "https://example.test/login".into(),
            display_name: None,
            scope: ReconScopeClassification::InScope,
            scope_reason: "Authorized.".into(),
            confidence: ReconConfidence::High,
            first_seen_at_ms: 1,
            last_seen_at_ms: 1,
            tags: vec![],
        });
        snapshot.observations.push(ReconObservation {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconObservationId("observation-http".into()),
            run_id: snapshot.run_id.clone(),
            source: ReconObservationSource::HttpProbe,
            subject_asset_ids: vec![page_id.clone()],
            summary: "HTTP page observed.".into(),
            facts: StructuredData::new(),
            confidence: ReconConfidence::High,
            evidence_ids: vec![],
            observed_at_ms: 2,
        });

        let first = ReconPlanner::plan(&task, &snapshot, 2).unwrap();
        assert!(first
            .candidate_actions
            .iter()
            .any(|action| action.capability == ReconCapability::AnalyzeVisualPage));
        snapshot.observations.push(ReconObservation {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconObservationId("observation-visual".into()),
            run_id: snapshot.run_id.clone(),
            source: ReconObservationSource::VisualAnalysis,
            subject_asset_ids: vec![page_id],
            summary: "Visual page observed.".into(),
            facts: StructuredData::new(),
            confidence: ReconConfidence::Medium,
            evidence_ids: vec![],
            observed_at_ms: 3,
        });
        let second = ReconPlanner::plan(&task, &snapshot, 3).unwrap();
        assert!(!second
            .candidate_actions
            .iter()
            .any(|action| action.capability == ReconCapability::AnalyzeVisualPage));
    }

    #[test]
    fn archive_lookup_is_suggested_once_for_an_unobserved_root_domain() {
        let mut task = task();
        task.available_tools.push("lookup_web_archive".into());
        let mut snapshot = snapshot();
        let first = ReconPlanner::plan(&task, &snapshot, 1).unwrap();
        assert!(first
            .candidate_actions
            .iter()
            .any(|action| action.capability == ReconCapability::LookupWebArchive));
        snapshot.observations.push(ReconObservation {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconObservationId("observation-archive".into()),
            run_id: snapshot.run_id.clone(),
            source: ReconObservationSource::WebArchive,
            subject_asset_ids: vec![ReconAssetId("asset-root".into())],
            summary: "Archive metadata searched.".into(),
            facts: StructuredData::new(),
            confidence: ReconConfidence::Low,
            evidence_ids: vec![],
            observed_at_ms: 2,
        });
        let second = ReconPlanner::plan(&task, &snapshot, 2).unwrap();
        assert!(!second
            .candidate_actions
            .iter()
            .any(|action| action.capability == ReconCapability::LookupWebArchive));
    }

    #[test]
    fn decision_scores_are_ordered_and_recommend_the_highest_value_action() {
        let decision = ReconPlanner::plan(&task(), &snapshot(), 1).unwrap();
        assert!(decision.action_scores.len() >= 2);
        assert!(decision
            .action_scores
            .windows(2)
            .all(|pair| pair[0].total >= pair[1].total));
        assert_eq!(
            decision.recommended_action_id,
            decision
                .action_scores
                .first()
                .map(|score| score.action_id.clone())
        );
        assert_eq!(
            decision
                .candidate_actions
                .first()
                .map(|action| action.id.clone()),
            decision.recommended_action_id
        );
        assert!(decision.coverage.unwrap().actionable_gaps >= 2);
    }

    #[test]
    fn unavailable_capability_remains_visible_as_a_blocked_knowledge_gap() {
        let decision = ReconPlanner::plan(&task(), &snapshot(), 1).unwrap();
        let archive_gap = decision
            .knowledge_gaps
            .iter()
            .find(|gap| gap.capability == ReconCapability::LookupWebArchive)
            .unwrap();
        assert!(!archive_gap.actionable);
        assert!(archive_gap.blocked_reason.is_some());
        assert!(!decision
            .candidate_actions
            .iter()
            .any(|action| action.capability == ReconCapability::LookupWebArchive));
    }

    #[test]
    fn an_exact_selected_action_is_not_offered_again_without_new_evidence() {
        let mut snapshot = snapshot();
        let mut first = ReconPlanner::plan(&task(), &snapshot, 1).unwrap();
        let selected = first
            .candidate_actions
            .iter()
            .find(|action| action.capability == ReconCapability::SearchCertificateTransparency)
            .unwrap()
            .clone();
        let attempted_action = AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "search_certificate_transparency".into(),
            arguments: selected.arguments.clone(),
            reason: "Test the highest-value passive gap.".into(),
        };
        ReconPlanner::record_selection(&mut first, &attempted_action);
        snapshot.decisions.push(first);

        assert!(ReconPlanner::selection_rejection_reason(&snapshot, &attempted_action).is_some());

        let second = ReconPlanner::plan(&task(), &snapshot, 2).unwrap();
        assert!(!second
            .candidate_actions
            .iter()
            .any(|action| action.capability == ReconCapability::SearchCertificateTransparency));
        let repeated_gap = second
            .knowledge_gaps
            .iter()
            .find(|gap| gap.capability == ReconCapability::SearchCertificateTransparency)
            .unwrap();
        assert!(!repeated_gap.actionable);
        assert!(repeated_gap
            .blocked_reason
            .as_deref()
            .unwrap()
            .contains("already selected"));
    }

    #[test]
    fn planner_stops_with_a_structured_reason_when_coverage_is_complete() {
        let mut task = task();
        task.available_tools.push("lookup_web_archive".into());
        let mut snapshot = snapshot();
        for (id, source) in [
            ("ct", ReconObservationSource::CertificateTransparency),
            ("archive", ReconObservationSource::WebArchive),
            ("dns", ReconObservationSource::DnsQuery),
            ("dns-ownership", ReconObservationSource::DnsOwnership),
            ("rdap", ReconObservationSource::Rdap),
        ] {
            snapshot.observations.push(ReconObservation {
                schema_version: CORE_SCHEMA_VERSION,
                id: ReconObservationId(format!("observation-{id}")),
                run_id: snapshot.run_id.clone(),
                source,
                subject_asset_ids: vec![ReconAssetId("asset-root".into())],
                summary: "Observed.".into(),
                facts: StructuredData::new(),
                confidence: ReconConfidence::High,
                evidence_ids: vec![],
                observed_at_ms: 2,
            });
        }
        for (id, url) in [
            ("http", "http://example.test/"),
            ("https", "https://example.test/"),
        ] {
            snapshot.observations.push(ReconObservation {
                schema_version: CORE_SCHEMA_VERSION,
                id: ReconObservationId(format!("observation-{id}")),
                run_id: snapshot.run_id.clone(),
                source: ReconObservationSource::HttpProbe,
                subject_asset_ids: vec![ReconAssetId("asset-root".into())],
                summary: "HTTP origin observed.".into(),
                facts: StructuredData::from([("url".into(), Value::String(url.into()))]),
                confidence: ReconConfidence::High,
                evidence_ids: vec![],
                observed_at_ms: 2,
            });
        }
        for port in [80_u16, 443_u16] {
            snapshot.observations.push(ReconObservation {
                schema_version: CORE_SCHEMA_VERSION,
                id: ReconObservationId(format!("observation-tcp-{port}")),
                run_id: snapshot.run_id.clone(),
                source: ReconObservationSource::TcpProbe,
                subject_asset_ids: vec![ReconAssetId("asset-root".into())],
                summary: "Authorized TCP port observed.".into(),
                facts: StructuredData::from([("port".into(), Value::from(port))]),
                confidence: ReconConfidence::High,
                evidence_ids: vec![],
                observed_at_ms: 2,
            });
        }

        let decision = ReconPlanner::plan(&task, &snapshot, 5).unwrap();
        assert_eq!(decision.mode, ReconMode::Stop);
        assert_eq!(
            decision.stop_reason_code,
            Some(ReconStopReasonCode::CoverageComplete)
        );
        assert!(decision.candidate_actions.is_empty());
        assert!(decision.stop_reason.is_some());
    }

    #[test]
    fn http_service_mapping_tracks_each_authorized_origin_independently() {
        let mut snapshot = snapshot();
        let first = ReconPlanner::plan(&task(), &snapshot, 1).unwrap();
        let probe_urls = first
            .candidate_actions
            .iter()
            .filter(|action| action.capability == ReconCapability::ProbeHttp)
            .filter_map(|action| action.arguments.get("url"))
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        assert!(probe_urls.iter().any(|url| url.starts_with("http://")));
        assert!(probe_urls.iter().any(|url| url.starts_with("https://")));

        snapshot.observations.push(ReconObservation {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconObservationId("observation-https-service".into()),
            run_id: snapshot.run_id.clone(),
            source: ReconObservationSource::HttpProbe,
            subject_asset_ids: vec![ReconAssetId("asset-root".into())],
            summary: "HTTPS observed.".into(),
            facts: StructuredData::from([(
                "url".into(),
                Value::String("https://example.test/".into()),
            )]),
            confidence: ReconConfidence::High,
            evidence_ids: vec![],
            observed_at_ms: 2,
        });
        let second = ReconPlanner::plan(&task(), &snapshot, 2).unwrap();
        let remaining = second
            .candidate_actions
            .iter()
            .filter(|action| action.capability == ReconCapability::ProbeHttp)
            .filter_map(|action| action.arguments.get("url"))
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        assert_eq!(remaining, vec!["http://example.test/"]);
    }

    #[test]
    fn discovered_web_page_is_analyzed_once_before_the_agent_moves_on() {
        let mut task = task();
        task.available_tools.push("analyze_web_page".into());
        let mut snapshot = snapshot();
        let page_id = ReconAssetId("asset-admin-page".into());
        snapshot.assets.push(ReconAsset {
            schema_version: CORE_SCHEMA_VERSION,
            id: page_id.clone(),
            kind: ReconAssetKind::Url,
            canonical_value: "https://example.test/admin".into(),
            display_name: None,
            scope: ReconScopeClassification::InScope,
            scope_reason: "Authorized.".into(),
            confidence: ReconConfidence::Medium,
            first_seen_at_ms: 1,
            last_seen_at_ms: 1,
            tags: vec!["web:discovered_link".into()],
        });

        let first = ReconPlanner::plan(&task, &snapshot, 2).unwrap();
        assert!(first.candidate_actions.iter().any(|action| {
            action.capability == ReconCapability::AnalyzeWebPage
                && action.arguments["url"] == "https://example.test/admin"
        }));

        snapshot.observations.push(ReconObservation {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconObservationId("observation-web-page".into()),
            run_id: snapshot.run_id.clone(),
            source: ReconObservationSource::WebPageAnalysis,
            subject_asset_ids: vec![page_id],
            summary: "Page structure analyzed.".into(),
            facts: StructuredData::new(),
            confidence: ReconConfidence::High,
            evidence_ids: vec![],
            observed_at_ms: 2,
        });
        let second = ReconPlanner::plan(&task, &snapshot, 3).unwrap();
        assert!(!second.candidate_actions.iter().any(|action| {
            action.capability == ReconCapability::AnalyzeWebPage
                && action.arguments["url"] == "https://example.test/admin"
        }));
    }

    #[test]
    fn active_hypothesis_changes_priority_and_is_attached_to_the_decision() {
        let mut snapshot = snapshot();
        snapshot.assets[0].tags = vec!["source:dns".into(), "dns:wildcard_match".into()];
        snapshot.observations.push(ReconObservation {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconObservationId("observation-wildcard".into()),
            run_id: snapshot.run_id.clone(),
            source: ReconObservationSource::DnsQuery,
            subject_asset_ids: vec![ReconAssetId("asset-root".into())],
            summary: "Wildcard DNS matched.".into(),
            facts: StructuredData::new(),
            confidence: ReconConfidence::Low,
            evidence_ids: vec![],
            observed_at_ms: 2,
        });
        snapshot.hypotheses = crate::core::ReconCorrelator::derive(&snapshot);

        let decision = ReconPlanner::plan(&task(), &snapshot, 3).unwrap();
        assert_eq!(decision.mode, ReconMode::Verify);
        assert!(decision.hypothesis_id.is_some());
        assert!(decision.action_scores.iter().any(|score| {
            score
                .rationale
                .iter()
                .any(|reason| reason.contains("hypothesis bonus"))
        }));
        assert_eq!(decision.coverage.unwrap().active_hypotheses, 1);
    }
}
