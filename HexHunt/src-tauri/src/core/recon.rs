use super::{EvidenceId, RunId, StructuredData, CORE_SCHEMA_VERSION};
use serde::{Deserialize, Serialize};

macro_rules! recon_string_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_string())
            }
        }
    };
}

recon_string_id!(ReconAssetId);
recon_string_id!(ReconRelationId);
recon_string_id!(ReconObservationId);
recon_string_id!(ReconHypothesisId);
recon_string_id!(ReconActionId);
recon_string_id!(ReconKnowledgeGapId);
recon_string_id!(ReconSnapshotId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconAssetKind {
    Organization,
    RootDomain,
    Subdomain,
    IpAddress,
    NetworkRange,
    Asn,
    DnsRecord,
    HttpService,
    NetworkService,
    Url,
    HistoricalUrl,
    Endpoint,
    JavascriptBundle,
    Api,
    AuthenticationSurface,
    WebForm,
    Parameter,
    DataModel,
    CloudResource,
    Technology,
    ThirdPartyService,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconScopeClassification {
    InScope,
    OutOfScope,
    Unknown,
    ThirdParty,
    RequiresReview,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconConfidence {
    Low,
    Medium,
    High,
    Confirmed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconAsset {
    pub schema_version: u32,
    pub id: ReconAssetId,
    pub kind: ReconAssetKind,
    pub canonical_value: String,
    pub display_name: Option<String>,
    pub scope: ReconScopeClassification,
    pub scope_reason: String,
    pub confidence: ReconConfidence,
    pub first_seen_at_ms: u64,
    pub last_seen_at_ms: u64,
    pub tags: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconRelationKind {
    Owns,
    ResolvesTo,
    AliasOf,
    HostedOn,
    Serves,
    RedirectsTo,
    Exposes,
    References,
    UsesTechnology,
    AuthenticatesWith,
    AcceptsInput,
    Describes,
    RelatedTo,
    HistoricalVersionOf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconAssetRelation {
    pub schema_version: u32,
    pub id: ReconRelationId,
    pub from_asset_id: ReconAssetId,
    pub to_asset_id: ReconAssetId,
    pub kind: ReconRelationKind,
    pub confidence: ReconConfidence,
    pub evidence_ids: Vec<EvidenceId>,
    pub observed_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconObservationSource {
    ProgramPolicy,
    CertificateTransparency,
    PassiveDns,
    DnsQuery,
    DnsOwnership,
    Rdap,
    TcpProbe,
    HttpProbe,
    ActiveValidation,
    ContentDiscovery,
    ExternalIntelligence,
    TlsInspection,
    RobotsTxt,
    Sitemap,
    WebArchive,
    JavascriptAnalysis,
    ApiDescription,
    WebPageAnalysis,
    VisualAnalysis,
    AdaptiveBrowser,
    Human,
    Derived,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconObservation {
    pub schema_version: u32,
    pub id: ReconObservationId,
    pub run_id: RunId,
    pub source: ReconObservationSource,
    pub subject_asset_ids: Vec<ReconAssetId>,
    pub summary: String,
    pub facts: StructuredData,
    pub confidence: ReconConfidence,
    pub evidence_ids: Vec<EvidenceId>,
    pub observed_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconHypothesisStatus {
    Proposed,
    Testing,
    Supported,
    Rejected,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconHypothesisKind {
    UndocumentedEndpoint,
    PublicSensitiveOperation,
    AuthenticationSurface,
    HistoricalSurface,
    SourceMapExposure,
    ClientSecretIndicator,
    ClientSecuritySignal,
    HighValueParameter,
    UnverifiedAsset,
    PotentialDanglingDns,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconInformationGain {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconRisk {
    Passive,
    LowImpact,
    Active,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconCapability {
    ReadProgramPolicy,
    SearchCertificateTransparency,
    QueryPassiveDns,
    ResolveDns,
    InspectDnsOwnership,
    InspectRdap,
    ProbeTcpService,
    ProbeHttp,
    ValidateUrlMetadata,
    DiscoverContent,
    QueryExternalIntelligence,
    InspectTls,
    FetchRobotsTxt,
    FetchSitemap,
    LookupWebArchive,
    AnalyzeJavascript,
    DescribeApi,
    AnalyzeWebPage,
    AnalyzeVisualPage,
    AdaptiveBrowserRecon,
    CompareSnapshot,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconAction {
    pub schema_version: u32,
    pub id: ReconActionId,
    pub capability: ReconCapability,
    pub target_asset_ids: Vec<ReconAssetId>,
    pub arguments: StructuredData,
    pub reason: String,
    pub expected_information_gain: ReconInformationGain,
    pub risk: ReconRisk,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconKnowledgeGap {
    pub schema_version: u32,
    pub id: ReconKnowledgeGapId,
    pub asset_id: ReconAssetId,
    pub capability: ReconCapability,
    pub description: String,
    pub priority: ReconInformationGain,
    pub actionable: bool,
    pub blocked_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconActionScore {
    pub schema_version: u32,
    pub action_id: ReconActionId,
    pub information_gain: u16,
    pub relevance: u16,
    pub confidence: u16,
    pub novelty: u16,
    pub estimated_cost: u16,
    pub risk_penalty: u16,
    pub repetition_penalty: u16,
    pub total: i32,
    pub rationale: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconCoverageSummary {
    pub in_scope_assets: usize,
    pub observed_assets: usize,
    pub actionable_gaps: usize,
    pub blocked_gaps: usize,
    pub coverage_percent: u8,
    #[serde(default)]
    pub active_hypotheses: usize,
    #[serde(default)]
    pub supported_hypotheses: usize,
    #[serde(default)]
    pub verified_in_scope_assets: usize,
    #[serde(default)]
    pub unresolved_actionable_hypotheses: usize,
    #[serde(default)]
    pub review_only_hypotheses: usize,
    #[serde(default)]
    pub host_assets: usize,
    #[serde(default)]
    pub dns_ownership_observed_hosts: usize,
    #[serde(default)]
    pub validation_candidates: usize,
    #[serde(default)]
    pub validated_candidates: usize,
    #[serde(default)]
    pub review_ready: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconStopReasonCode {
    CoverageComplete,
    RequiredCapabilityUnavailable,
    MarginalInformationGainTooLow,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconHypothesis {
    pub schema_version: u32,
    pub id: ReconHypothesisId,
    #[serde(default)]
    pub kind: Option<ReconHypothesisKind>,
    pub statement: String,
    pub status: ReconHypothesisStatus,
    pub subject_asset_ids: Vec<ReconAssetId>,
    pub rationale: String,
    pub confidence: ReconConfidence,
    #[serde(default)]
    pub priority: Option<ReconInformationGain>,
    #[serde(default)]
    pub recommended_capability: Option<ReconCapability>,
    pub supporting_observation_ids: Vec<ReconObservationId>,
    pub contradicting_observation_ids: Vec<ReconObservationId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconMode {
    Breadth,
    Depth,
    Verify,
    Monitor,
    Stop,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconDecision {
    pub schema_version: u32,
    pub run_id: RunId,
    pub step: u64,
    pub mode: ReconMode,
    pub hypothesis_id: Option<ReconHypothesisId>,
    #[serde(default)]
    pub knowledge_gaps: Vec<ReconKnowledgeGap>,
    pub candidate_actions: Vec<ReconAction>,
    #[serde(default)]
    pub action_scores: Vec<ReconActionScore>,
    #[serde(default)]
    pub recommended_action_id: Option<ReconActionId>,
    pub selected_action_id: Option<ReconActionId>,
    #[serde(default)]
    pub coverage: Option<ReconCoverageSummary>,
    pub decision_summary: String,
    #[serde(default)]
    pub stop_reason_code: Option<ReconStopReasonCode>,
    pub stop_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconSnapshot {
    pub schema_version: u32,
    pub id: ReconSnapshotId,
    pub run_id: RunId,
    pub created_at_ms: u64,
    pub assets: Vec<ReconAsset>,
    pub relations: Vec<ReconAssetRelation>,
    pub observations: Vec<ReconObservation>,
    pub hypotheses: Vec<ReconHypothesis>,
    pub decisions: Vec<ReconDecision>,
}

impl ReconSnapshot {
    pub fn empty(id: ReconSnapshotId, run_id: RunId, created_at_ms: u64) -> Self {
        Self {
            schema_version: CORE_SCHEMA_VERSION,
            id,
            run_id,
            created_at_ms,
            assets: vec![],
            relations: vec![],
            observations: vec![],
            hypotheses: vec![],
            decisions: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn asset(id: &str, kind: ReconAssetKind, value: &str) -> ReconAsset {
        ReconAsset {
            schema_version: CORE_SCHEMA_VERSION,
            id: id.into(),
            kind,
            canonical_value: value.into(),
            display_name: None,
            scope: ReconScopeClassification::InScope,
            scope_reason: "Explicitly authorized by the program policy.".into(),
            confidence: ReconConfidence::Confirmed,
            first_seen_at_ms: 1_000,
            last_seen_at_ms: 1_000,
            tags: vec!["authorized".into()],
        }
    }

    #[test]
    fn recon_snapshot_round_trips_without_losing_graph_state() {
        let root = asset("asset-root", ReconAssetKind::RootDomain, "example.test");
        let api = asset("asset-api", ReconAssetKind::Subdomain, "api.example.test");
        let mut snapshot = ReconSnapshot::empty("snapshot-1".into(), RunId("run-1".into()), 1_000);
        snapshot.assets = vec![root.clone(), api.clone()];
        snapshot.relations.push(ReconAssetRelation {
            schema_version: CORE_SCHEMA_VERSION,
            id: "relation-1".into(),
            from_asset_id: root.id,
            to_asset_id: api.id,
            kind: ReconRelationKind::Owns,
            confidence: ReconConfidence::High,
            evidence_ids: vec![EvidenceId("evidence-1".into())],
            observed_at_ms: 1_000,
        });
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert_eq!(
            serde_json::from_str::<ReconSnapshot>(&encoded).unwrap(),
            snapshot
        );
    }

    #[test]
    fn recon_json_names_are_stable_and_unknown_values_are_rejected() {
        assert_eq!(serde_json::to_value(ReconMode::Breadth).unwrap(), "breadth");
        assert_eq!(
            serde_json::to_value(ReconCapability::ResolveDns).unwrap(),
            "resolve_dns"
        );
        assert_eq!(
            serde_json::to_value(ReconScopeClassification::RequiresReview).unwrap(),
            "requires_review"
        );
        assert!(serde_json::from_value::<ReconCapability>(json!("run_everything")).is_err());
    }

    #[test]
    fn decision_represents_adaptive_choice_instead_of_a_fixed_sequence() {
        let certificate_action = ReconAction {
            schema_version: CORE_SCHEMA_VERSION,
            id: "action-ct".into(),
            capability: ReconCapability::SearchCertificateTransparency,
            target_asset_ids: vec!["asset-root".into()],
            arguments: StructuredData::new(),
            reason: "Passive evidence has the best expected coverage.".into(),
            expected_information_gain: ReconInformationGain::High,
            risk: ReconRisk::Passive,
        };
        let dns_action = ReconAction {
            id: "action-dns".into(),
            capability: ReconCapability::ResolveDns,
            reason: "Verify a candidate only after it is discovered.".into(),
            expected_information_gain: ReconInformationGain::Medium,
            risk: ReconRisk::LowImpact,
            ..certificate_action.clone()
        };
        let decision = ReconDecision {
            schema_version: CORE_SCHEMA_VERSION,
            run_id: RunId("run-1".into()),
            step: 1,
            mode: ReconMode::Breadth,
            hypothesis_id: Some("hypothesis-1".into()),
            knowledge_gaps: vec![],
            candidate_actions: vec![certificate_action.clone(), dns_action],
            action_scores: vec![],
            recommended_action_id: Some(certificate_action.id.clone()),
            selected_action_id: Some(certificate_action.id),
            coverage: None,
            decision_summary: "Choose the passive action with greater information gain.".into(),
            stop_reason_code: None,
            stop_reason: None,
        };
        assert_eq!(decision.candidate_actions.len(), 2);
        assert_eq!(decision.selected_action_id, Some("action-ct".into()));
    }

    #[test]
    fn decision_engine_json_names_are_stable() {
        assert_eq!(
            serde_json::to_value(ReconStopReasonCode::MarginalInformationGainTooLow).unwrap(),
            "marginal_information_gain_too_low"
        );
        assert!(serde_json::from_value::<ReconStopReasonCode>(json!("guess")).is_err());
    }

    #[test]
    fn observation_links_facts_to_assets_and_real_evidence() {
        let observation = ReconObservation {
            schema_version: CORE_SCHEMA_VERSION,
            id: "observation-1".into(),
            run_id: RunId("run-1".into()),
            source: ReconObservationSource::DnsQuery,
            subject_asset_ids: vec!["asset-api".into()],
            summary: "The API hostname resolved to an address.".into(),
            facts: StructuredData::from([("address".into(), Value::String("192.0.2.10".into()))]),
            confidence: ReconConfidence::High,
            evidence_ids: vec![EvidenceId("evidence-1".into())],
            observed_at_ms: 1_000,
        };
        assert_eq!(
            observation.subject_asset_ids,
            vec![ReconAssetId("asset-api".into())]
        );
        assert_eq!(
            observation.evidence_ids,
            vec![EvidenceId("evidence-1".into())]
        );
    }
}
