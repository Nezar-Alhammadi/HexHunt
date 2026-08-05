use super::{
    current_agent_prompt, Agent, AgentAction, AgentContext, AgentError, ModelCallRecord,
    ModelProvider, ModelRequest, ModelToolDefinition, PromptVersion,
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use url::Url;

const MAX_CONTEXT_STRING_CHARS: usize = 768;
const MAX_CONTEXT_ARRAY_ITEMS: usize = 40;
const MAX_WORKING_TOOL_RESULTS: usize = 8;
const MAX_WORKING_EVIDENCE: usize = 36;
const MAX_WORKING_ASSETS: usize = 72;
const MAX_WORKING_RELATIONS: usize = 96;
const MAX_WORKING_OBSERVATIONS: usize = 32;
const MAX_WORKING_HYPOTHESES: usize = 20;

pub struct LlmAgent {
    provider: Arc<dyn ModelProvider>,
    prompt: PromptVersion,
    last_model_call: Option<ModelCallRecord>,
    last_rejection: Option<String>,
}

impl LlmAgent {
    pub fn new(provider: Arc<dyn ModelProvider>) -> Self {
        Self {
            provider,
            prompt: current_agent_prompt(),
            last_model_call: None,
            last_rejection: None,
        }
    }

    pub fn with_prompt(provider: Arc<dyn ModelProvider>, prompt: PromptVersion) -> Self {
        Self {
            provider,
            prompt,
            last_model_call: None,
            last_rejection: None,
        }
    }

    fn build_request(&self, context: &AgentContext) -> ModelRequest {
        let recon_plan = context.recon_plan.clone().map(select_recon_decision);
        let recon_snapshot = select_recon_snapshot(
            &context.recon_snapshot,
            recon_plan.as_ref(),
            &context.task.primary_target,
        );
        let evidence = select_evidence(&context.evidence, &recon_snapshot);
        let tool_results = select_tool_results(&context.tool_results, &evidence);
        let recon_memory = select_recon_memory(&context.recon_memory, &recon_snapshot);
        ModelRequest {
            system_instructions: self.prompt.redacted_text.clone(),
            prompt_id: self.prompt.prompt_id.clone(),
            prompt_version: self.prompt.version,
            prompt_hash: self.prompt.hash.clone(),
            task: context.task.clone(),
            run_id: context.run_id.clone(),
            current_step: context.current_step,
            tools: tool_definitions(&context.task.available_tools),
            tool_results,
            evidence,
            remaining_budget: context.remaining_budget.clone(),
            last_rejection: self.last_rejection.clone(),
            recon_snapshot,
            recon_plan,
            recon_memory,
            recon_critique: context.recon_critique.clone(),
            browser_identities: context.browser_identities.clone(),
        }
    }
}

fn select_recon_decision(mut decision: super::ReconDecision) -> super::ReconDecision {
    let mut ranked = decision.action_scores.clone();
    ranked.sort_by(|left, right| right.total.cmp(&left.total));
    let mut action_ids = ranked
        .iter()
        .take(8)
        .map(|score| score.action_id.clone())
        .collect::<HashSet<_>>();
    if let Some(id) = &decision.recommended_action_id {
        action_ids.insert(id.clone());
    }
    if let Some(id) = &decision.selected_action_id {
        action_ids.insert(id.clone());
    }
    decision
        .candidate_actions
        .retain(|action| action_ids.contains(&action.id));
    decision
        .action_scores
        .retain(|score| action_ids.contains(&score.action_id));
    let relevant_assets = decision
        .candidate_actions
        .iter()
        .flat_map(|action| action.target_asset_ids.iter().cloned())
        .collect::<HashSet<_>>();
    decision
        .knowledge_gaps
        .sort_by_key(|gap| (!relevant_assets.contains(&gap.asset_id), !gap.actionable));
    decision.knowledge_gaps.truncate(16);
    for action in &mut decision.candidate_actions {
        truncate_string(&mut action.reason, 384);
        for value in action.arguments.values_mut() {
            compact_json_value(value);
        }
    }
    for score in &mut decision.action_scores {
        score.rationale.truncate(4);
        for rationale in &mut score.rationale {
            truncate_string(rationale, 256);
        }
    }
    truncate_string(&mut decision.decision_summary, 768);
    if let Some(reason) = &mut decision.stop_reason {
        truncate_string(reason, 384);
    }
    decision
}

fn select_recon_snapshot(
    snapshot: &super::ReconSnapshot,
    plan: Option<&super::ReconDecision>,
    primary_target: &str,
) -> super::ReconSnapshot {
    let mut asset_scores = HashMap::<super::ReconAssetId, i32>::new();
    let primary_host = Url::parse(primary_target)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()));
    for asset in &snapshot.assets {
        let mut score = match asset.kind {
            super::ReconAssetKind::Organization | super::ReconAssetKind::RootDomain => 90,
            super::ReconAssetKind::AuthenticationSurface | super::ReconAssetKind::Api => 45,
            _ => 0,
        };
        if primary_host
            .as_ref()
            .is_some_and(|host| asset.canonical_value.to_ascii_lowercase().contains(host))
        {
            score += 45;
        }
        if score > 0 {
            bump_asset_score(&mut asset_scores, &asset.id, score);
        }
    }

    let mut priority_observations = HashSet::<super::ReconObservationId>::new();
    let current_hypothesis_id = plan.and_then(|decision| decision.hypothesis_id.clone());
    if let Some(plan) = plan {
        for gap in &plan.knowledge_gaps {
            bump_asset_score(
                &mut asset_scores,
                &gap.asset_id,
                if gap.actionable { 85 } else { 40 },
            );
        }
        for action in &plan.candidate_actions {
            let score = if plan.recommended_action_id.as_ref() == Some(&action.id) {
                130
            } else if plan.selected_action_id.as_ref() == Some(&action.id) {
                120
            } else {
                75
            };
            for asset_id in &action.target_asset_ids {
                bump_asset_score(&mut asset_scores, asset_id, score);
            }
        }
    }
    for hypothesis in snapshot.hypotheses.iter().rev() {
        let score = if current_hypothesis_id.as_ref() == Some(&hypothesis.id) {
            130
        } else {
            match hypothesis.status {
                super::ReconHypothesisStatus::Testing => 100,
                super::ReconHypothesisStatus::Proposed => 85,
                super::ReconHypothesisStatus::Supported => 65,
                super::ReconHypothesisStatus::Inconclusive => 45,
                super::ReconHypothesisStatus::Rejected => 0,
            }
        };
        if score == 0 {
            continue;
        }
        for asset_id in &hypothesis.subject_asset_ids {
            bump_asset_score(&mut asset_scores, asset_id, score);
        }
        if current_hypothesis_id.as_ref() == Some(&hypothesis.id) {
            priority_observations.extend(hypothesis.supporting_observation_ids.iter().cloned());
            priority_observations.extend(hypothesis.contradicting_observation_ids.iter().cloned());
        }
    }
    for observation in snapshot.observations.iter().rev().take(8) {
        priority_observations.insert(observation.id.clone());
        for asset_id in &observation.subject_asset_ids {
            bump_asset_score(&mut asset_scores, asset_id, 95);
        }
    }

    let anchor_scores = asset_scores.clone();
    for relation in &snapshot.relations {
        if let Some(score) = anchor_scores.get(&relation.from_asset_id) {
            bump_asset_score(
                &mut asset_scores,
                &relation.to_asset_id,
                score.saturating_sub(35).max(20),
            );
        }
        if let Some(score) = anchor_scores.get(&relation.to_asset_id) {
            bump_asset_score(
                &mut asset_scores,
                &relation.from_asset_id,
                score.saturating_sub(35).max(20),
            );
        }
    }
    if asset_scores.is_empty() {
        for asset in snapshot.assets.iter().rev().take(24) {
            bump_asset_score(&mut asset_scores, &asset.id, 20);
        }
    }

    let mut assets = snapshot.assets.clone();
    assets.sort_by(|left, right| {
        asset_scores
            .get(&right.id)
            .copied()
            .unwrap_or_default()
            .cmp(&asset_scores.get(&left.id).copied().unwrap_or_default())
            .then_with(|| right.last_seen_at_ms.cmp(&left.last_seen_at_ms))
    });
    assets.retain(|asset| asset_scores.contains_key(&asset.id));
    assets.truncate(MAX_WORKING_ASSETS);
    for asset in &mut assets {
        asset.tags.truncate(12);
        truncate_string(&mut asset.canonical_value, 512);
        truncate_string(&mut asset.scope_reason, 256);
    }
    let selected_asset_ids = assets
        .iter()
        .map(|asset| asset.id.clone())
        .collect::<HashSet<_>>();

    let mut relations = snapshot
        .relations
        .iter()
        .filter(|relation| {
            selected_asset_ids.contains(&relation.from_asset_id)
                && selected_asset_ids.contains(&relation.to_asset_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    relations.sort_by(|left, right| {
        relation_score(right, &asset_scores)
            .cmp(&relation_score(left, &asset_scores))
            .then_with(|| right.observed_at_ms.cmp(&left.observed_at_ms))
    });
    relations.truncate(MAX_WORKING_RELATIONS);
    for relation in &mut relations {
        relation.evidence_ids.truncate(4);
    }

    let mut observations = snapshot
        .observations
        .iter()
        .filter(|observation| {
            priority_observations.contains(&observation.id)
                || observation
                    .subject_asset_ids
                    .iter()
                    .any(|id| selected_asset_ids.contains(id))
        })
        .cloned()
        .collect::<Vec<_>>();
    observations.sort_by(|left, right| {
        priority_observations
            .contains(&right.id)
            .cmp(&priority_observations.contains(&left.id))
            .then_with(|| right.observed_at_ms.cmp(&left.observed_at_ms))
    });
    observations.truncate(MAX_WORKING_OBSERVATIONS);
    for observation in &mut observations {
        truncate_string(&mut observation.summary, 512);
        for value in observation.facts.values_mut() {
            compact_json_value(value);
        }
    }
    let selected_observation_ids = observations
        .iter()
        .map(|observation| observation.id.clone())
        .collect::<HashSet<_>>();

    let mut hypotheses = snapshot.hypotheses.clone();
    hypotheses.sort_by(|left, right| {
        hypothesis_score(right, current_hypothesis_id.as_ref(), &selected_asset_ids).cmp(
            &hypothesis_score(left, current_hypothesis_id.as_ref(), &selected_asset_ids),
        )
    });
    hypotheses.retain(|hypothesis| {
        hypothesis_score(
            hypothesis,
            current_hypothesis_id.as_ref(),
            &selected_asset_ids,
        ) > 0
            || hypothesis
                .supporting_observation_ids
                .iter()
                .chain(hypothesis.contradicting_observation_ids.iter())
                .any(|id| selected_observation_ids.contains(id))
    });
    hypotheses.truncate(MAX_WORKING_HYPOTHESES);
    for hypothesis in &mut hypotheses {
        truncate_string(&mut hypothesis.statement, 512);
        truncate_string(&mut hypothesis.rationale, 512);
        hypothesis.supporting_observation_ids.truncate(12);
        hypothesis.contradicting_observation_ids.truncate(12);
    }

    super::ReconSnapshot {
        schema_version: snapshot.schema_version,
        id: snapshot.id.clone(),
        run_id: snapshot.run_id.clone(),
        created_at_ms: snapshot.created_at_ms,
        assets,
        relations,
        observations,
        hypotheses,
        decisions: Vec::new(),
    }
}

fn select_evidence(
    evidence: &[super::Evidence],
    snapshot: &super::ReconSnapshot,
) -> Vec<super::Evidence> {
    let relevant_ids = snapshot
        .observations
        .iter()
        .flat_map(|observation| observation.evidence_ids.iter().cloned())
        .chain(
            snapshot
                .relations
                .iter()
                .flat_map(|relation| relation.evidence_ids.iter().cloned()),
        )
        .collect::<HashSet<_>>();
    let recent_ids = evidence
        .iter()
        .rev()
        .take(8)
        .map(|item| item.id.clone())
        .collect::<HashSet<_>>();
    let mut selected = evidence
        .iter()
        .filter(|item| relevant_ids.contains(&item.id) || recent_ids.contains(&item.id))
        .cloned()
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| {
        relevant_ids
            .contains(&right.id)
            .cmp(&relevant_ids.contains(&left.id))
            .then_with(|| right.recorded_at_ms.cmp(&left.recorded_at_ms))
    });
    selected.truncate(MAX_WORKING_EVIDENCE);
    for item in &mut selected {
        truncate_string(&mut item.description, 384);
        truncate_string(&mut item.value_or_excerpt, MAX_CONTEXT_STRING_CHARS);
    }
    selected
}

fn select_tool_results(
    results: &[super::ToolResult],
    evidence: &[super::Evidence],
) -> Vec<super::ToolResult> {
    let referenced = evidence
        .iter()
        .filter_map(|item| match &item.source {
            super::EvidenceSource::ToolResult { tool_result_id } => Some(tool_result_id.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let recent_ids = results
        .iter()
        .rev()
        .take(4)
        .map(|result| result.id.clone())
        .collect::<HashSet<_>>();
    let mut selected = results
        .iter()
        .enumerate()
        .filter(|(_, result)| {
            referenced.contains(&result.id) || recent_ids.contains(&result.id) || !result.success
        })
        .map(|(index, result)| (index, result.clone()))
        .collect::<Vec<_>>();
    selected.sort_by(|(left_index, left), (right_index, right)| {
        referenced
            .contains(&right.id)
            .cmp(&referenced.contains(&left.id))
            .then_with(|| right_index.cmp(left_index))
    });
    selected.truncate(MAX_WORKING_TOOL_RESULTS);
    selected
        .into_iter()
        .map(|(_, mut result)| {
            let mut truncated = false;
            for value in result.data.values_mut() {
                truncated |= compact_json_value(value);
            }
            if truncated {
                result
                    .data
                    .insert("model_context_truncated".into(), Value::Bool(true));
            }
            result
        })
        .collect()
}

fn select_recon_memory(
    memory: &super::ReconMemory,
    snapshot: &super::ReconSnapshot,
) -> super::ReconMemory {
    let selected_values = snapshot
        .assets
        .iter()
        .map(|asset| asset.canonical_value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let mut assets = memory
        .assets
        .iter()
        .filter(|asset| context_value_related(&asset.canonical_value, &selected_values))
        .cloned()
        .collect::<Vec<_>>();
    if assets.is_empty() {
        assets.extend(memory.assets.iter().rev().take(8).cloned());
    }
    assets.truncate(32);
    let mut prior_actions = memory
        .prior_actions
        .iter()
        .filter(|action| {
            action
                .target_values
                .iter()
                .any(|value| context_value_related(value, &selected_values))
        })
        .cloned()
        .collect::<Vec<_>>();
    if prior_actions.is_empty() {
        prior_actions.extend(memory.prior_actions.iter().rev().take(8).cloned());
    }
    prior_actions.truncate(24);
    for action in &mut prior_actions {
        for value in action.arguments.values_mut() {
            compact_json_value(value);
        }
    }
    super::ReconMemory {
        source_run_ids: memory
            .source_run_ids
            .iter()
            .rev()
            .take(12)
            .cloned()
            .collect(),
        assets,
        prior_actions,
        hypotheses: memory.hypotheses.iter().rev().take(12).cloned().collect(),
    }
}

fn bump_asset_score(
    scores: &mut HashMap<super::ReconAssetId, i32>,
    asset_id: &super::ReconAssetId,
    score: i32,
) {
    scores
        .entry(asset_id.clone())
        .and_modify(|current| *current = (*current).max(score))
        .or_insert(score);
}

fn relation_score(
    relation: &super::ReconAssetRelation,
    scores: &HashMap<super::ReconAssetId, i32>,
) -> i32 {
    scores
        .get(&relation.from_asset_id)
        .copied()
        .unwrap_or_default()
        + scores
            .get(&relation.to_asset_id)
            .copied()
            .unwrap_or_default()
}

fn hypothesis_score(
    hypothesis: &super::ReconHypothesis,
    current: Option<&super::ReconHypothesisId>,
    selected_assets: &HashSet<super::ReconAssetId>,
) -> i32 {
    let mut score = if current == Some(&hypothesis.id) {
        150
    } else {
        match hypothesis.status {
            super::ReconHypothesisStatus::Testing => 100,
            super::ReconHypothesisStatus::Proposed => 85,
            super::ReconHypothesisStatus::Supported => 70,
            super::ReconHypothesisStatus::Inconclusive => 45,
            super::ReconHypothesisStatus::Rejected => 0,
        }
    };
    if hypothesis
        .subject_asset_ids
        .iter()
        .any(|id| selected_assets.contains(id))
    {
        score += 35;
    }
    score
}

fn context_value_related(candidate: &str, selected_values: &HashSet<String>) -> bool {
    let candidate = candidate.to_ascii_lowercase();
    let candidate_host = Url::parse(&candidate)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_else(|| candidate.trim_end_matches('.').to_string());
    selected_values.iter().any(|selected| {
        let selected_host = Url::parse(selected)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .unwrap_or_else(|| selected.trim_end_matches('.').to_string());
        candidate == *selected
            || candidate_host == selected_host
            || candidate_host.ends_with(&format!(".{selected_host}"))
            || selected_host.ends_with(&format!(".{candidate_host}"))
    })
}

fn compact_json_value(value: &mut Value) -> bool {
    match value {
        Value::String(text) => truncate_string(text, MAX_CONTEXT_STRING_CHARS),
        Value::Array(items) => {
            let mut truncated = false;
            if items.len() > MAX_CONTEXT_ARRAY_ITEMS {
                items.truncate(MAX_CONTEXT_ARRAY_ITEMS);
                truncated = true;
            }
            for item in items {
                truncated |= compact_json_value(item);
            }
            truncated
        }
        Value::Object(object) => object.values_mut().fold(false, |truncated, item| {
            compact_json_value(item) || truncated
        }),
        _ => false,
    }
}

fn truncate_string(value: &mut String, max_chars: usize) -> bool {
    if value.chars().count() <= max_chars {
        return false;
    }
    let mut truncated = value.chars().take(max_chars).collect::<String>();
    truncated.push('…');
    *value = truncated;
    true
}

impl Agent for LlmAgent {
    fn next_action(&mut self, context: &AgentContext) -> Result<AgentAction, AgentError> {
        self.last_model_call = None;
        let request = self.build_request(context);
        match self.provider.generate_next_action(&request) {
            Ok(generation) => {
                self.last_model_call = Some(generation.call);
                self.last_rejection = None;
                Ok(generation.action)
            }
            Err(error) => {
                self.last_model_call = Some(error.call);
                Err(AgentError {
                    code: format!("{:?}", error.code).to_ascii_uppercase(),
                    message: error.message,
                })
            }
        }
    }

    fn is_model_driven(&self) -> bool {
        true
    }

    fn take_last_model_call(&mut self) -> Option<ModelCallRecord> {
        self.last_model_call.take()
    }

    fn on_action_rejected(&mut self, action: &AgentAction, reason: &str) {
        self.last_rejection = Some(format!(
            "The previous '{}' action was rejected: {}. Return a corrected single action.",
            action.name, reason
        ));
    }
}

fn tool_definitions(allowed: &[String]) -> Vec<ModelToolDefinition> {
    let mut tools = Vec::new();
    if allowed.iter().any(|tool| tool == "http_request") {
        tools.push(ModelToolDefinition {
            name: "http_request".into(),
            description: "Perform one authorized HTTP GET or POST request after Scope Guard approval."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "method": {"enum": ["GET", "POST"]},
                    "url": {"type": "string"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string"},
                    "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 30000}
                },
                "required": ["method", "url"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "record_note") {
        tools.push(ModelToolDefinition {
            name: "record_note".into(),
            description: "Store a short internal run note.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
                "additionalProperties": false
            }),
        });
    }
    if allowed
        .iter()
        .any(|tool| tool == "search_certificate_transparency")
    {
        tools.push(ModelToolDefinition {
            name: "search_certificate_transparency".into(),
            description: "Search public Certificate Transparency records for hostnames related to one authorized domain. This is passive and scope checked.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "lookup_web_archive") {
        tools.push(ModelToolDefinition {
            name: "lookup_web_archive".into(),
            description: "Query passive Wayback and Common Crawl metadata for one authorized domain. Returns normalized historical URLs, JavaScript and endpoint clues, subdomains, timestamps, and parameter names. Query values and raw archive records are not retained, and archived URLs are not fetched from the target.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "resolve_dns") {
        tools.push(ModelToolDefinition {
            name: "resolve_dns".into(),
            description: "Resolve one authorized hostname, classify observed IP addresses, and when wildcard subdomains are explicitly in scope compare the result with a safe randomized wildcard DNS baseline.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"hostname": {"type": "string"}},
                "required": ["hostname"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "inspect_dns_ownership") {
        tools.push(ModelToolDefinition {
            name: "inspect_dns_ownership".into(),
            description: "Inspect authorized DNS ownership metadata through passive DNS-over-HTTPS. Returns CNAME, address, NS and MX structure, redacted TXT categories, cloud-provider hints, and a non-conclusive dangling-DNS candidate signal.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"hostname": {"type": "string"}},
                "required": ["hostname"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "inspect_rdap") {
        tools.push(ModelToolDefinition {
            name: "inspect_rdap".into(),
            description: "Read public RDAP metadata for one authorized domain or IP address. Returns registration state, nameservers, network range and lifecycle metadata while discarding contact entities and personal data.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "probe_tcp_service") {
        tools.push(ModelToolDefinition {
            name: "probe_tcp_service".into(),
            description: "Perform one authorized TCP connect check on an explicitly allowed host and port. It does not request a banner, send a protocol payload, or scan ports outside the supplied action.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hostname": {"type": "string"},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 10000}
                },
                "required": ["hostname", "port"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "probe_http") {
        tools.push(ModelToolDefinition {
            name: "probe_http".into(),
            description: "Perform one lightweight authorized HTTP GET probe and record a structured HTTP/TLS service profile, status, headers, redirect metadata, infrastructure hints, and a bounded body.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 30000}
                },
                "required": ["url"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "validate_url_metadata") {
        tools.push(ModelToolDefinition {
            name: "validate_url_metadata".into(),
            description: "Send one scope-checked HTTP HEAD request to verify whether a discovered historical URL, endpoint, or source-map candidate currently responds. No response body, payload, fuzzing, or business operation is sent.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 30000}
                },
                "required": ["url"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "discover_content") {
        tools.push(ModelToolDefinition {
            name: "discover_content".into(),
            description: "Check up to 32 evidence-guided paths on one authorized origin using bodyless HEAD requests. Supply paths chosen from the current graph, technologies, archive, authentication, or API clues; do not use random fuzz strings or query values.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "base_url": {"type": "string"},
                    "paths": {"type": "array", "minItems": 1, "maxItems": 32, "items": {"type": "string"}},
                    "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 30000}
                },
                "required": ["base_url", "paths"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "analyze_web_page") {
        tools.push(ModelToolDefinition {
            name: "analyze_web_page".into(),
            description: "Analyze one discovered authorized web page. Returns normalized same-origin links, forms without field values, scripts, parameter names, title, and surface signals. Raw HTML and query values are not retained; this action does not automatically crawl discovered links.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 30000}
                },
                "required": ["url"],
                "additionalProperties": false
            }),
        });
    }
    for (name, description) in [
        (
            "fetch_robots_txt",
            "Read /robots.txt from one authorized HTTP service without crawling its paths.",
        ),
        (
            "fetch_sitemap",
            "Read /sitemap.xml from one authorized HTTP service without crawling its entries.",
        ),
    ] {
        if allowed.iter().any(|tool| tool == name) {
            tools.push(ModelToolDefinition {
                name: name.into(),
                description: description.into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "base_url": {"type": "string"},
                        "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 30000}
                    },
                    "required": ["base_url"],
                    "additionalProperties": false
                }),
            });
        }
    }
    if allowed.iter().any(|tool| tool == "analyze_javascript") {
        tools.push(ModelToolDefinition {
            name: "analyze_javascript".into(),
            description: "Fetch and statically analyze one discovered in-scope JavaScript bundle. Returns normalized endpoint profiles, API base URLs, HTTP methods and parameter names, authentication signals, GraphQL operation names, WebSocket endpoints, imported chunks, technology hints, declared and heuristic source-map candidates, client security-signal categories, hashes, and only redacted secret-indicator categories. Raw source, credentials, and query values are not retained.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 30000}
                },
                "required": ["url"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "describe_api") {
        tools.push(ModelToolDefinition {
            name: "describe_api".into(),
            description: "Fetch one discovered in-scope OpenAPI, Swagger, or GraphQL metadata endpoint and extract operations, HTTP methods, parameter names and locations, declared authentication, schemas, servers, and GraphQL root metadata without invoking business operations or retaining the raw document.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 30000}
                },
                "required": ["url"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "analyze_visual_page") {
        tools.push(ModelToolDefinition {
            name: "analyze_visual_page".into(),
            description: "Capture one authorized page in a scope-filtered headless browser and ask a vision model for structured visual security observations. Screenshot bytes are discarded after analysis; only a hash, safe metadata, and redacted observations are retained.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "timeout_ms": {"type": "integer", "minimum": 1000, "maximum": 30000}
                },
                "required": ["url"],
                "additionalProperties": false
            }),
        });
    }
    if allowed.iter().any(|tool| tool == "adaptive_browser_recon") {
        tools.push(ModelToolDefinition {
            name: "adaptive_browser_recon".into(),
            description: "Render one authorized page in Chromium and collect sanitized dynamic DOM, SPA, storage-key names, and scope-filtered network response metadata. Optionally compare up to four session identities listed in browser_identities. Secret values, bodies, and query values are never returned.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "identity_ids": {"type": "array", "maxItems": 4, "items": {"type": "string"}},
                    "timeout_ms": {"type": "integer", "minimum": 1000, "maximum": 30000}
                },
                "required": ["url"],
                "additionalProperties": false
            }),
        });
    }
    if allowed
        .iter()
        .any(|tool| tool == "query_external_intelligence")
    {
        tools.push(ModelToolDefinition {
            name: "query_external_intelligence".into(),
            description: "Query every configured passive external source applicable to one authorized domain or IP. Supported connectors are Shodan, Censys, SecurityTrails passive DNS and subdomain metadata, and GitHub code-search metadata. API credentials, raw responses, banners, and source-code contents are never returned.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
                "additionalProperties": false
            }),
        });
    }
    tools
}
