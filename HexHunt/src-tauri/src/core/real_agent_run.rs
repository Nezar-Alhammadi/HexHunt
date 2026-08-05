use super::{
    AgentRunResult, AgentRuntime, AgentRuntimeError, AgentRuntimeErrorCode, CoreToolExecutor,
    HttpRequestTool, LlmAgent, ModelConfig, OpenRouterProvider, PromptVersion, RunId, RunService,
    Task, TaskBudget, TaskId, CORE_SCHEMA_VERSION,
};
use crate::scope_guard::{ScopeGuardState, ScopeProject};
use std::sync::Arc;

pub fn execute_openrouter_agent_run(
    service: &RunService,
    run_id: &RunId,
    scope_guard: Arc<ScopeGuardState>,
) -> Result<AgentRunResult, AgentRuntimeError> {
    let config = ModelConfig::from_env()
        .map_err(|error| configuration_failure(service, run_id, error.to_string()))?;
    execute_openrouter_agent_run_with_config(
        service,
        run_id,
        scope_guard,
        config,
        super::current_agent_prompt(),
    )
}

pub fn execute_openrouter_agent_run_with_isolated_scope(
    service: &RunService,
    run_id: &RunId,
) -> Result<AgentRunResult, AgentRuntimeError> {
    execute_openrouter_agent_run(service, run_id, Arc::new(ScopeGuardState::default()))
}

pub fn execute_openrouter_agent_run_with_config(
    service: &RunService,
    run_id: &RunId,
    scope_guard: Arc<ScopeGuardState>,
    config: ModelConfig,
    prompt: PromptVersion,
) -> Result<AgentRunResult, AgentRuntimeError> {
    let provider = OpenRouterProvider::new(config)
        .map_err(|error| configuration_failure(service, run_id, error.to_string()))?;
    let http_tool = HttpRequestTool::new(scope_guard).map_err(|error| {
        configuration_failure(
            service,
            run_id,
            format!("{}: {}", error.code, error.message),
        )
    })?;
    let executor = CoreToolExecutor::new(http_tool);
    let mut agent = LlmAgent::with_prompt(Arc::new(provider), prompt);
    AgentRuntime::default().execute_managed(service, run_id, &mut agent, &executor)
}

fn configuration_failure(
    service: &RunService,
    run_id: &RunId,
    message: impl Into<String>,
) -> AgentRuntimeError {
    let message = message.into();
    if service
        .get_run(run_id)
        .is_ok_and(|run| run.status == super::RunStatus::Created)
    {
        let _ = service.start_run(run_id);
        let _ = service.fail_run(
            run_id,
            super::RunFailure {
                code: "CONFIGURATION_ERROR".into(),
                message: message.clone(),
            },
        );
    }
    AgentRuntimeError::new(AgentRuntimeErrorCode::ConfigurationError, message)
}

pub fn local_profile_task(port: u16) -> Task {
    Task {
        schema_version: CORE_SCHEMA_VERSION,
        id: TaskId(String::new()),
        objective: "استخدم الأدوات المسموحة لطلب endpoint المحلي /profile. أعد اسم المستخدم والدور، ولا تنه المهمة إلا بعد وجود دليل مرتبط باستجابة HTTP المحفوظة."
            .into(),
        primary_target: format!("http://127.0.0.1:{port}/profile"),
        scope: ScopeProject {
            id: format!("local-profile-lab-{port}"),
            allowed_domains: vec!["127.0.0.1".into()],
            excluded_domains: vec![],
            allowed_ports: vec![port],
            request_rate: 5,
            authorized: true,
        },
        budget: TaskBudget {
            max_steps: 8,
            max_http_requests: 3,
            max_model_calls: 8,
            max_input_tokens: 40_000,
            max_output_tokens: 8_000,
            max_duration_ms: 180_000,
        },
        available_tools: vec!["http_request".into()],
        memory_policy: Default::default(),
    }
}
