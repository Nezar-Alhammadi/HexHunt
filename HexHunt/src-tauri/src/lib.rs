pub mod core;
mod scope_guard;
use tauri::Manager;

#[cfg(target_os = "linux")]
fn configure_linux_webkit() {
    const SOFTWARE_RENDERING: &str = "HEXHUNT_SOFTWARE_RENDERING";

    let override_value = std::env::var(SOFTWARE_RENDERING).ok();
    let force_software = match override_value.as_deref() {
        Some("1" | "true" | "yes") => true,
        Some("0" | "false" | "no") => false,
        _ => linux_host_looks_like_vmware(),
    };

    if !force_software {
        return;
    }

    set_env_if_missing("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    set_env_if_missing("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
}

#[cfg(target_os = "linux")]
fn linux_host_looks_like_vmware() -> bool {
    [
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
    ]
    .iter()
    .filter_map(|path| std::fs::read_to_string(path).ok())
    .any(|value| value.to_ascii_lowercase().contains("vmware"))
}

#[cfg(target_os = "linux")]
fn set_env_if_missing(key: &str, value: &str) {
    if std::env::var_os(key).is_none() {
        std::env::set_var(key, value);
    }
}

#[tauri::command]
fn validate_scope_target(
    project: scope_guard::ScopeProject,
    target_value: String,
) -> scope_guard::ScopeDecision {
    scope_guard::validate(&project, &target_value)
}

#[tauri::command]
fn authorize_scoped_request(
    state: tauri::State<'_, std::sync::Arc<scope_guard::ScopeGuardState>>,
    project: scope_guard::ScopeProject,
    target_value: String,
) -> scope_guard::ScopeDecision {
    state.authorize_request(&project, &target_value)
}

#[tauri::command]
async fn openrouter_api_key_status() -> Result<core::OpenRouterCredentialStatus, String> {
    tauri::async_runtime::spawn_blocking(core::openrouter_credential_status)
        .await
        .map_err(|_| {
            "CREDENTIAL_TASK_FAILED: The credential check stopped unexpectedly.".to_string()
        })?
}

#[tauri::command]
async fn save_openrouter_api_key(
    api_key: String,
) -> Result<core::OpenRouterCredentialStatus, String> {
    tauri::async_runtime::spawn_blocking(move || core::save_openrouter_credential(api_key))
        .await
        .map_err(|_| {
            "CREDENTIAL_TASK_FAILED: Saving the credential stopped unexpectedly.".to_string()
        })?
}

#[tauri::command]
async fn delete_openrouter_api_key() -> Result<core::OpenRouterCredentialStatus, String> {
    tauri::async_runtime::spawn_blocking(core::delete_openrouter_credential)
        .await
        .map_err(|_| {
            "CREDENTIAL_TASK_FAILED: Removing the credential stopped unexpectedly.".to_string()
        })?
}

#[tauri::command]
fn save_browser_identity(
    identity: core::BrowserIdentityInput,
) -> Result<core::BrowserIdentity, String> {
    core::browser_session_vault().save(identity)
}

#[tauri::command]
fn list_browser_identities() -> Result<Vec<core::BrowserIdentity>, String> {
    core::browser_session_vault().list()
}

#[tauri::command]
fn delete_browser_identity(identity_id: core::BrowserIdentityId) -> Result<bool, String> {
    core::browser_session_vault().delete(&identity_id)
}

#[tauri::command]
fn external_recon_source_status() -> core::ExternalSourceStatus {
    core::external_source_status()
}

#[tauri::command]
fn create_run(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    task: core::Task,
) -> Result<core::Run, core::RunServiceError> {
    state.create_run(task)
}

#[tauri::command]
fn start_run(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    run_id: core::RunId,
) -> Result<core::Run, core::RunServiceError> {
    state.start_run(&run_id)
}

#[tauri::command]
fn get_run(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    run_id: core::RunId,
) -> Result<core::Run, core::RunServiceError> {
    state.get_run(&run_id)
}

#[tauri::command]
fn list_runs(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<core::Page<core::RunListItem>, core::RunServiceError> {
    state.list_run_summaries(core::PageRequest {
        offset: offset.unwrap_or(0),
        limit: limit.unwrap_or(core::DEFAULT_PAGE_LIMIT),
    })
}

#[tauri::command]
fn get_run_events(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    run_id: core::RunId,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<core::Page<core::RunEvent>, core::RunServiceError> {
    state.page_run_events(
        &run_id,
        core::PageRequest {
            offset: offset.unwrap_or(0),
            limit: limit.unwrap_or(core::DEFAULT_PAGE_LIMIT),
        },
    )
}

#[tauri::command]
fn get_tool_results(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    run_id: core::RunId,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<core::Page<core::ToolResult>, core::RunServiceError> {
    state.page_tool_results(&run_id, page_request(offset, limit))
}

#[tauri::command]
fn get_evidence(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    run_id: core::RunId,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<core::Page<core::Evidence>, core::RunServiceError> {
    state.page_evidence(&run_id, page_request(offset, limit))
}

#[tauri::command]
fn get_model_calls(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    run_id: core::RunId,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<core::Page<core::ModelCallRecord>, core::RunServiceError> {
    state.page_model_calls(&run_id, page_request(offset, limit))
}

#[tauri::command]
fn get_evaluation_result(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    run_id: core::RunId,
) -> Result<Option<core::EvaluationResult>, core::RunServiceError> {
    state.get_evaluation_result(&run_id)
}

#[tauri::command]
fn get_task_for_run(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    run_id: core::RunId,
) -> Result<core::Task, core::RunServiceError> {
    state.get_run_task(&run_id)
}

#[tauri::command]
fn get_run_details(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    run_id: core::RunId,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<core::RunDetails, core::RunServiceError> {
    state.get_run_details(&run_id, page_request(offset, limit))
}

#[tauri::command]
fn get_recon_report(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    run_id: core::RunId,
) -> Result<core::ReconReport, core::RunServiceError> {
    state.build_recon_report(&run_id)
}

#[tauri::command]
fn compare_recon_runs(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    baseline_run_id: core::RunId,
    current_run_id: core::RunId,
) -> Result<core::ReconSnapshotDelta, core::RunServiceError> {
    state.compare_recon_runs(&baseline_run_id, &current_run_id)
}

fn page_request(offset: Option<usize>, limit: Option<usize>) -> core::PageRequest {
    core::PageRequest {
        offset: offset.unwrap_or(0),
        limit: limit.unwrap_or(core::DEFAULT_PAGE_LIMIT),
    }
}

#[tauri::command]
fn cancel_run(
    state: tauri::State<'_, std::sync::Arc<core::RunService>>,
    run_id: core::RunId,
    reason: Option<String>,
) -> Result<core::Run, core::RunServiceError> {
    state.cancel_run(&run_id, reason)
}

#[tauri::command]
async fn execute_agent_run(
    run_service: tauri::State<'_, std::sync::Arc<core::RunService>>,
    scope_guard: tauri::State<'_, std::sync::Arc<scope_guard::ScopeGuardState>>,
    run_id: core::RunId,
) -> Result<core::AgentRunResult, core::AgentRuntimeError> {
    let run_service = run_service.inner().clone();
    let scope_guard = scope_guard.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        core::execute_openrouter_agent_run(run_service.as_ref(), &run_id, scope_guard)
    })
    .await
    .map_err(|_| {
        core::AgentRuntimeError::new(
            core::AgentRuntimeErrorCode::RunServiceError,
            "The agent execution task stopped unexpectedly.",
        )
    })?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "linux")]
    configure_linux_webkit();

    core::load_saved_openrouter_credential();

    tauri::Builder::default()
        .manage(std::sync::Arc::new(scope_guard::ScopeGuardState::default()))
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            let repository = std::sync::Arc::new(core::SqliteRunRepository::open(
                &app_data_dir.join("hexhunt-v1.sqlite3"),
            )?);
            let service = core::RunService::with_repository(repository.clone())?;
            service.recover_interrupted_runs()?;
            app.manage(std::sync::Arc::new(service));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            validate_scope_target,
            authorize_scoped_request,
            openrouter_api_key_status,
            save_openrouter_api_key,
            delete_openrouter_api_key,
            save_browser_identity,
            list_browser_identities,
            delete_browser_identity,
            external_recon_source_status,
            create_run,
            start_run,
            get_run,
            list_runs,
            get_run_events,
            get_tool_results,
            get_evidence,
            get_model_calls,
            get_evaluation_result,
            get_task_for_run,
            get_run_details,
            get_recon_report,
            compare_recon_runs,
            cancel_run,
            execute_agent_run
        ])
        .run(tauri::generate_context!())
        .expect("error while running HexHunt");
}
