use keyring::{Entry, Error as KeyringError};
use serde::Serialize;

const SERVICE_NAME: &str = "io.hexhunt.desktop";
const OPENROUTER_ACCOUNT: &str = "openrouter-api-key";
const OPENROUTER_ENV: &str = "OPENROUTER_API_KEY";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenRouterCredentialStatus {
    pub configured: bool,
    pub saved: bool,
    pub source: String,
}

fn entry() -> Result<Entry, String> {
    Entry::new(SERVICE_NAME, OPENROUTER_ACCOUNT).map_err(|_| {
        "CREDENTIAL_STORE_UNAVAILABLE: The operating system secret store is unavailable.".into()
    })
}

fn saved_key() -> Result<Option<String>, String> {
    match entry()?.get_password() {
        Ok(value) if !value.trim().is_empty() => Ok(Some(value)),
        Ok(_) | Err(KeyringError::NoEntry) => Ok(None),
        Err(_) => {
            Err("CREDENTIAL_READ_FAILED: HexHunt could not read the saved OpenRouter key.".into())
        }
    }
}

pub fn openrouter_credential_status() -> Result<OpenRouterCredentialStatus, String> {
    let saved = saved_key()?.is_some();
    let environment = std::env::var(OPENROUTER_ENV).is_ok_and(|value| !value.trim().is_empty());
    Ok(OpenRouterCredentialStatus {
        configured: saved || environment,
        saved,
        source: if saved {
            "secure_store"
        } else if environment {
            "environment"
        } else {
            "none"
        }
        .into(),
    })
}

pub fn save_openrouter_credential(api_key: String) -> Result<OpenRouterCredentialStatus, String> {
    let api_key = api_key.trim();
    if api_key.is_empty() {
        return Err("API_KEY_REQUIRED: Enter an OpenRouter API key before saving.".into());
    }
    entry()?.set_password(api_key)
        .map_err(|_| "CREDENTIAL_SAVE_FAILED: HexHunt could not save the key in the operating system secret store.".to_string())?;
    std::env::set_var(OPENROUTER_ENV, api_key);
    Ok(OpenRouterCredentialStatus {
        configured: true,
        saved: true,
        source: "secure_store".into(),
    })
}

pub fn delete_openrouter_credential() -> Result<OpenRouterCredentialStatus, String> {
    match entry()?.delete_credential() {
        Ok(()) | Err(KeyringError::NoEntry) => {}
        Err(_) => {
            return Err(
                "CREDENTIAL_DELETE_FAILED: HexHunt could not remove the saved OpenRouter key."
                    .into(),
            )
        }
    }
    std::env::remove_var(OPENROUTER_ENV);
    Ok(OpenRouterCredentialStatus {
        configured: false,
        saved: false,
        source: "none".into(),
    })
}

pub fn load_saved_openrouter_credential() {
    if std::env::var(OPENROUTER_ENV).is_ok_and(|value| !value.trim().is_empty()) {
        return;
    }
    if let Ok(Some(api_key)) = saved_key() {
        std::env::set_var(OPENROUTER_ENV, api_key);
    }
}
