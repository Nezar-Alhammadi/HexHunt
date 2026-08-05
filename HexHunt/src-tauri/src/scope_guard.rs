use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};
use url::Url;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ScopeProject {
    pub id: String,
    #[serde(alias = "allowedDomains")]
    pub allowed_domains: Vec<String>,
    #[serde(alias = "excludedDomains")]
    pub excluded_domains: Vec<String>,
    #[serde(alias = "allowedPorts")]
    pub allowed_ports: Vec<u16>,
    #[serde(alias = "requestRate")]
    pub request_rate: usize,
    pub authorized: bool,
}

#[derive(Debug, Serialize)]
pub struct ScopeDecision {
    pub allowed: bool,
    pub code: &'static str,
    pub reason: &'static str,
}

#[derive(Default)]
pub struct ScopeGuardState {
    request_times: Mutex<HashMap<String, VecDeque<Instant>>>,
}

fn allow() -> ScopeDecision {
    ScopeDecision {
        allowed: true,
        code: "allowed",
        reason: "Target is inside the authorized scope.",
    }
}

fn deny(code: &'static str, reason: &'static str) -> ScopeDecision {
    ScopeDecision {
        allowed: false,
        code,
        reason,
    }
}

fn normalized_rule(rule: &str) -> (String, bool) {
    let normalized = rule.trim().trim_end_matches('.').to_lowercase();
    let wildcard = normalized.starts_with("*.");
    let raw_rule = normalized.strip_prefix("*.").unwrap_or(&normalized);
    let hostname = Url::parse(raw_rule)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .or_else(|| {
            Url::parse(&format!("https://{raw_rule}"))
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
        })
        .unwrap_or_default();

    (hostname.trim_end_matches('.').to_lowercase(), wildcard)
}

fn matches_rule(hostname: &str, rule: &str) -> bool {
    let hostname = hostname.trim_end_matches('.').to_lowercase();
    let (rule_hostname, wildcard) = normalized_rule(rule);

    if rule_hostname.is_empty() {
        return false;
    }

    if wildcard {
        hostname.ends_with(&format!(".{rule_hostname}"))
    } else {
        hostname == rule_hostname
    }
}

pub fn validate(project: &ScopeProject, target_value: &str) -> ScopeDecision {
    if !project.authorized {
        return deny(
            "unauthorized",
            "The project has no authorization confirmation.",
        );
    }

    let Ok(target) = Url::parse(target_value) else {
        return deny("invalid-url", "The target is not a valid absolute URL.");
    };

    if target.scheme() != "http" && target.scheme() != "https" {
        return deny("protocol", "Only HTTP and HTTPS targets are allowed.");
    }

    let Some(hostname) = target.host_str() else {
        return deny("invalid-url", "The target URL has no hostname.");
    };

    if project
        .excluded_domains
        .iter()
        .any(|rule| matches_rule(hostname, rule))
    {
        return deny("excluded", "The target matches an excluded domain rule.");
    }

    if !project
        .allowed_domains
        .iter()
        .any(|rule| matches_rule(hostname, rule))
    {
        return deny("domain", "The target is outside the allowed domains.");
    }

    let port = target.port_or_known_default().unwrap_or_default();
    if !project.allowed_ports.contains(&port) {
        return deny("port", "The target port is outside the allowed ports.");
    }

    allow()
}

impl ScopeGuardState {
    pub fn authorize_request(&self, project: &ScopeProject, target_value: &str) -> ScopeDecision {
        let target_decision = validate(project, target_value);
        if !target_decision.allowed {
            return target_decision;
        }

        let Ok(mut projects) = self.request_times.lock() else {
            return deny("guard-state", "The scope guard state is unavailable.");
        };

        let now = Instant::now();
        let request_times = projects.entry(project.id.clone()).or_default();
        while request_times
            .front()
            .is_some_and(|request_time| now.duration_since(*request_time) >= Duration::from_secs(1))
        {
            request_times.pop_front();
        }

        if request_times.len() >= project.request_rate {
            return deny(
                "rate-limit",
                "The project request rate limit has been reached.",
            );
        }

        request_times.push_back(now);
        target_decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> ScopeProject {
        ScopeProject {
            id: "project-1".into(),
            allowed_domains: vec!["example.test".into(), "*.lab.example.test".into()],
            excluded_domains: vec!["admin.example.test".into()],
            allowed_ports: vec![80, 443],
            request_rate: 2,
            authorized: true,
        }
    }

    #[test]
    fn allows_exact_and_wildcard_scope() {
        assert!(validate(&project(), "https://example.test/path").allowed);
        assert!(validate(&project(), "https://api.lab.example.test").allowed);
    }

    #[test]
    fn exclusion_wins_and_lookalikes_are_denied() {
        let mut scoped_project = project();
        scoped_project
            .allowed_domains
            .push("admin.example.test".into());

        assert_eq!(
            validate(&scoped_project, "https://admin.example.test").code,
            "excluded"
        );
        assert_eq!(
            validate(&project(), "https://example.test.attacker.invalid").code,
            "domain"
        );
    }

    #[test]
    fn denies_unlisted_ports_and_protocols() {
        assert_eq!(
            validate(&project(), "https://example.test:8443").code,
            "port"
        );
        assert_eq!(validate(&project(), "ftp://example.test").code, "protocol");
    }

    #[test]
    fn enforces_the_project_request_rate() {
        let guard = ScopeGuardState::default();
        let scoped_project = project();

        assert!(
            guard
                .authorize_request(&scoped_project, "https://example.test")
                .allowed
        );
        assert!(
            guard
                .authorize_request(&scoped_project, "https://example.test")
                .allowed
        );
        assert_eq!(
            guard
                .authorize_request(&scoped_project, "https://example.test")
                .code,
            "rate-limit"
        );
    }
}
