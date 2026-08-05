use super::{
    Clock, Evidence, HistoricalUrlKind, HistoricalUrlSummary, ReconAsset, ReconAssetId,
    ReconAssetKind, ReconAssetRelation, ReconConfidence, ReconCorrelator, ReconObservation,
    ReconObservationId, ReconObservationSource, ReconRelationId, ReconRelationKind,
    ReconScopeClassification, RunId, RunService, RunServiceError, RunServiceErrorCode,
    StructuredData, SystemClock, Task, ToolResult, CORE_SCHEMA_VERSION,
};
use crate::scope_guard::validate;
use regex::Regex;
use serde_json::Value;
use std::{collections::BTreeSet, net::IpAddr, sync::Arc};
use url::Url;
use uuid::Uuid;

pub struct ReconIngestor {
    clock: Arc<dyn Clock>,
}

impl Default for ReconIngestor {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
}

impl ReconIngestor {
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }

    pub fn seed_task(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
    ) -> Result<(), RunServiceError> {
        let Ok(url) = Url::parse(&task.primary_target) else {
            return Ok(());
        };
        let Some(hostname) = url.host_str() else {
            return Ok(());
        };
        let kind = if hostname.parse::<IpAddr>().is_ok() {
            ReconAssetKind::IpAddress
        } else {
            ReconAssetKind::RootDomain
        };
        self.ensure_asset(
            service,
            run_id,
            task,
            kind,
            hostname,
            ReconConfidence::Confirmed,
        )?;
        Ok(())
    }

    pub fn ingest_tool_result(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        result: &ToolResult,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        if !result.success {
            if result.tool_name == "search_certificate_transparency" {
                let Some(domain) = string_field(&result.data, "domain") else {
                    return Ok(());
                };
                let root_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::RootDomain,
                    domain,
                    ReconConfidence::Confirmed,
                )?;
                return self.append_observation(
                    service,
                    run_id,
                    ReconObservationSource::CertificateTransparency,
                    vec![root_id],
                    format!("Certificate Transparency lookup for {domain} was inconclusive."),
                    StructuredData::from([(
                        "tool_error".into(),
                        result
                            .error
                            .as_ref()
                            .map(|error| Value::String(error.code.clone()))
                            .unwrap_or(Value::Null),
                    )]),
                    ReconConfidence::Low,
                    evidence,
                );
            }
            return Ok(());
        }
        let ingestion = match result.tool_name.as_str() {
            "search_certificate_transparency" => {
                self.ingest_certificate_transparency(service, run_id, task, result, evidence)
            }
            "resolve_dns" => self.ingest_dns(service, run_id, task, result, evidence),
            "inspect_dns_ownership" => {
                self.ingest_dns_ownership(service, run_id, task, result, evidence)
            }
            "inspect_rdap" => self.ingest_rdap(service, run_id, task, result, evidence),
            "probe_tcp_service" => self.ingest_tcp_service(service, run_id, task, result, evidence),
            "discover_content" => {
                self.ingest_content_discovery(service, run_id, task, result, evidence)
            }
            "lookup_web_archive" => self.ingest_historical(service, run_id, task, result, evidence),
            "http_request"
            | "probe_http"
            | "validate_url_metadata"
            | "fetch_robots_txt"
            | "fetch_sitemap"
            | "analyze_web_page"
            | "analyze_javascript"
            | "describe_api" => self.ingest_http(service, run_id, task, result, evidence),
            "analyze_visual_page" => self.ingest_visual(service, run_id, task, result, evidence),
            "adaptive_browser_recon" => {
                self.ingest_adaptive_browser(service, run_id, task, result, evidence)
            }
            "query_external_intelligence" => {
                self.ingest_external_intelligence(service, run_id, task, result, evidence)
            }
            _ => Ok(()),
        };
        ingestion?;
        ReconCorrelator::refresh(service, run_id)
    }

    fn ingest_certificate_transparency(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        result: &ToolResult,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        let Some(domain) = string_field(&result.data, "domain") else {
            return Ok(());
        };
        let root_id = self.ensure_asset(
            service,
            run_id,
            task,
            ReconAssetKind::RootDomain,
            domain,
            ReconConfidence::Confirmed,
        )?;
        self.enrich_asset(
            service,
            run_id,
            &root_id,
            ["source:certificate_transparency".into()],
        )?;
        let mut discovered = Vec::new();
        for hostname in string_array(&result.data, "subdomains") {
            let kind = if hostname.eq_ignore_ascii_case(domain) {
                ReconAssetKind::RootDomain
            } else {
                ReconAssetKind::Subdomain
            };
            let asset_id =
                self.ensure_asset(service, run_id, task, kind, hostname, ReconConfidence::High)?;
            self.enrich_asset(
                service,
                run_id,
                &asset_id,
                ["source:certificate_transparency".into()],
            )?;
            if asset_id != root_id {
                self.ensure_relation(
                    service,
                    run_id,
                    &root_id,
                    &asset_id,
                    ReconRelationKind::Owns,
                    evidence,
                )?;
            }
            discovered.push(Value::String(hostname.to_string()));
        }
        self.append_observation(
            service,
            run_id,
            ReconObservationSource::CertificateTransparency,
            vec![root_id],
            format!(
                "Certificate Transparency returned {} unique hostnames for {domain}.",
                discovered.len()
            ),
            StructuredData::from([
                ("domain".into(), Value::String(domain.into())),
                ("hostnames".into(), Value::Array(discovered)),
                (
                    "record_count".into(),
                    result
                        .data
                        .get("record_count")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
            ]),
            ReconConfidence::High,
            evidence,
        )
    }

    fn ingest_dns(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        result: &ToolResult,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        let Some(hostname) = string_field(&result.data, "hostname") else {
            return Ok(());
        };
        let snapshot = service.get_recon_snapshot(run_id)?;
        let kind = snapshot
            .assets
            .iter()
            .find(|asset| asset.canonical_value.eq_ignore_ascii_case(hostname))
            .map(|asset| asset.kind)
            .unwrap_or(ReconAssetKind::Subdomain);
        let resolved = result
            .data
            .get("resolved")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let wildcard_detected = result
            .data
            .get("wildcard_detected")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let wildcard_match = result
            .data
            .get("wildcard_match")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let confidence = if resolved && !wildcard_match {
            ReconConfidence::Confirmed
        } else if resolved {
            ReconConfidence::Medium
        } else {
            ReconConfidence::Low
        };
        let host_id = self.ensure_asset(service, run_id, task, kind, hostname, confidence)?;
        let mut host_tags = vec!["source:dns".to_string()];
        host_tags.push(if resolved {
            "dns:resolved".into()
        } else {
            "dns:unresolved".into()
        });
        if wildcard_detected {
            host_tags.push("dns:wildcard_zone".into());
        }
        if wildcard_match {
            host_tags.push("dns:wildcard_match".into());
        }
        self.enrich_asset(service, run_id, &host_id, host_tags)?;
        let mut subjects = vec![host_id.clone()];
        let mut addresses = Vec::new();
        for address in string_array(&result.data, "addresses") {
            if address.parse::<IpAddr>().is_err() {
                continue;
            }
            let address_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::IpAddress,
                address,
                ReconConfidence::High,
            )?;
            let classification = result
                .data
                .get("address_profiles")
                .and_then(Value::as_array)
                .and_then(|profiles| {
                    profiles.iter().find(|profile| {
                        profile.get("address").and_then(Value::as_str) == Some(address)
                    })
                })
                .and_then(|profile| profile.get("classification"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            self.enrich_asset(
                service,
                run_id,
                &address_id,
                ["source:dns".into(), format!("network:{classification}")],
            )?;
            self.ensure_relation(
                service,
                run_id,
                &host_id,
                &address_id,
                ReconRelationKind::ResolvesTo,
                evidence,
            )?;
            subjects.push(address_id);
            addresses.push(Value::String(address.into()));
        }
        self.append_observation(
            service,
            run_id,
            ReconObservationSource::DnsQuery,
            subjects,
            if addresses.is_empty() {
                format!("{hostname} did not resolve to an address.")
            } else {
                format!(
                    "{hostname} resolved to {} unique addresses.",
                    addresses.len()
                )
            },
            StructuredData::from([
                ("hostname".into(), Value::String(hostname.into())),
                ("addresses".into(), Value::Array(addresses)),
                (
                    "lookup_error".into(),
                    result
                        .data
                        .get("lookup_error")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                (
                    "address_profiles".into(),
                    result
                        .data
                        .get("address_profiles")
                        .cloned()
                        .unwrap_or_else(|| Value::Array(vec![])),
                ),
                ("wildcard_detected".into(), Value::Bool(wildcard_detected)),
                ("wildcard_match".into(), Value::Bool(wildcard_match)),
                (
                    "dns_query_count".into(),
                    result
                        .data
                        .get("dns_query_count")
                        .cloned()
                        .unwrap_or(Value::from(1)),
                ),
            ]),
            confidence,
            evidence,
        )
    }

    fn ingest_dns_ownership(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        result: &ToolResult,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        let Some(hostname) = string_field(&result.data, "hostname") else {
            return Ok(());
        };
        let snapshot = service.get_recon_snapshot(run_id)?;
        let host_kind = snapshot
            .assets
            .iter()
            .find(|asset| asset.canonical_value.eq_ignore_ascii_case(hostname))
            .map(|asset| asset.kind)
            .unwrap_or(ReconAssetKind::Subdomain);
        let host_id = self.ensure_asset(
            service,
            run_id,
            task,
            host_kind,
            hostname,
            ReconConfidence::High,
        )?;
        let dangling = result
            .data
            .get("dangling_candidate")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mut host_tags = vec!["source:dns_ownership".into()];
        if dangling {
            host_tags.push("dns:dangling_candidate".into());
        }
        self.enrich_asset(service, run_id, &host_id, host_tags)?;
        let mut subjects = vec![host_id.clone()];
        for record in result
            .data
            .get("records")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(500)
        {
            let Some(record_type) = record.get("record_type").and_then(Value::as_str) else {
                continue;
            };
            let Some(value) = record.get("value").and_then(Value::as_str) else {
                continue;
            };
            let record_identity = format!(
                "https://{hostname}/#hexhunt-dns-{}-{}",
                parameter_slug(record_type),
                stable_fragment(value)
            );
            let record_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::DnsRecord,
                &record_identity,
                ReconConfidence::High,
            )?;
            self.enrich_asset(
                service,
                run_id,
                &record_id,
                [
                    "source:dns_ownership".into(),
                    format!("dns:type:{}", record_type.to_ascii_lowercase()),
                    if record_type == "TXT" {
                        "dns:value_redacted".into()
                    } else {
                        "dns:value_normalized".into()
                    },
                ],
            )?;
            self.ensure_relation(
                service,
                run_id,
                &host_id,
                &record_id,
                ReconRelationKind::Exposes,
                evidence,
            )?;
            subjects.push(record_id);
        }
        for provider in string_array(&result.data, "provider_hints") {
            let identity = format!(
                "https://{hostname}/#hexhunt-cloud-{}",
                parameter_slug(provider)
            );
            let cloud_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::CloudResource,
                &identity,
                ReconConfidence::Medium,
            )?;
            self.enrich_asset(
                service,
                run_id,
                &cloud_id,
                [
                    "source:dns_ownership".into(),
                    format!("cloud:provider:{provider}"),
                ],
            )?;
            self.ensure_relation(
                service,
                run_id,
                &host_id,
                &cloud_id,
                ReconRelationKind::HostedOn,
                evidence,
            )?;
            subjects.push(cloud_id);
        }
        self.append_observation(
            service,
            run_id,
            ReconObservationSource::DnsOwnership,
            subjects,
            format!("DNS ownership inspection mapped normalized records and cloud-provider hints for {hostname}."),
            StructuredData::from([
                ("hostname".into(), Value::String(hostname.into())),
                ("records".into(), result.data.get("records").cloned().unwrap_or_else(|| Value::Array(vec![]))),
                ("provider_hints".into(), result.data.get("provider_hints").cloned().unwrap_or_else(|| Value::Array(vec![]))),
                ("dangling_candidate".into(), Value::Bool(dangling)),
                ("txt_values_redacted".into(), Value::Bool(true)),
            ]),
            if dangling { ReconConfidence::Medium } else { ReconConfidence::High },
            evidence,
        )
    }

    fn ingest_rdap(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        result: &ToolResult,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        let Some(target) = string_field(&result.data, "target") else {
            return Ok(());
        };
        let kind = if target.parse::<IpAddr>().is_ok() {
            ReconAssetKind::IpAddress
        } else {
            ReconAssetKind::RootDomain
        };
        let target_id =
            self.ensure_asset(service, run_id, task, kind, target, ReconConfidence::High)?;
        self.enrich_asset(service, run_id, &target_id, ["source:rdap".into()])?;
        let mut subjects = vec![target_id.clone()];
        if let (Some(start), Some(end)) = (
            string_field(&result.data, "start_address"),
            string_field(&result.data, "end_address"),
        ) {
            let identity = format!(
                "https://{target}/#hexhunt-network-{}",
                stable_fragment(&format!("{start}-{end}"))
            );
            let range_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::NetworkRange,
                &identity,
                ReconConfidence::High,
            )?;
            let mut range = service
                .get_recon_snapshot(run_id)?
                .assets
                .into_iter()
                .find(|asset| asset.id == range_id)
                .ok_or_else(|| {
                    RunServiceError::new(
                        RunServiceErrorCode::ReconItemNotFound,
                        "RDAP network-range asset was not found.",
                    )
                })?;
            range.display_name = Some(format!("{start} – {end}"));
            service.update_recon_asset(run_id, range)?;
            self.enrich_asset(service, run_id, &range_id, ["source:rdap".into()])?;
            self.ensure_relation(
                service,
                run_id,
                &target_id,
                &range_id,
                ReconRelationKind::RelatedTo,
                evidence,
            )?;
            subjects.push(range_id);
        }
        for asn in result
            .data
            .get("origin_asns")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_u64)
            .take(50)
        {
            let identity = format!("https://{target}/#hexhunt-asn-{asn}");
            let asn_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::Asn,
                &identity,
                ReconConfidence::High,
            )?;
            let mut asset = service
                .get_recon_snapshot(run_id)?
                .assets
                .into_iter()
                .find(|asset| asset.id == asn_id)
                .ok_or_else(|| {
                    RunServiceError::new(
                        RunServiceErrorCode::ReconItemNotFound,
                        "RDAP ASN asset was not found.",
                    )
                })?;
            asset.display_name = Some(format!("AS{asn}"));
            service.update_recon_asset(run_id, asset)?;
            self.enrich_asset(service, run_id, &asn_id, ["source:rdap".into()])?;
            self.ensure_relation(
                service,
                run_id,
                &target_id,
                &asn_id,
                ReconRelationKind::HostedOn,
                evidence,
            )?;
            subjects.push(asn_id);
        }
        self.append_observation(
            service,
            run_id,
            ReconObservationSource::Rdap,
            subjects,
            format!(
                "RDAP metadata mapped registration and network ownership context for {target}."
            ),
            result.data.clone(),
            ReconConfidence::High,
            evidence,
        )
    }

    fn ingest_tcp_service(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        result: &ToolResult,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        let Some(hostname) = string_field(&result.data, "hostname") else {
            return Ok(());
        };
        let Some(port) = result.data.get("port").and_then(Value::as_u64) else {
            return Ok(());
        };
        let host_kind = if hostname.parse::<IpAddr>().is_ok() {
            ReconAssetKind::IpAddress
        } else {
            ReconAssetKind::Subdomain
        };
        let host_id = self.ensure_asset(
            service,
            run_id,
            task,
            host_kind,
            hostname,
            ReconConfidence::High,
        )?;
        let open = result
            .data
            .get("open")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let identity = format!("https://{hostname}:{port}/#hexhunt-tcp-service");
        let service_id = self.ensure_asset(
            service,
            run_id,
            task,
            ReconAssetKind::NetworkService,
            &identity,
            if open {
                ReconConfidence::Confirmed
            } else {
                ReconConfidence::Medium
            },
        )?;
        self.enrich_asset(
            service,
            run_id,
            &service_id,
            [
                "source:tcp_probe".into(),
                format!("network:port:{port}"),
                if open {
                    "network:open".into()
                } else {
                    "network:closed_or_filtered".into()
                },
                "network:no_banner_requested".into(),
            ],
        )?;
        self.ensure_relation(
            service,
            run_id,
            &host_id,
            &service_id,
            ReconRelationKind::Serves,
            evidence,
        )?;
        self.append_observation(
            service,
            run_id,
            ReconObservationSource::TcpProbe,
            vec![host_id, service_id],
            format!(
                "Authorized TCP connect check found {hostname}:{port} {}.",
                if open {
                    "reachable"
                } else {
                    "closed or filtered"
                }
            ),
            result.data.clone(),
            if open {
                ReconConfidence::Confirmed
            } else {
                ReconConfidence::Medium
            },
            evidence,
        )
    }

    fn ingest_adaptive_browser(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        result: &ToolResult,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        let mut subjects = Vec::new();
        let mut observed_urls = BTreeSet::new();
        for view in result
            .data
            .get("identity_views")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(4)
        {
            if let Some(final_url) = view.get("final_url").and_then(Value::as_str) {
                let page_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Url,
                    final_url,
                    ReconConfidence::Confirmed,
                )?;
                self.enrich_asset(
                    service,
                    run_id,
                    &page_id,
                    ["source:adaptive_browser".into(), "browser:rendered".into()],
                )?;
                subjects.push(page_id.clone());
                observed_urls.insert(final_url.to_string());
                if let Some(dom) = view.get("dom") {
                    for link in dom
                        .get("links")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .take(500)
                    {
                        let link_id = self.ensure_asset(
                            service,
                            run_id,
                            task,
                            ReconAssetKind::Url,
                            link,
                            ReconConfidence::High,
                        )?;
                        self.enrich_asset(
                            service,
                            run_id,
                            &link_id,
                            ["source:adaptive_browser".into(), "browser:dom_link".into()],
                        )?;
                        self.ensure_relation(
                            service,
                            run_id,
                            &page_id,
                            &link_id,
                            ReconRelationKind::References,
                            evidence,
                        )?;
                        subjects.push(link_id);
                    }
                    for script in dom
                        .get("scripts")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .take(200)
                    {
                        let script_id = self.ensure_asset(
                            service,
                            run_id,
                            task,
                            ReconAssetKind::JavascriptBundle,
                            script,
                            ReconConfidence::High,
                        )?;
                        self.enrich_asset(
                            service,
                            run_id,
                            &script_id,
                            [
                                "source:adaptive_browser".into(),
                                "browser:loaded_script".into(),
                            ],
                        )?;
                        self.ensure_relation(
                            service,
                            run_id,
                            &page_id,
                            &script_id,
                            ReconRelationKind::References,
                            evidence,
                        )?;
                        subjects.push(script_id);
                    }
                }
            }
            for event in view
                .get("network_events")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(500)
            {
                let Some(url) = event.get("url").and_then(Value::as_str) else {
                    continue;
                };
                if !observed_urls.insert(url.to_string()) {
                    continue;
                }
                let resource_type = event
                    .get("resource_type")
                    .and_then(Value::as_str)
                    .unwrap_or("other");
                let kind = if matches!(resource_type, "xhr" | "fetch" | "websocket" | "eventsource")
                {
                    ReconAssetKind::Endpoint
                } else if resource_type == "script" {
                    ReconAssetKind::JavascriptBundle
                } else {
                    ReconAssetKind::Url
                };
                let asset_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    kind,
                    url,
                    ReconConfidence::Confirmed,
                )?;
                let mut tags = vec![
                    "source:adaptive_browser".into(),
                    format!("browser:resource:{resource_type}"),
                ];
                if let Some(status) = event.get("status_code").and_then(Value::as_u64) {
                    tags.push(format!("http:status:{status}"));
                }
                if event
                    .get("from_service_worker")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    tags.push("browser:service_worker".into());
                }
                self.enrich_asset(service, run_id, &asset_id, tags)?;
                subjects.push(asset_id);
            }
        }
        subjects.sort_by(|left, right| left.0.cmp(&right.0));
        subjects.dedup();
        self.append_observation(
            service,
            run_id,
            ReconObservationSource::AdaptiveBrowser,
            subjects,
            "Adaptive Browser Recon mapped dynamic DOM and scope-filtered network metadata.".into(),
            StructuredData::from([
                (
                    "requested_url".into(),
                    result
                        .data
                        .get("requested_url")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                (
                    "identity_views".into(),
                    result
                        .data
                        .get("identity_views")
                        .cloned()
                        .unwrap_or_else(|| Value::Array(vec![])),
                ),
                (
                    "identity_comparison".into(),
                    result
                        .data
                        .get("identity_comparison")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                ("secret_values_retained".into(), Value::Bool(false)),
            ]),
            ReconConfidence::Confirmed,
            evidence,
        )
    }

    fn ingest_external_intelligence(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        result: &ToolResult,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        let Some(target) = string_field(&result.data, "target") else {
            return Ok(());
        };
        let target_kind = if target.parse::<IpAddr>().is_ok() {
            ReconAssetKind::IpAddress
        } else {
            ReconAssetKind::RootDomain
        };
        let target_id = self.ensure_asset(
            service,
            run_id,
            task,
            target_kind,
            target,
            ReconConfidence::High,
        )?;
        self.enrich_asset(
            service,
            run_id,
            &target_id,
            ["source:external_intelligence".into()],
        )?;
        let mut subjects = vec![target_id.clone()];
        for source in result
            .data
            .get("sources")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|source| {
                source
                    .get("success")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
        {
            let provider = source
                .get("provider")
                .and_then(Value::as_str)
                .unwrap_or("external");
            let findings = source.get("findings").unwrap_or(&Value::Null);
            for address in findings
                .get("addresses")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .take(500)
            {
                if address.parse::<IpAddr>().is_err() {
                    continue;
                }
                let id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::IpAddress,
                    address,
                    ReconConfidence::Medium,
                )?;
                self.enrich_asset(service, run_id, &id, [format!("source:{provider}")])?;
                self.ensure_relation(
                    service,
                    run_id,
                    &target_id,
                    &id,
                    ReconRelationKind::ResolvesTo,
                    evidence,
                )?;
                subjects.push(id);
            }
            for hostname in findings
                .get("hostnames")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .take(500)
            {
                let id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Subdomain,
                    hostname,
                    ReconConfidence::Medium,
                )?;
                self.enrich_asset(service, run_id, &id, [format!("source:{provider}")])?;
                subjects.push(id);
            }
            for service_item in findings
                .get("services")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(200)
            {
                let Some(port) = service_item.get("port").and_then(Value::as_u64) else {
                    continue;
                };
                let identity = format!("https://{target}:{port}/#hexhunt-external-service");
                let id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::NetworkService,
                    &identity,
                    ReconConfidence::Medium,
                )?;
                self.enrich_asset(
                    service,
                    run_id,
                    &id,
                    [
                        format!("source:{provider}"),
                        format!("network:port:{port}"),
                        "external:unverified".into(),
                    ],
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &target_id,
                    &id,
                    ReconRelationKind::Serves,
                    evidence,
                )?;
                subjects.push(id);
            }
            for repository in findings
                .get("repositories")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(100)
            {
                let Some(name) = repository.get("repository").and_then(Value::as_str) else {
                    continue;
                };
                let identity = format!("https://github.com/{name}");
                let id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::ThirdPartyService,
                    &identity,
                    ReconConfidence::Medium,
                )?;
                self.enrich_asset(
                    service,
                    run_id,
                    &id,
                    ["source:github".into(), "github:metadata_only".into()],
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &target_id,
                    &id,
                    ReconRelationKind::References,
                    evidence,
                )?;
                subjects.push(id);
            }
            for record in findings
                .get("records")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(500)
            {
                for address in record
                    .get("addresses")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .take(100)
                {
                    if address.parse::<IpAddr>().is_err() {
                        continue;
                    }
                    let id = self.ensure_asset(
                        service,
                        run_id,
                        task,
                        ReconAssetKind::IpAddress,
                        address,
                        ReconConfidence::Low,
                    )?;
                    self.enrich_asset(
                        service,
                        run_id,
                        &id,
                        [format!("source:{provider}"), "external:historical".into()],
                    )?;
                    subjects.push(id);
                }
            }
        }
        subjects.sort_by(|left, right| left.0.cmp(&right.0));
        subjects.dedup();
        self.append_observation(
            service,
            run_id,
            ReconObservationSource::ExternalIntelligence,
            subjects,
            format!(
                "Configured passive external sources returned normalized metadata for {target}."
            ),
            result.data.clone(),
            ReconConfidence::Medium,
            evidence,
        )
    }

    fn ingest_content_discovery(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        result: &ToolResult,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        let Some(base_url) = string_field(&result.data, "base_url") else {
            return Ok(());
        };
        let Ok(base) = Url::parse(base_url) else {
            return Ok(());
        };
        let service_id = self.ensure_asset(
            service,
            run_id,
            task,
            ReconAssetKind::HttpService,
            &origin(&base),
            ReconConfidence::High,
        )?;
        let mut subjects = vec![service_id.clone()];
        for finding in result
            .data
            .get("findings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(100)
        {
            let Some(status) = finding.get("status_code").and_then(Value::as_u64) else {
                continue;
            };
            if matches!(status, 404 | 410) {
                continue;
            }
            let Some(url) = finding.get("url").and_then(Value::as_str) else {
                continue;
            };
            let url_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::Url,
                url,
                ReconConfidence::High,
            )?;
            self.enrich_asset(
                service,
                run_id,
                &url_id,
                [
                    "source:content_discovery".into(),
                    format!("http:status:{status}"),
                    "content:discovered".into(),
                ],
            )?;
            self.ensure_relation(
                service,
                run_id,
                &service_id,
                &url_id,
                ReconRelationKind::Exposes,
                evidence,
            )?;
            subjects.push(url_id);
        }
        self.append_observation(
            service,
            run_id,
            ReconObservationSource::ContentDiscovery,
            subjects,
            format!("Evidence-guided content discovery checked authorized paths at {base_url}."),
            result.data.clone(),
            ReconConfidence::High,
            evidence,
        )
    }

    fn ingest_http(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        result: &ToolResult,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        let Some(raw_url) = string_field(&result.data, "final_url")
            .or_else(|| string_field(&result.data, "requested_url"))
        else {
            return Ok(());
        };
        let Ok(url) = Url::parse(raw_url) else {
            return Ok(());
        };
        let Some(hostname) = url.host_str() else {
            return Ok(());
        };
        let snapshot = service.get_recon_snapshot(run_id)?;
        let host_kind = snapshot
            .assets
            .iter()
            .find(|asset| asset.canonical_value.eq_ignore_ascii_case(hostname))
            .map(|asset| asset.kind)
            .unwrap_or_else(|| {
                if hostname.parse::<IpAddr>().is_ok() {
                    ReconAssetKind::IpAddress
                } else {
                    ReconAssetKind::Subdomain
                }
            });
        let host_id = self.ensure_asset(
            service,
            run_id,
            task,
            host_kind,
            hostname,
            ReconConfidence::High,
        )?;
        let origin = origin(&url);
        let service_id = self.ensure_asset(
            service,
            run_id,
            task,
            ReconAssetKind::HttpService,
            &origin,
            ReconConfidence::High,
        )?;
        let url_id = self.ensure_asset(
            service,
            run_id,
            task,
            ReconAssetKind::Url,
            url.as_str(),
            ReconConfidence::High,
        )?;
        let status_code = result.data.get("status_code").and_then(Value::as_u64);
        let tls_present = result
            .data
            .get("tls")
            .and_then(Value::as_object)
            .and_then(|tls| tls.get("present"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        self.enrich_asset(
            service,
            run_id,
            &host_id,
            ["source:http".into(), "http:live".into()],
        )?;
        let mut service_tags = vec!["source:http".into(), "http:live".into()];
        if let Some(status) = status_code {
            service_tags.push(format!("http:status:{}", status));
        }
        if tls_present {
            service_tags.push("tls:present".into());
        }
        self.enrich_asset(service, run_id, &service_id, service_tags)?;
        let mut url_tags = vec!["source:http".into(), "http:observed".into()];
        if let Some(status) = status_code {
            url_tags.push(format!("http:status:{status}"));
        }
        if let Some(content_type) = result
            .data
            .get("response_headers")
            .and_then(Value::as_object)
            .and_then(|headers| headers.get("content-type"))
            .and_then(Value::as_str)
        {
            let normalized = content_type.to_ascii_lowercase();
            if normalized.contains("text/html") {
                url_tags.push("http:content:html".into());
            } else if normalized.contains("json") {
                url_tags.push("http:content:json".into());
            } else if normalized.contains("javascript") {
                url_tags.push("http:content:javascript".into());
            }
        }
        self.enrich_asset(service, run_id, &url_id, url_tags)?;
        if result.tool_name == "validate_url_metadata" {
            let validation_tag = match status_code {
                Some(404 | 410) => "validation:not_found",
                Some(405 | 501) => "validation:method_unsupported",
                Some(_) => "validation:responded",
                None => "validation:inconclusive",
            };
            self.enrich_asset(
                service,
                run_id,
                &url_id,
                ["source:active_validation".into(), validation_tag.into()],
            )?;
        }
        self.ensure_relation(
            service,
            run_id,
            &host_id,
            &service_id,
            ReconRelationKind::Serves,
            evidence,
        )?;
        self.ensure_relation(
            service,
            run_id,
            &service_id,
            &url_id,
            ReconRelationKind::Exposes,
            evidence,
        )?;
        let mut discovered_subjects = Vec::new();

        if result.tool_name == "analyze_web_page" {
            let mut page_tags = vec!["source:web_page".into(), "web:analyzed".into()];
            for signal in string_array(&result.data, "page_signals") {
                page_tags.push(format!("web:signal:{signal}"));
            }
            self.enrich_asset(service, run_id, &url_id, page_tags)?;
            if let Some(title) = string_field(&result.data, "page_title") {
                let mut page = service
                    .get_recon_snapshot(run_id)?
                    .assets
                    .into_iter()
                    .find(|asset| asset.id == url_id)
                    .ok_or_else(|| {
                        RunServiceError::new(
                            RunServiceErrorCode::ReconItemNotFound,
                            "Analyzed web page asset was not found.",
                        )
                    })?;
                page.display_name = Some(title.chars().take(200).collect());
                page.last_seen_at_ms = self.clock.now_ms();
                service.update_recon_asset(run_id, page)?;
            }
            for link in string_array(&result.data, "links") {
                let link_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Url,
                    link,
                    ReconConfidence::Medium,
                )?;
                self.enrich_asset(
                    service,
                    run_id,
                    &link_id,
                    ["source:web_page".into(), "web:discovered_link".into()],
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &url_id,
                    &link_id,
                    ReconRelationKind::References,
                    evidence,
                )?;
                discovered_subjects.push(link_id);
            }
            for (index, form) in result
                .data
                .get("forms")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(100)
                .enumerate()
            {
                let Some(action) = form.get("action").and_then(Value::as_str) else {
                    continue;
                };
                let method = form.get("method").and_then(Value::as_str).unwrap_or("GET");
                let form_identity = format!(
                    "{}#hexhunt-form-{}-{}",
                    action.split('#').next().unwrap_or(action),
                    method.to_ascii_lowercase(),
                    index + 1
                );
                let form_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::WebForm,
                    &form_identity,
                    ReconConfidence::High,
                )?;
                let mut form_tags = vec![
                    "source:web_page".into(),
                    format!("form:method:{}", method.to_ascii_lowercase()),
                ];
                if form
                    .get("has_password_input")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    form_tags.push("form:password".into());
                }
                if form
                    .get("has_file_upload")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    form_tags.push("form:file_upload".into());
                }
                self.enrich_asset(service, run_id, &form_id, form_tags)?;
                self.ensure_relation(
                    service,
                    run_id,
                    &url_id,
                    &form_id,
                    ReconRelationKind::Exposes,
                    evidence,
                )?;
                discovered_subjects.push(form_id.clone());
                for input_name in form
                    .get("input_names")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .take(200)
                {
                    let parameter_id = self.ensure_parameter(
                        service,
                        run_id,
                        task,
                        &form_id,
                        action,
                        &format!("form-{}", method.to_ascii_lowercase()),
                        input_name,
                        "form",
                        "web_form",
                        false,
                        evidence,
                    )?;
                    discovered_subjects.push(parameter_id);
                }

                let action_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Url,
                    action,
                    ReconConfidence::Medium,
                )?;
                self.enrich_asset(
                    service,
                    run_id,
                    &action_id,
                    ["source:web_form".into(), "web:discovered_link".into()],
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &form_id,
                    &action_id,
                    ReconRelationKind::References,
                    evidence,
                )?;
                discovered_subjects.push(action_id.clone());

                if form
                    .get("has_password_input")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    let auth_id = self.ensure_asset(
                        service,
                        run_id,
                        task,
                        ReconAssetKind::AuthenticationSurface,
                        action,
                        ReconConfidence::High,
                    )?;
                    self.enrich_asset(
                        service,
                        run_id,
                        &auth_id,
                        ["source:web_page".into(), "auth:password_form".into()],
                    )?;
                    self.ensure_relation(
                        service,
                        run_id,
                        &form_id,
                        &auth_id,
                        ReconRelationKind::AuthenticatesWith,
                        evidence,
                    )?;
                    discovered_subjects.push(auth_id);
                }
            }
        }

        for provider in result
            .data
            .get("service_profile")
            .and_then(Value::as_object)
            .and_then(|profile| profile.get("infrastructure_hints"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .take(20)
        {
            let provider_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::ThirdPartyService,
                provider,
                ReconConfidence::High,
            )?;
            self.enrich_asset(
                service,
                run_id,
                &provider_id,
                [
                    "source:http_headers".into(),
                    "infrastructure:provider".into(),
                ],
            )?;
            self.ensure_relation(
                service,
                run_id,
                &service_id,
                &provider_id,
                ReconRelationKind::HostedOn,
                evidence,
            )?;
            discovered_subjects.push(provider_id);
        }

        for script_url in script_urls(result, &url) {
            let script_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::JavascriptBundle,
                &script_url,
                ReconConfidence::High,
            )?;
            self.ensure_relation(
                service,
                run_id,
                &service_id,
                &script_id,
                ReconRelationKind::References,
                evidence,
            )?;
            discovered_subjects.push(script_id);
        }

        if result.tool_name == "analyze_javascript" {
            let script_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::JavascriptBundle,
                url.as_str(),
                ReconConfidence::High,
            )?;
            self.ensure_relation(
                service,
                run_id,
                &service_id,
                &script_id,
                ReconRelationKind::References,
                evidence,
            )?;
            discovered_subjects.push(script_id.clone());
            let mut script_tags = vec!["source:javascript".into()];
            if result
                .data
                .get("secret_indicator_count")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                > 0
            {
                script_tags.push("javascript:secret_indicator".into());
            }
            if result
                .data
                .get("graphql_operations")
                .and_then(Value::as_array)
                .is_some_and(|operations| !operations.is_empty())
            {
                script_tags.push("javascript:graphql_operations".into());
            }
            if result
                .data
                .get("websocket_endpoints")
                .and_then(Value::as_array)
                .is_some_and(|endpoints| !endpoints.is_empty())
            {
                script_tags.push("javascript:websocket".into());
            }
            script_tags.extend(
                result
                    .data
                    .get("client_security_signals")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|signal| signal.get("kind").and_then(Value::as_str))
                    .map(|kind| format!("javascript:security_signal:{kind}")),
            );
            self.enrich_asset(service, run_id, &script_id, script_tags)?;
            let mut profiled_endpoints = BTreeSet::new();
            for profile in result
                .data
                .get("endpoint_profiles")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(500)
            {
                let Some(endpoint) = profile
                    .get("url")
                    .and_then(Value::as_str)
                    .and_then(|value| url.join(value).ok())
                    .filter(|value| matches!(value.scheme(), "http" | "https"))
                    .map(|value| value.to_string())
                else {
                    continue;
                };
                profiled_endpoints.insert(endpoint.clone());
                let endpoint_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Endpoint,
                    &endpoint,
                    ReconConfidence::High,
                )?;
                let mut tags = vec!["source:javascript".into()];
                tags.extend(
                    profile
                        .get("methods")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(|method| format!("http:method:{}", method.to_ascii_lowercase())),
                );
                self.enrich_asset(service, run_id, &endpoint_id, tags)?;
                self.ensure_relation(
                    service,
                    run_id,
                    &script_id,
                    &endpoint_id,
                    ReconRelationKind::References,
                    evidence,
                )?;
                discovered_subjects.push(endpoint_id.clone());
                for parameter_name in profile
                    .get("parameter_names")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .take(200)
                {
                    let parameter_id = self.ensure_parameter(
                        service,
                        run_id,
                        task,
                        &endpoint_id,
                        &endpoint,
                        "javascript",
                        parameter_name,
                        "query",
                        "javascript",
                        false,
                        evidence,
                    )?;
                    discovered_subjects.push(parameter_id);
                }
            }
            for endpoint in resolved_values(result, "endpoints", &url)
                .into_iter()
                .chain(resolved_values(result, "absolute_urls", &url))
            {
                if profiled_endpoints.contains(&endpoint) {
                    continue;
                }
                let endpoint_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Endpoint,
                    &endpoint,
                    ReconConfidence::Medium,
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &script_id,
                    &endpoint_id,
                    ReconRelationKind::References,
                    evidence,
                )?;
                discovered_subjects.push(endpoint_id);
            }
            for source_map in resolved_values(result, "source_map_urls", &url) {
                let source_map_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Url,
                    &source_map,
                    ReconConfidence::Medium,
                )?;
                self.enrich_asset(
                    service,
                    run_id,
                    &source_map_id,
                    ["source:javascript".into(), "web:source_map".into()],
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &script_id,
                    &source_map_id,
                    ReconRelationKind::References,
                    evidence,
                )?;
                discovered_subjects.push(source_map_id);
            }
            let declared_source_maps = resolved_values(result, "source_map_urls", &url)
                .into_iter()
                .collect::<BTreeSet<_>>();
            for source_map in resolved_values(result, "source_map_candidates", &url) {
                if declared_source_maps.contains(&source_map) {
                    continue;
                }
                let source_map_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Url,
                    &source_map,
                    ReconConfidence::Low,
                )?;
                self.enrich_asset(
                    service,
                    run_id,
                    &source_map_id,
                    [
                        "source:javascript".into(),
                        "web:source_map_candidate".into(),
                    ],
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &script_id,
                    &source_map_id,
                    ReconRelationKind::References,
                    evidence,
                )?;
                discovered_subjects.push(source_map_id);
            }
            for javascript_import in resolved_values(result, "javascript_imports", &url) {
                let import_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::JavascriptBundle,
                    &javascript_import,
                    ReconConfidence::Medium,
                )?;
                self.enrich_asset(
                    service,
                    run_id,
                    &import_id,
                    ["source:javascript_import".into()],
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &script_id,
                    &import_id,
                    ReconRelationKind::References,
                    evidence,
                )?;
                discovered_subjects.push(import_id);
            }
            for api in resolved_values(result, "api_candidates", &url) {
                let api_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Api,
                    &api,
                    ReconConfidence::Medium,
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &script_id,
                    &api_id,
                    ReconRelationKind::References,
                    evidence,
                )?;
                discovered_subjects.push(api_id);
            }
            for api in resolved_values(result, "api_base_urls", &url) {
                let api_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Api,
                    &api,
                    ReconConfidence::Medium,
                )?;
                self.enrich_asset(
                    service,
                    run_id,
                    &api_id,
                    ["source:javascript".into(), "api:client_base_url".into()],
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &script_id,
                    &api_id,
                    ReconRelationKind::References,
                    evidence,
                )?;
                discovered_subjects.push(api_id);
            }
            for authentication_surface in resolved_values(result, "auth_candidates", &url) {
                let authentication_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::AuthenticationSurface,
                    &authentication_surface,
                    ReconConfidence::Medium,
                )?;
                self.enrich_asset(
                    service,
                    run_id,
                    &authentication_id,
                    ["source:javascript".into()],
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &script_id,
                    &authentication_id,
                    ReconRelationKind::References,
                    evidence,
                )?;
                discovered_subjects.push(authentication_id);
            }
        }

        if result.tool_name == "describe_api" {
            let api_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::Api,
                url.as_str(),
                ReconConfidence::High,
            )?;
            if let Some(format) = string_field(&result.data, "api_format") {
                self.enrich_asset(
                    service,
                    run_id,
                    &api_id,
                    [
                        "source:api_description".into(),
                        format!("api:format:{format}"),
                    ],
                )?;
            }
            discovered_subjects.push(api_id.clone());
            let mut profiled_paths = BTreeSet::new();
            for operation in result
                .data
                .get("operation_profiles")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(500)
            {
                let Some(path) = operation.get("path").and_then(Value::as_str) else {
                    continue;
                };
                let Some(endpoint) = url
                    .join(path)
                    .ok()
                    .filter(|value| matches!(value.scheme(), "http" | "https"))
                    .map(|value| value.to_string())
                else {
                    continue;
                };
                profiled_paths.insert(endpoint.clone());
                let method = operation
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("UNKNOWN");
                let operation_identity = format!(
                    "{}#hexhunt-method-{}",
                    endpoint.split('#').next().unwrap_or(&endpoint),
                    method.to_ascii_lowercase()
                );
                let endpoint_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Endpoint,
                    &operation_identity,
                    ReconConfidence::High,
                )?;
                let mut tags = vec!["source:api_description".into()];
                tags.push(format!("http:method:{}", method.to_ascii_lowercase()));
                if operation
                    .get("authentication_required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    tags.push("api:authentication_required".into());
                } else {
                    tags.push("api:public_operation".into());
                }
                if operation
                    .get("deprecated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    tags.push("api:deprecated".into());
                }
                self.enrich_asset(service, run_id, &endpoint_id, tags)?;
                self.ensure_relation(
                    service,
                    run_id,
                    &api_id,
                    &endpoint_id,
                    ReconRelationKind::Exposes,
                    evidence,
                )?;
                discovered_subjects.push(endpoint_id.clone());
                for parameter in operation
                    .get("parameters")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .take(200)
                {
                    let Some(name) = parameter.get("name").and_then(Value::as_str) else {
                        continue;
                    };
                    let location = parameter
                        .get("location")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let parameter_id = self.ensure_parameter(
                        service,
                        run_id,
                        task,
                        &endpoint_id,
                        &endpoint,
                        &method.to_ascii_lowercase(),
                        name,
                        location,
                        "api_description",
                        parameter
                            .get("required")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        evidence,
                    )?;
                    discovered_subjects.push(parameter_id);
                }
            }
            for path in resolved_values(result, "api_paths", &url) {
                if profiled_paths.contains(&path) {
                    continue;
                }
                let endpoint_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Endpoint,
                    &path,
                    ReconConfidence::High,
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &api_id,
                    &endpoint_id,
                    ReconRelationKind::Exposes,
                    evidence,
                )?;
                discovered_subjects.push(endpoint_id);
            }
            for server_url in resolved_values(result, "server_urls", &url) {
                let server_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::HttpService,
                    &server_url,
                    ReconConfidence::High,
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &api_id,
                    &server_id,
                    ReconRelationKind::HostedOn,
                    evidence,
                )?;
                discovered_subjects.push(server_id);
            }
            for scheme in result
                .data
                .get("security_schemes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(100)
            {
                let Some(name) = scheme.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let identity = format!("{}#hexhunt-auth-scheme-{}", url, name);
                let auth_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::AuthenticationSurface,
                    &identity,
                    ReconConfidence::High,
                )?;
                let mut tags = vec!["source:api_description".into()];
                if let Some(kind) = scheme.get("kind").and_then(Value::as_str) {
                    tags.push(format!("auth:kind:{kind}"));
                }
                if let Some(auth_scheme) = scheme.get("scheme").and_then(Value::as_str) {
                    tags.push(format!("auth:scheme:{auth_scheme}"));
                }
                self.enrich_asset(service, run_id, &auth_id, tags)?;
                self.ensure_relation(
                    service,
                    run_id,
                    &api_id,
                    &auth_id,
                    ReconRelationKind::AuthenticatesWith,
                    evidence,
                )?;
                discovered_subjects.push(auth_id);
            }
            for schema_name in string_array(&result.data, "schema_names") {
                let identity = format!("{}#hexhunt-schema-{}", url, parameter_slug(schema_name));
                let model_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::DataModel,
                    &identity,
                    ReconConfidence::High,
                )?;
                let mut model = service
                    .get_recon_snapshot(run_id)?
                    .assets
                    .into_iter()
                    .find(|asset| asset.id == model_id)
                    .ok_or_else(|| {
                        RunServiceError::new(
                            RunServiceErrorCode::ReconItemNotFound,
                            "API data-model asset was not found after creation.",
                        )
                    })?;
                model.display_name = Some(schema_name.chars().take(100).collect());
                service.update_recon_asset(run_id, model)?;
                self.enrich_asset(
                    service,
                    run_id,
                    &model_id,
                    ["source:api_description".into()],
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &api_id,
                    &model_id,
                    ReconRelationKind::Describes,
                    evidence,
                )?;
                discovered_subjects.push(model_id);
            }
        }

        if let Some(location) =
            response_header(result, "location").and_then(|location| url.join(location).ok())
        {
            let redirect_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::Url,
                location.as_str(),
                ReconConfidence::High,
            )?;
            self.ensure_relation(
                service,
                run_id,
                &url_id,
                &redirect_id,
                ReconRelationKind::RedirectsTo,
                evidence,
            )?;
        }

        for technology in detected_technologies(result) {
            let technology_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::Technology,
                &technology,
                ReconConfidence::Medium,
            )?;
            self.ensure_relation(
                service,
                run_id,
                &service_id,
                &technology_id,
                ReconRelationKind::UsesTechnology,
                evidence,
            )?;
        }

        let source = match result.tool_name.as_str() {
            "fetch_robots_txt" => ReconObservationSource::RobotsTxt,
            "fetch_sitemap" => ReconObservationSource::Sitemap,
            "analyze_web_page" => ReconObservationSource::WebPageAnalysis,
            "analyze_javascript" => ReconObservationSource::JavascriptAnalysis,
            "describe_api" => ReconObservationSource::ApiDescription,
            "validate_url_metadata" => ReconObservationSource::ActiveValidation,
            _ => ReconObservationSource::HttpProbe,
        };
        let mut subjects = vec![host_id, service_id.clone(), url_id.clone()];
        subjects.append(&mut discovered_subjects);
        let declared_urls = declared_urls(result, &origin);
        for declared_url in &declared_urls {
            let declared_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::Url,
                declared_url,
                ReconConfidence::Medium,
            )?;
            self.ensure_relation(
                service,
                run_id,
                &service_id,
                &declared_id,
                ReconRelationKind::Exposes,
                evidence,
            )?;
            subjects.push(declared_id);
        }
        subjects.sort_by(|left, right| left.0.cmp(&right.0));
        subjects.dedup();
        self.append_observation(
            service,
            run_id,
            source,
            subjects,
            format!(
                "{} observed HTTP status {} at {}.",
                result.tool_name,
                result
                    .data
                    .get("status_code")
                    .and_then(Value::as_u64)
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                url
            ),
            StructuredData::from([
                ("url".into(), Value::String(url.to_string())),
                (
                    "status_code".into(),
                    result
                        .data
                        .get("status_code")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                (
                    "response_headers".into(),
                    result
                        .data
                        .get("response_headers")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                (
                    "redirected".into(),
                    result
                        .data
                        .get("redirected")
                        .cloned()
                        .unwrap_or(Value::Bool(false)),
                ),
                (
                    "declared_urls".into(),
                    Value::Array(declared_urls.into_iter().map(Value::String).collect()),
                ),
                (
                    "tls".into(),
                    result.data.get("tls").cloned().unwrap_or(Value::Null),
                ),
                (
                    "service_profile".into(),
                    result
                        .data
                        .get("service_profile")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                ("analysis".into(), sanitized_analysis(result)),
            ]),
            ReconConfidence::High,
            evidence,
        )?;

        if result
            .data
            .get("tls")
            .and_then(Value::as_object)
            .and_then(|tls| tls.get("present"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            self.append_observation(
                service,
                run_id,
                ReconObservationSource::TlsInspection,
                vec![service_id, url_id],
                format!("A trusted TLS connection exposed peer certificate metadata at {url}."),
                StructuredData::from([(
                    "tls".into(),
                    result.data.get("tls").cloned().unwrap_or(Value::Null),
                )]),
                ReconConfidence::High,
                evidence,
            )?;
        }
        Ok(())
    }

    fn ensure_asset(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        kind: ReconAssetKind,
        canonical_value: &str,
        confidence: ReconConfidence,
    ) -> Result<ReconAssetId, RunServiceError> {
        if let Some(mut asset) =
            service
                .get_recon_snapshot(run_id)?
                .assets
                .into_iter()
                .find(|asset| {
                    asset.kind == kind
                        && asset.canonical_value.eq_ignore_ascii_case(canonical_value)
                })
        {
            if confidence_rank(confidence) > confidence_rank(asset.confidence) {
                asset.confidence = confidence;
            }
            asset.last_seen_at_ms = self.clock.now_ms();
            let id = asset.id.clone();
            service.update_recon_asset(run_id, asset)?;
            return Ok(id);
        }
        let (scope, scope_reason) = classify_scope(task, kind, canonical_value);
        let asset = ReconAsset {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconAssetId(Uuid::new_v4().to_string()),
            kind,
            canonical_value: canonical_value.to_string(),
            display_name: None,
            scope,
            scope_reason,
            confidence,
            first_seen_at_ms: self.clock.now_ms(),
            last_seen_at_ms: self.clock.now_ms(),
            tags: vec![],
        };
        service
            .append_recon_asset(run_id, asset)
            .map(|asset| asset.id)
    }

    fn enrich_asset(
        &self,
        service: &RunService,
        run_id: &RunId,
        asset_id: &ReconAssetId,
        tags: impl IntoIterator<Item = String>,
    ) -> Result<(), RunServiceError> {
        let mut asset = service
            .get_recon_snapshot(run_id)?
            .assets
            .into_iter()
            .find(|asset| asset.id == *asset_id)
            .ok_or_else(|| {
                RunServiceError::new(
                    RunServiceErrorCode::ReconItemNotFound,
                    format!("Recon asset '{}' was not found for enrichment.", asset_id.0),
                )
            })?;
        for tag in tags {
            if !asset.tags.iter().any(|stored| stored == &tag) {
                asset.tags.push(tag);
            }
        }
        asset.tags.sort();
        let independent_sources = asset
            .tags
            .iter()
            .filter(|tag| tag.starts_with("source:"))
            .collect::<BTreeSet<_>>()
            .len();
        let directly_verified = asset.tags.iter().any(|tag| tag == "dns:resolved")
            && !asset.tags.iter().any(|tag| tag == "dns:wildcard_match")
            || asset.tags.iter().any(|tag| tag == "http:live");
        if directly_verified {
            asset.confidence = ReconConfidence::Confirmed;
        } else if independent_sources >= 2
            && confidence_rank(asset.confidence) < confidence_rank(ReconConfidence::High)
        {
            asset.confidence = ReconConfidence::High;
        }
        asset.last_seen_at_ms = self.clock.now_ms();
        service.update_recon_asset(run_id, asset)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_parameter(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        parent_asset_id: &ReconAssetId,
        parent_url: &str,
        context: &str,
        name: &str,
        location: &str,
        source: &str,
        required: bool,
        evidence: Option<&Evidence>,
    ) -> Result<ReconAssetId, RunServiceError> {
        let name = name.trim();
        if name.is_empty() {
            return Ok(parent_asset_id.clone());
        }
        let slug = parameter_slug(name);
        let base = parent_url.split("#hexhunt-").next().unwrap_or(parent_url);
        let identity = format!(
            "{base}#hexhunt-parameter-{}-{}-{}",
            parameter_slug(context),
            parameter_slug(location),
            slug
        );
        let parameter_id = self.ensure_asset(
            service,
            run_id,
            task,
            ReconAssetKind::Parameter,
            &identity,
            ReconConfidence::High,
        )?;
        let mut parameter = service
            .get_recon_snapshot(run_id)?
            .assets
            .into_iter()
            .find(|asset| asset.id == parameter_id)
            .ok_or_else(|| {
                RunServiceError::new(
                    RunServiceErrorCode::ReconItemNotFound,
                    "Parameter asset was not found after creation.",
                )
            })?;
        parameter.display_name = Some(name.chars().take(100).collect());
        service.update_recon_asset(run_id, parameter)?;
        let mut tags = vec![
            format!("source:{source}"),
            format!("parameter:location:{}", parameter_slug(location)),
        ];
        if required {
            tags.push("parameter:required".into());
        }
        if let Some(sensitivity) = parameter_sensitivity(name) {
            tags.push(format!("parameter:sensitivity:{sensitivity}"));
        }
        self.enrich_asset(service, run_id, &parameter_id, tags)?;
        self.ensure_relation(
            service,
            run_id,
            parent_asset_id,
            &parameter_id,
            ReconRelationKind::AcceptsInput,
            evidence,
        )?;
        Ok(parameter_id)
    }

    fn ingest_visual(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        result: &ToolResult,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        let Some(url) = string_field(&result.data, "final_url")
            .or_else(|| string_field(&result.data, "requested_url"))
        else {
            return Ok(());
        };
        let Some(observation) = result
            .data
            .get("visual_observation")
            .and_then(Value::as_object)
        else {
            return Ok(());
        };
        let url_id = self.ensure_asset(
            service,
            run_id,
            task,
            ReconAssetKind::Url,
            url,
            ReconConfidence::High,
        )?;
        let mut subjects = vec![url_id.clone()];
        let authentication_surface = observation
            .get("authentication_surface")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if authentication_surface {
            let auth_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::AuthenticationSurface,
                url,
                ReconConfidence::Medium,
            )?;
            self.ensure_relation(
                service,
                run_id,
                &url_id,
                &auth_id,
                ReconRelationKind::Exposes,
                evidence,
            )?;
            subjects.push(auth_id);
        }
        if let Some(technology_hints) = observation
            .get("technology_hints")
            .and_then(Value::as_array)
        {
            for technology in technology_hints.iter().filter_map(Value::as_str).take(25) {
                let technology_id = self.ensure_asset(
                    service,
                    run_id,
                    task,
                    ReconAssetKind::Technology,
                    technology,
                    ReconConfidence::Low,
                )?;
                self.ensure_relation(
                    service,
                    run_id,
                    &url_id,
                    &technology_id,
                    ReconRelationKind::UsesTechnology,
                    evidence,
                )?;
                subjects.push(technology_id);
            }
        }
        let page_kind = observation
            .get("page_kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let summary = observation
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or("No visual summary was returned.");
        let confidence = match observation.get("confidence").and_then(Value::as_str) {
            Some("high" | "medium") => ReconConfidence::Medium,
            _ => ReconConfidence::Low,
        };
        let mut facts = StructuredData::new();
        facts.insert("url".into(), Value::String(url.into()));
        facts.insert(
            "visual_observation".into(),
            Value::Object(observation.clone()),
        );
        for key in [
            "screenshot_sha256",
            "screenshot_bytes",
            "screenshot_retained",
            "viewport_width",
            "viewport_height",
            "blocked_out_of_scope_requests",
            "visual_model",
            "api_response_model",
            "actual_provider",
            "input_tokens",
            "output_tokens",
            "usage_reported",
        ] {
            if let Some(value) = result.data.get(key) {
                facts.insert(key.into(), value.clone());
            }
        }
        subjects.sort_by(|left, right| left.0.cmp(&right.0));
        subjects.dedup();
        self.append_observation(
            service,
            run_id,
            ReconObservationSource::VisualAnalysis,
            subjects,
            format!("Visual Recon classified {url} as {page_kind}: {summary}"),
            facts,
            confidence,
            evidence,
        )
    }

    fn ingest_historical(
        &self,
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        result: &ToolResult,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        let Some(domain) = string_field(&result.data, "domain") else {
            return Ok(());
        };
        let records = result
            .data
            .get("historical_urls")
            .cloned()
            .and_then(|value| serde_json::from_value::<Vec<HistoricalUrlSummary>>(value).ok())
            .unwrap_or_default();
        let before = service.get_recon_snapshot(run_id)?;
        let previously_known = records
            .iter()
            .filter(|record| {
                before.assets.iter().any(|asset| {
                    asset.kind != ReconAssetKind::HistoricalUrl
                        && asset.canonical_value.eq_ignore_ascii_case(&record.url)
                })
            })
            .count();
        let root_id = self.ensure_asset(
            service,
            run_id,
            task,
            ReconAssetKind::RootDomain,
            domain,
            ReconConfidence::Confirmed,
        )?;
        self.enrich_asset(service, run_id, &root_id, ["source:web_archive".into()])?;
        let mut subjects = vec![root_id.clone()];
        for hostname in string_array(&result.data, "historical_subdomains") {
            let hostname_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::Subdomain,
                hostname,
                ReconConfidence::Low,
            )?;
            self.enrich_asset(service, run_id, &hostname_id, ["source:web_archive".into()])?;
            self.ensure_relation(
                service,
                run_id,
                &root_id,
                &hostname_id,
                ReconRelationKind::Owns,
                evidence,
            )?;
            subjects.push(hostname_id);
        }
        for record in &records {
            let historical_id = self.ensure_asset(
                service,
                run_id,
                task,
                ReconAssetKind::HistoricalUrl,
                &record.url,
                ReconConfidence::Low,
            )?;
            self.ensure_relation(
                service,
                run_id,
                &root_id,
                &historical_id,
                ReconRelationKind::References,
                evidence,
            )?;
            let current_kind = match record.kind {
                HistoricalUrlKind::Javascript => ReconAssetKind::JavascriptBundle,
                HistoricalUrlKind::Endpoint => ReconAssetKind::Endpoint,
                HistoricalUrlKind::ApiDescription => ReconAssetKind::Api,
                HistoricalUrlKind::Page | HistoricalUrlKind::Other => ReconAssetKind::Url,
            };
            let current_id = self.ensure_asset(
                service,
                run_id,
                task,
                current_kind,
                &record.url,
                ReconConfidence::Low,
            )?;
            self.ensure_relation(
                service,
                run_id,
                &historical_id,
                &current_id,
                ReconRelationKind::HistoricalVersionOf,
                evidence,
            )?;
            subjects.push(historical_id.clone());
            subjects.push(current_id);

            if let Ok(url) = Url::parse(&record.url) {
                if let Some(hostname) = url.host_str() {
                    if !hostname.eq_ignore_ascii_case(domain) {
                        let hostname_id = self.ensure_asset(
                            service,
                            run_id,
                            task,
                            ReconAssetKind::Subdomain,
                            hostname,
                            ReconConfidence::Low,
                        )?;
                        self.enrich_asset(
                            service,
                            run_id,
                            &hostname_id,
                            ["source:web_archive".into()],
                        )?;
                        self.ensure_relation(
                            service,
                            run_id,
                            &root_id,
                            &hostname_id,
                            ReconRelationKind::Owns,
                            evidence,
                        )?;
                        self.ensure_relation(
                            service,
                            run_id,
                            &hostname_id,
                            &historical_id,
                            ReconRelationKind::References,
                            evidence,
                        )?;
                        subjects.push(hostname_id);
                    }
                }
            }
        }
        subjects.sort_by(|left, right| left.0.cmp(&right.0));
        subjects.dedup();
        let new_clues = records.len().saturating_sub(previously_known);
        let mut facts = StructuredData::from([
            ("domain".into(), Value::String(domain.into())),
            (
                "historical_url_count".into(),
                Value::from(records.len() as u64),
            ),
            (
                "previously_known_count".into(),
                Value::from(previously_known as u64),
            ),
            ("new_clue_count".into(), Value::from(new_clues as u64)),
        ]);
        for key in [
            "provider_results",
            "historical_javascript_count",
            "historical_endpoint_count",
            "historical_subdomains",
            "parameter_names",
            "raw_archive_records_retained",
        ] {
            if let Some(value) = result.data.get(key) {
                facts.insert(key.into(), value.clone());
            }
        }
        self.append_observation(
            service,
            run_id,
            ReconObservationSource::WebArchive,
            subjects,
            format!(
                "Passive archive indexes returned {} normalized historical URLs for {domain}; {new_clues} were absent from the pre-existing graph.",
                records.len()
            ),
            facts,
            ReconConfidence::Low,
            evidence,
        )
    }

    fn ensure_relation(
        &self,
        service: &RunService,
        run_id: &RunId,
        from_asset_id: &ReconAssetId,
        to_asset_id: &ReconAssetId,
        kind: ReconRelationKind,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        if service
            .get_recon_snapshot(run_id)?
            .relations
            .iter()
            .any(|relation| {
                relation.from_asset_id == *from_asset_id
                    && relation.to_asset_id == *to_asset_id
                    && relation.kind == kind
            })
        {
            return Ok(());
        }
        service.append_recon_relation(
            run_id,
            ReconAssetRelation {
                schema_version: CORE_SCHEMA_VERSION,
                id: ReconRelationId(Uuid::new_v4().to_string()),
                from_asset_id: from_asset_id.clone(),
                to_asset_id: to_asset_id.clone(),
                kind,
                confidence: ReconConfidence::High,
                evidence_ids: evidence
                    .map(|item| vec![item.id.clone()])
                    .unwrap_or_default(),
                observed_at_ms: self.clock.now_ms(),
            },
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn append_observation(
        &self,
        service: &RunService,
        run_id: &RunId,
        source: ReconObservationSource,
        subject_asset_ids: Vec<ReconAssetId>,
        summary: String,
        facts: StructuredData,
        confidence: ReconConfidence,
        evidence: Option<&Evidence>,
    ) -> Result<(), RunServiceError> {
        service.append_recon_observation(
            run_id,
            ReconObservation {
                schema_version: CORE_SCHEMA_VERSION,
                id: ReconObservationId(Uuid::new_v4().to_string()),
                run_id: run_id.clone(),
                source,
                subject_asset_ids,
                summary,
                facts,
                confidence,
                evidence_ids: evidence
                    .map(|item| vec![item.id.clone()])
                    .unwrap_or_default(),
                observed_at_ms: self.clock.now_ms(),
            },
        )?;
        Ok(())
    }
}

fn classify_scope(
    task: &Task,
    kind: ReconAssetKind,
    canonical_value: &str,
) -> (ReconScopeClassification, String) {
    if matches!(
        kind,
        ReconAssetKind::Technology | ReconAssetKind::ThirdPartyService
    ) {
        return (
            ReconScopeClassification::ThirdParty,
            "Observed technology metadata is contextual and is not a test target.".into(),
        );
    }
    let target = match kind {
        ReconAssetKind::HttpService
        | ReconAssetKind::NetworkService
        | ReconAssetKind::Url
        | ReconAssetKind::HistoricalUrl
        | ReconAssetKind::Endpoint
        | ReconAssetKind::JavascriptBundle
        | ReconAssetKind::Api
        | ReconAssetKind::AuthenticationSurface
        | ReconAssetKind::WebForm
        | ReconAssetKind::Parameter
        | ReconAssetKind::DataModel
            if Url::parse(canonical_value).is_ok() =>
        {
            canonical_value.to_string()
        }
        ReconAssetKind::IpAddress => format!("https://{canonical_value}"),
        _ => format!("https://{canonical_value}"),
    };
    let mut project = task.scope.clone();
    if !project.allowed_ports.contains(&443) {
        project.allowed_ports.push(443);
    }
    let decision = validate(&project, &target);
    if decision.allowed {
        (
            ReconScopeClassification::InScope,
            "The asset matches the authorized Run scope.".into(),
        )
    } else if matches!(decision.code, "excluded" | "domain") {
        (
            ReconScopeClassification::OutOfScope,
            format!("Scope Guard classified the asset as {}.", decision.code),
        )
    } else {
        (
            ReconScopeClassification::RequiresReview,
            format!("Scope classification requires review: {}.", decision.code),
        )
    }
}

fn origin(url: &Url) -> String {
    let default_port = match url.scheme() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    };
    match (url.host_str(), url.port(), default_port) {
        (Some(host), Some(port), Some(default)) if port != default => {
            format!("{}://{}:{}", url.scheme(), host, port)
        }
        (Some(host), _, _) => format!("{}://{}", url.scheme(), host),
        _ => url.as_str().to_string(),
    }
}

fn confidence_rank(confidence: ReconConfidence) -> u8 {
    match confidence {
        ReconConfidence::Low => 1,
        ReconConfidence::Medium => 2,
        ReconConfidence::High => 3,
        ReconConfidence::Confirmed => 4,
    }
}

fn parameter_slug(value: &str) -> String {
    let mut slug = value
        .chars()
        .take(100)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "unnamed".into()
    } else {
        slug
    }
}

fn stable_fragment(value: &str) -> String {
    let hash = value
        .as_bytes()
        .iter()
        .fold(0xcbf29ce484222325_u64, |state, byte| {
            (state ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        });
    format!("{hash:016x}")
}

fn parameter_sensitivity(name: &str) -> Option<&'static str> {
    let name = name.to_ascii_lowercase();
    if [
        "password", "passwd", "token", "secret", "api_key", "apikey", "session", "csrf",
    ]
    .iter()
    .any(|needle| name.contains(needle))
    {
        Some("authentication")
    } else if [
        "user_id",
        "userid",
        "account_id",
        "tenant",
        "organization",
        "org_id",
        "role",
        "permission",
        "owner",
        "object_id",
    ]
    .iter()
    .any(|needle| name.contains(needle))
    {
        Some("object_reference")
    } else if [
        "redirect",
        "return_to",
        "returnurl",
        "callback",
        "continue",
        "next",
        "url",
    ]
    .iter()
    .any(|needle| name.contains(needle))
    {
        Some("redirect")
    } else if [
        "file",
        "filename",
        "upload",
        "path",
        "document",
        "attachment",
    ]
    .iter()
    .any(|needle| name.contains(needle))
    {
        Some("file")
    } else if [
        "query", "search", "filter", "sort", "page", "limit", "offset",
    ]
    .iter()
    .any(|needle| name.contains(needle))
    {
        Some("data_selection")
    } else {
        None
    }
}

fn detected_technologies(result: &ToolResult) -> Vec<String> {
    let headers = result
        .data
        .get("response_headers")
        .and_then(Value::as_object);
    let body = string_field(&result.data, "response_body")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut technologies = BTreeSet::new();
    for header in ["server", "x-powered-by", "x-generator"] {
        if let Some(value) = headers
            .and_then(|headers| headers.get(header))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            technologies.insert(value.trim().to_string());
        }
    }
    for (needle, name) in [
        ("wp-content", "WordPress"),
        ("__next_data__", "Next.js"),
        ("data-reactroot", "React"),
    ] {
        if body.contains(needle) {
            technologies.insert(name.into());
        }
    }
    technologies.extend(
        string_array(&result.data, "technology_hints")
            .into_iter()
            .map(str::to_owned),
    );
    technologies.into_iter().collect()
}

fn response_header<'a>(result: &'a ToolResult, name: &str) -> Option<&'a str> {
    result
        .data
        .get("response_headers")
        .and_then(Value::as_object)
        .and_then(|headers| headers.get(name))
        .and_then(Value::as_str)
}

fn script_urls(result: &ToolResult, base: &Url) -> Vec<String> {
    const MAX_SCRIPT_URLS: usize = 500;
    let structured = string_array(&result.data, "script_urls")
        .into_iter()
        .filter_map(|value| base.join(value).ok())
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .map(|url| url.to_string())
        .collect::<BTreeSet<_>>();
    if !structured.is_empty() {
        return structured.into_iter().take(MAX_SCRIPT_URLS).collect();
    }
    let body = string_field(&result.data, "response_body").unwrap_or_default();
    let pattern = Regex::new(r#"(?is)<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']"#).unwrap();
    pattern
        .captures_iter(body)
        .filter_map(|captures| captures.get(1))
        .filter_map(|value| base.join(value.as_str().trim()).ok())
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .map(|url| url.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(MAX_SCRIPT_URLS)
        .collect()
}

fn resolved_values(result: &ToolResult, key: &str, base: &Url) -> Vec<String> {
    string_array(&result.data, key)
        .into_iter()
        .filter_map(|value| base.join(value).ok())
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .map(|url| url.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sanitized_analysis(result: &ToolResult) -> Value {
    const SAFE_KEYS: &[&str] = &[
        "body_sha256",
        "body_bytes",
        "is_html",
        "page_title",
        "links",
        "script_urls",
        "forms",
        "page_signals",
        "external_link_count",
        "same_origin_links_only",
        "absolute_urls",
        "endpoints",
        "endpoint_profiles",
        "source_map_urls",
        "source_map_candidates",
        "javascript_imports",
        "api_candidates",
        "api_base_urls",
        "auth_candidates",
        "parameter_names",
        "auth_signals",
        "technology_hints",
        "graphql_operations",
        "websocket_endpoints",
        "client_security_signals",
        "secret_indicator_kinds",
        "secret_indicator_count",
        "recognized_api_description",
        "api_version",
        "api_format",
        "api_paths",
        "server_urls",
        "schema_count",
        "schema_names",
        "operation_profiles",
        "operation_count",
        "authenticated_operation_count",
        "public_operation_count",
        "deprecated_operation_count",
        "security_schemes",
        "graphql_detected",
        "graphql_root_types",
        "graphql_type_count",
        "raw_body_retained",
    ];
    Value::Object(
        SAFE_KEYS
            .iter()
            .filter_map(|key| {
                result
                    .data
                    .get(*key)
                    .cloned()
                    .map(|value| ((*key).into(), value))
            })
            .collect(),
    )
}

fn declared_urls(result: &ToolResult, origin: &str) -> Vec<String> {
    const MAX_DECLARED_URLS: usize = 500;
    let body = string_field(&result.data, "response_body").unwrap_or_default();
    let Ok(base) = Url::parse(&format!("{}/", origin.trim_end_matches('/'))) else {
        return vec![];
    };
    let mut values = BTreeSet::new();
    match result.tool_name.as_str() {
        "fetch_robots_txt" => {
            for line in body.lines() {
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                if !matches!(
                    name.trim().to_ascii_lowercase().as_str(),
                    "allow" | "disallow" | "sitemap"
                ) {
                    continue;
                }
                let value = value.trim();
                if value.is_empty() {
                    continue;
                }
                if let Ok(url) = base.join(value) {
                    values.insert(url.to_string());
                }
                if values.len() >= MAX_DECLARED_URLS {
                    break;
                }
            }
        }
        "fetch_sitemap" => {
            let mut remaining = body;
            while let Some(start) = remaining.find("<loc>") {
                remaining = &remaining[start + 5..];
                let Some(end) = remaining.find("</loc>") else {
                    break;
                };
                let value = remaining[..end].trim();
                if let Ok(url) = base.join(value) {
                    values.insert(url.to_string());
                }
                remaining = &remaining[end + 6..];
                if values.len() >= MAX_DECLARED_URLS {
                    break;
                }
            }
        }
        _ => {}
    }
    values.into_iter().collect()
}

fn string_field<'a>(data: &'a StructuredData, key: &str) -> Option<&'a str> {
    data.get(key).and_then(Value::as_str)
}

fn string_array<'a>(data: &'a StructuredData, key: &str) -> Vec<&'a str> {
    data.get(key)
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

pub fn is_duplicate_recon_error(error: &RunServiceError) -> bool {
    error.code == RunServiceErrorCode::ReconItemAlreadyExists
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{RunService, TaskBudget, TaskId, ToolResultId},
        scope_guard::ScopeProject,
    };

    fn task() -> Task {
        Task {
            schema_version: CORE_SCHEMA_VERSION,
            id: TaskId("task-ingest".into()),
            objective: "Ingest Recon observations.".into(),
            primary_target: "https://example.test".into(),
            scope: ScopeProject {
                id: "scope-ingest".into(),
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
            available_tools: vec![],
            memory_policy: Default::default(),
        }
    }

    #[test]
    fn certificate_and_dns_results_expand_the_asset_graph_without_duplicates() {
        let service = RunService::default();
        let task = task();
        let run = service.create_run(task.clone()).unwrap();
        service.start_run(&run.id).unwrap();
        let ingestor = ReconIngestor::default();
        ingestor.seed_task(&service, &run.id, &task).unwrap();
        let ct = ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId("tool-ct".into()),
            tool_name: "search_certificate_transparency".into(),
            success: true,
            data: StructuredData::from([
                ("domain".into(), Value::String("example.test".into())),
                (
                    "subdomains".into(),
                    Value::Array(vec![Value::String("api.example.test".into())]),
                ),
                ("record_count".into(), Value::from(1)),
            ]),
            error: None,
            duration_ms: 1,
        };
        ingestor
            .ingest_tool_result(&service, &run.id, &task, &ct, None)
            .unwrap();
        ingestor
            .ingest_tool_result(&service, &run.id, &task, &ct, None)
            .unwrap();
        let dns = ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId("tool-dns".into()),
            tool_name: "resolve_dns".into(),
            success: true,
            data: StructuredData::from([
                ("hostname".into(), Value::String("api.example.test".into())),
                ("addresses".into(), serde_json::json!(["192.0.2.10"])),
                (
                    "address_profiles".into(),
                    serde_json::json!([{
                        "address": "192.0.2.10",
                        "family": "ipv4",
                        "classification": "documentation"
                    }]),
                ),
                ("resolved".into(), Value::Bool(true)),
                ("lookup_error".into(), Value::Null),
                ("wildcard_detected".into(), Value::Bool(false)),
                ("wildcard_match".into(), Value::Bool(false)),
                ("dns_query_count".into(), Value::from(3)),
            ]),
            error: None,
            duration_ms: 1,
        };
        ingestor
            .ingest_tool_result(&service, &run.id, &task, &dns, None)
            .unwrap();
        let snapshot = service.get_recon_snapshot(&run.id).unwrap();
        assert_eq!(snapshot.assets.len(), 3);
        assert_eq!(snapshot.relations.len(), 2);
        assert_eq!(snapshot.observations.len(), 3);
        let api = snapshot
            .assets
            .iter()
            .find(|asset| asset.canonical_value == "api.example.test")
            .unwrap();
        assert_eq!(api.confidence, ReconConfidence::Confirmed);
        assert!(api.tags.contains(&"source:certificate_transparency".into()));
        assert!(api.tags.contains(&"source:dns".into()));
    }

    #[test]
    fn visual_result_creates_authentication_surface_and_visual_observation() {
        let service = RunService::default();
        let task = task();
        let run = service.create_run(task.clone()).unwrap();
        service.start_run(&run.id).unwrap();
        let result = ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId("tool-visual".into()),
            tool_name: "analyze_visual_page".into(),
            success: true,
            data: StructuredData::from([
                (
                    "final_url".into(),
                    Value::String("https://example.test/login".into()),
                ),
                ("screenshot_sha256".into(), Value::String("a".repeat(64))),
                ("screenshot_retained".into(), Value::Bool(false)),
                (
                    "visual_observation".into(),
                    serde_json::json!({
                        "page_kind": "authentication",
                        "summary": "A login form is visible.",
                        "authentication_surface": true,
                        "administration_surface": false,
                        "form_kinds": ["login"],
                        "technology_hints": ["React"],
                        "security_relevant_elements": ["login_form"],
                        "confidence": "high",
                        "limitations": []
                    }),
                ),
            ]),
            error: None,
            duration_ms: 10,
        };

        ReconIngestor::default()
            .ingest_tool_result(&service, &run.id, &task, &result, None)
            .unwrap();
        let snapshot = service.get_recon_snapshot(&run.id).unwrap();
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == ReconAssetKind::AuthenticationSurface
                && asset.canonical_value == "https://example.test/login"
        }));
        assert!(snapshot.observations.iter().any(|observation| {
            observation.source == ReconObservationSource::VisualAnalysis
                && observation.facts["screenshot_retained"] == false
        }));
    }

    #[test]
    fn http_service_profile_links_infrastructure_and_confirms_the_host() {
        let service = RunService::default();
        let task = task();
        let run = service.create_run(task.clone()).unwrap();
        service.start_run(&run.id).unwrap();
        let result = ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId("tool-http-profile".into()),
            tool_name: "probe_http".into(),
            success: true,
            data: StructuredData::from([
                (
                    "final_url".into(),
                    Value::String("https://api.example.test/".into()),
                ),
                ("status_code".into(), Value::from(200)),
                (
                    "response_headers".into(),
                    serde_json::json!({"server": "cloudflare"}),
                ),
                ("response_body".into(), Value::String(String::new())),
                ("redirected".into(), Value::Bool(false)),
                ("tls".into(), serde_json::json!({"present": true})),
                (
                    "service_profile".into(),
                    serde_json::json!({
                        "scheme": "https",
                        "hostname": "api.example.test",
                        "port": 443,
                        "live": true,
                        "status_class": "2xx",
                        "tls_present": true,
                        "security_headers_present": [],
                        "infrastructure_hints": ["Cloudflare"]
                    }),
                ),
            ]),
            error: None,
            duration_ms: 2,
        };

        ReconIngestor::default()
            .ingest_tool_result(&service, &run.id, &task, &result, None)
            .unwrap();
        let snapshot = service.get_recon_snapshot(&run.id).unwrap();
        let host = snapshot
            .assets
            .iter()
            .find(|asset| asset.canonical_value == "api.example.test")
            .unwrap();
        assert_eq!(host.confidence, ReconConfidence::Confirmed);
        assert!(host.tags.contains(&"http:live".into()));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == ReconAssetKind::ThirdPartyService && asset.canonical_value == "Cloudflare"
        }));
        assert!(snapshot
            .relations
            .iter()
            .any(|relation| relation.kind == ReconRelationKind::HostedOn));
        assert!(snapshot
            .observations
            .iter()
            .any(|observation| { observation.source == ReconObservationSource::TlsInspection }));
    }

    #[test]
    fn historical_result_links_old_clues_to_current_candidate_assets() {
        let service = RunService::default();
        let task = task();
        let run = service.create_run(task.clone()).unwrap();
        service.start_run(&run.id).unwrap();
        let result = ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId("tool-history".into()),
            tool_name: "lookup_web_archive".into(),
            success: true,
            data: StructuredData::from([
                ("domain".into(), Value::String("example.test".into())),
                (
                    "historical_urls".into(),
                    serde_json::json!([{
                        "url": "https://api.example.test/assets/legacy.js",
                        "kind": "javascript",
                        "first_seen": "20200101000000",
                        "last_seen": "20240101000000",
                        "capture_count": 2,
                        "mime_types": ["application/javascript"],
                        "providers": ["wayback", "common_crawl"]
                    }]),
                ),
                ("historical_url_count".into(), Value::from(1)),
                ("historical_javascript_count".into(), Value::from(1)),
                ("historical_endpoint_count".into(), Value::from(0)),
                (
                    "historical_subdomains".into(),
                    serde_json::json!(["api.example.test"]),
                ),
                ("parameter_names".into(), Value::Array(vec![])),
                ("raw_archive_records_retained".into(), Value::Bool(false)),
            ]),
            error: None,
            duration_ms: 10,
        };

        ReconIngestor::default()
            .ingest_tool_result(&service, &run.id, &task, &result, None)
            .unwrap();
        let snapshot = service.get_recon_snapshot(&run.id).unwrap();
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == ReconAssetKind::HistoricalUrl
                && asset.canonical_value == "https://api.example.test/assets/legacy.js"
        }));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == ReconAssetKind::JavascriptBundle
                && asset.canonical_value == "https://api.example.test/assets/legacy.js"
        }));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.canonical_value == "api.example.test"
                && asset.tags.contains(&"source:web_archive".into())
        }));
        assert!(snapshot
            .relations
            .iter()
            .any(|relation| relation.kind == ReconRelationKind::HistoricalVersionOf));
        assert!(snapshot.observations.iter().any(|observation| {
            observation.source == ReconObservationSource::WebArchive
                && observation.facts["new_clue_count"] == 1
        }));
    }

    #[test]
    fn web_page_result_expands_links_forms_and_authentication_surface() {
        let service = RunService::default();
        let task = task();
        let run = service.create_run(task.clone()).unwrap();
        service.start_run(&run.id).unwrap();
        let result = ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId("tool-web-page".into()),
            tool_name: "analyze_web_page".into(),
            success: true,
            data: StructuredData::from([
                (
                    "final_url".into(),
                    Value::String("https://example.test/".into()),
                ),
                ("status_code".into(), Value::from(200)),
                (
                    "response_headers".into(),
                    serde_json::json!({"content-type": "text/html"}),
                ),
                ("tls".into(), serde_json::json!({"present": true})),
                ("page_title".into(), Value::String("Account Portal".into())),
                (
                    "links".into(),
                    serde_json::json!(["https://example.test/admin"]),
                ),
                ("script_urls".into(), Value::Array(vec![])),
                (
                    "forms".into(),
                    serde_json::json!([{
                        "method": "POST",
                        "action": "https://example.test/login",
                        "has_password_input": true,
                        "has_file_upload": false,
                        "input_names": ["password", "username"],
                        "input_types": ["password", "text"]
                    }]),
                ),
                ("page_signals".into(), serde_json::json!(["authentication"])),
                ("raw_body_retained".into(), Value::Bool(false)),
            ]),
            error: None,
            duration_ms: 4,
        };

        ReconIngestor::default()
            .ingest_tool_result(&service, &run.id, &task, &result, None)
            .unwrap();
        let snapshot = service.get_recon_snapshot(&run.id).unwrap();
        let page = snapshot
            .assets
            .iter()
            .find(|asset| asset.canonical_value == "https://example.test/")
            .unwrap();
        assert_eq!(page.display_name.as_deref(), Some("Account Portal"));
        assert!(page.tags.contains(&"web:analyzed".into()));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == ReconAssetKind::Url
                && asset.canonical_value == "https://example.test/admin"
                && asset.tags.contains(&"web:discovered_link".into())
        }));
        assert!(snapshot
            .assets
            .iter()
            .any(|asset| asset.kind == ReconAssetKind::WebForm));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == ReconAssetKind::AuthenticationSurface
                && asset.canonical_value == "https://example.test/login"
        }));
        assert!(snapshot
            .observations
            .iter()
            .any(|observation| { observation.source == ReconObservationSource::WebPageAnalysis }));
        assert!(snapshot
            .relations
            .iter()
            .any(|relation| relation.kind == ReconRelationKind::AuthenticatesWith));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == ReconAssetKind::Parameter
                && asset.display_name.as_deref() == Some("password")
                && asset
                    .tags
                    .contains(&"parameter:sensitivity:authentication".into())
        }));
        assert!(snapshot
            .relations
            .iter()
            .any(|relation| relation.kind == ReconRelationKind::AcceptsInput));
        assert!(snapshot.hypotheses.iter().any(|hypothesis| {
            hypothesis.kind == Some(super::super::ReconHypothesisKind::HighValueParameter)
        }));
    }
}
