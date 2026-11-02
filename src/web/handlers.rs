use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::presets::{get_top_ports, PortPreset};
use crate::scanner::{ScanConfig as CoreScanConfig, Scanner};
use crate::web::state::AppState;
use crate::web::types::{
    ApiResponse, ExportRequest, ScanConfig, ScanInfo, ScanProgress, ScanRequest, ScanStatus,
};

pub async fn health_check() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success(
        "NullScan Web Dashboard is healthy".to_string(),
    ))
}

pub async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ScanRequest>,
) -> Result<Json<ApiResponse<ScanInfo>>, StatusCode> {
    let scan_id = Uuid::new_v4();
    let now = Utc::now();

    // Parse ports
    let ports = if request.top100 {
        get_top_ports(PortPreset::Top100)
    } else if request.top1000 {
        get_top_ports(PortPreset::Top1000)
    } else if let Some(port_spec) = &request.ports {
        parse_port_spec(port_spec).map_err(|_| StatusCode::BAD_REQUEST)?
    } else {
        return Err(StatusCode::BAD_REQUEST);
    };

    // Parse targets
    let targets = parse_targets(&request.target)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let config = ScanConfig {
        target: request.target.clone(),
        ports: ports.clone(),
        concurrency: request.concurrency.unwrap_or(100),
        max_hosts: request.max_hosts.unwrap_or(1),
        ping_sweep: request.ping_sweep,
        timeout: request.timeout.unwrap_or(3000),
        ping_timeout: request.ping_timeout.unwrap_or(800),
        banners: request.banners,
        vuln_check: request.vuln_check,
        fast_mode: request.fast_mode,
    };

    let scan_info = ScanInfo {
        id: scan_id,
        name: request.name.unwrap_or_else(|| format!("Scan {}", scan_id)),
        description: request
            .description
            .unwrap_or_else(|| format!("Scan of {}", request.target)),
        target: request.target.clone(),
        status: ScanStatus::Pending,
        created_at: now,
        started_at: None,
        completed_at: None,
        progress: ScanProgress::default(),
        config,
        results: Vec::new(),
        error: None,
    };

    let scan_arc = Arc::new(RwLock::new(scan_info.clone()));
    state.scans.insert(scan_id, scan_arc.clone());

    // Start the scan in a background task
    let scan_task = tokio::spawn(async move {
        run_scan_task(scan_arc, targets, ports).await;
    });

    state.scan_handles.insert(scan_id, scan_task);

    Ok(Json(ApiResponse::success(scan_info)))
}

pub async fn list_scans(State(state): State<Arc<AppState>>) -> Json<ApiResponse<Vec<ScanInfo>>> {
    state.cleanup_completed_scans().await;
    let mut scans = Vec::new();

    for scan_ref in state.scans.iter() {
        let scan = scan_ref.value().read().await;
        scans.push(scan.clone());
    }

    // Sort by creation time (newest first)
    scans.sort_by_key(|scan| std::cmp::Reverse(scan.created_at));

    Json(ApiResponse::success(scans))
}

pub async fn get_scan(
    Path(scan_id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<ScanInfo>>, StatusCode> {
    if let Some(scan_ref) = state.scans.get(&scan_id) {
        let scan = scan_ref.value().read().await;
        Ok(Json(ApiResponse::success(scan.clone())))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn get_scan_results(
    Path(scan_id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    if let Some(scan_ref) = state.scans.get(&scan_id) {
        let scan = scan_ref.value().read().await;
        let results = json!({
            "scan_id": scan_id,
            "status": scan.status,
            "progress": scan.progress,
            "results": scan.results,
            "summary": {
                "total_ports": scan.progress.total_ports,
                "open_ports": scan.progress.open_ports,
                "closed_ports": scan.progress.total_ports - scan.progress.open_ports,
                "hosts_scanned": scan.progress.hosts_completed,
                "vulnerabilities": scan.results.iter().map(|r| r.vulnerabilities.len()).sum::<usize>()
            }
        });
        Ok(Json(ApiResponse::success(results)))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn stop_scan(
    Path(scan_id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    if let Some((_, handle)) = state.scan_handles.remove(&scan_id) {
        handle.abort();

        if let Some(scan_ref) = state.scans.get(&scan_id) {
            let mut scan = scan_ref.value().write().await;
            scan.status = ScanStatus::Stopped;
            scan.completed_at = Some(Utc::now());
        }

        Ok(Json(ApiResponse::success("Scan stopped".to_string())))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn export_scan(
    Path(scan_id): Path<Uuid>,
    Query(_export_req): Query<ExportRequest>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    if let Some(scan_ref) = state.scans.get(&scan_id) {
        let _scan = scan_ref.value().read().await;

        // TODO: Implement export functionality using existing export module
        let export_data = format!("Export of scan {}", scan_id);

        Ok(Json(ApiResponse::success(export_data)))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn run_scan_task(
    scan_arc: Arc<RwLock<ScanInfo>>,
    targets: Vec<std::net::IpAddr>,
    ports: Vec<u16>,
) {
    // Update scan status to running
    {
        let mut scan = scan_arc.write().await;
        scan.status = ScanStatus::Running;
        scan.started_at = Some(Utc::now());
        scan.progress.total_hosts = targets.len();
        scan.progress.total_ports = ports.len() * targets.len();
    }

    // Create scanner configuration
    let config = {
        let scan = scan_arc.read().await;
        CoreScanConfig {
            target: targets[0], // Use first target for now
            ports: ports.clone(),
            concurrency: scan.config.concurrency,
            timeout_ms: scan.config.timeout,
            grab_banners: scan.config.banners,
            quiet: true, // Web scans should be quiet
            fast_mode: scan.config.fast_mode,
        }
    };

    // Run the scan
    let scanner = Scanner::new(config);
    match scanner.scan().await {
        Ok(results) => {
            let mut scan = scan_arc.write().await;
            scan.status = ScanStatus::Completed;
            scan.completed_at = Some(Utc::now());
            scan.results = results;
            scan.progress.hosts_completed = targets.len();
            scan.progress.ports_scanned = ports.len() * targets.len();
            scan.progress.open_ports = scan.results.iter().filter(|r| r.is_open).count();
        }
        Err(e) => {
            let mut scan = scan_arc.write().await;
            scan.status = ScanStatus::Failed;
            scan.completed_at = Some(Utc::now());
            scan.error = Some(e.to_string());
        }
    }
}

// Helper functions
fn parse_port_spec(port_spec: &str) -> anyhow::Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in port_spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            // Range like "1-1000"
            let parts: Vec<&str> = part.split('-').collect();
            if parts.len() == 2 {
                let start: u16 = parts[0].parse()?;
                let end: u16 = parts[1].parse()?;
                for port in start..=end {
                    ports.push(port);
                }
            }
        } else {
            // Single port
            let port: u16 = part.parse()?;
            ports.push(port);
        }
    }

    Ok(ports)
}

async fn parse_targets(target_spec: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
    let mut targets = Vec::new();

    // Simple IP parsing for now
    if target_spec.contains('/') {
        // CIDR notation
        let network: ipnet::IpNet = target_spec.parse()?;
        for ip in network.hosts().take(1024) {
            targets.push(ip);
        }
    } else {
        // Single IP or hostname
        match target_spec.parse::<std::net::IpAddr>() {
            Ok(ip) => targets.push(ip),
            Err(_) => {
                // Try to resolve hostname
                let resolved = tokio::net::lookup_host(format!("{}:80", target_spec)).await?;
                if let Some(addr) = resolved.map(|addr| addr.ip()).next() {
                    targets.push(addr);
                }
            }
        }
    }

    Ok(targets)
}
