use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::web::types::{ScanInfo, ScanSummary};

#[derive(Clone)]
pub struct AppState {
    pub scans: Arc<DashMap<Uuid, Arc<RwLock<ScanInfo>>>>,
    pub scan_handles: Arc<DashMap<Uuid, tokio::task::JoinHandle<()>>>,
    /// Bearer token required for the dashboard UI and API.
    pub auth_token: String,
}

impl AppState {
    pub fn new(auth_token: String) -> Self {
        Self {
            scans: Arc::new(DashMap::new()),
            scan_handles: Arc::new(DashMap::new()),
            auth_token,
        }
    }

    pub async fn get_summary(&self) -> ScanSummary {
        let mut summary = ScanSummary {
            total_scans: 0,
            active_scans: 0,
            completed_scans: 0,
            failed_scans: 0,
            total_hosts_scanned: 0,
            total_ports_scanned: 0,
            total_open_ports: 0,
            total_vulnerabilities: 0,
        };

        for scan_ref in self.scans.iter() {
            let scan = scan_ref.value().read().await;
            summary.total_scans += 1;

            match scan.status {
                crate::web::types::ScanStatus::Running => summary.active_scans += 1,
                crate::web::types::ScanStatus::Completed => summary.completed_scans += 1,
                crate::web::types::ScanStatus::Failed => summary.failed_scans += 1,
                _ => {}
            }

            summary.total_hosts_scanned += scan.progress.hosts_completed;
            summary.total_ports_scanned += scan.progress.ports_scanned;
            summary.total_open_ports += scan.progress.open_ports;

            // Count vulnerabilities
            for result in &scan.results {
                summary.total_vulnerabilities += result.vulnerabilities.len();
            }
        }

        summary
    }

    pub async fn cleanup_completed_scans(&self) {
        let mut to_remove = Vec::new();

        for scan_ref in self.scans.iter() {
            let scan = scan_ref.value().read().await;
            if matches!(
                scan.status,
                crate::web::types::ScanStatus::Completed | crate::web::types::ScanStatus::Failed
            ) {
                // Keep scans for 24 hours after completion
                if let Some(completed_at) = scan.completed_at {
                    let hours_since_completion = (chrono::Utc::now() - completed_at).num_hours();
                    if hours_since_completion > 24 {
                        to_remove.push(scan.id);
                    }
                }
            }
        }

        for id in to_remove {
            self.scans.remove(&id);
            self.scan_handles.remove(&id);
        }
    }
}
