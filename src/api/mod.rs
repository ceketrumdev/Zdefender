use axum::{
    routing::{post, get},
    Router,
    Json,
    extract::Path,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use crate::protection::suspend::IpSuspender;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct SuspendRequest {
    ip: String,
    interface: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    success: bool,
    message: String,
}

pub fn create_router(suspender: Arc<IpSuspender>) -> Router {
    Router::new()
        .route("/api/v1/suspend", post(suspend_ip))
        .route("/api/v1/unsuspend/:ip", post(unsuspend_ip))
        .route("/api/v1/status/:ip", get(check_status))
        .route("/api/v1/list", get(list_suspended))
        .with_state(suspender)
}

async fn suspend_ip(
    state: axum::extract::State<Arc<IpSuspender>>,
    Json(payload): Json<SuspendRequest>,
) -> Json<ApiResponse> {
    match payload.ip.parse::<IpAddr>() {
        Ok(ip) => {
            match state.suspend_ip(ip, payload.interface).await {
                Ok(_) => Json(ApiResponse {
                    success: true,
                    message: format!("IP {} suspendue avec succès", payload.ip),
                }),
                Err(e) => Json(ApiResponse {
                    success: false,
                    message: format!("Erreur lors de la suspension de l'IP {}: {}", payload.ip, e),
                }),
            }
        },
        Err(_) => Json(ApiResponse {
            success: false,
            message: format!("IP invalide: {}", payload.ip),
        }),
    }
}

async fn unsuspend_ip(
    state: axum::extract::State<Arc<IpSuspender>>,
    Path(ip): Path<String>,
) -> Json<ApiResponse> {
    match ip.parse::<IpAddr>() {
        Ok(ip_addr) => {
            match state.unsuspend_ip(&ip_addr).await {
                Ok(_) => Json(ApiResponse {
                    success: true,
                    message: format!("IP {} désuspendue avec succès", ip),
                }),
                Err(e) => Json(ApiResponse {
                    success: false,
                    message: format!("Erreur lors de la désuspension de l'IP {}: {}", ip, e),
                }),
            }
        },
        Err(_) => Json(ApiResponse {
            success: false,
            message: format!("IP invalide: {}", ip),
        }),
    }
}

async fn check_status(
    state: axum::extract::State<Arc<IpSuspender>>,
    Path(ip): Path<String>,
) -> Json<ApiResponse> {
    match ip.parse::<IpAddr>() {
        Ok(ip_addr) => {
            let is_suspended = state.is_suspended(&ip_addr).await;
            Json(ApiResponse {
                success: true,
                message: if is_suspended {
                    format!("IP {} est suspendue", ip)
                } else {
                    format!("IP {} n'est pas suspendue", ip)
                },
            })
        },
        Err(_) => Json(ApiResponse {
            success: false,
            message: format!("IP invalide: {}", ip),
        }),
    }
}

async fn list_suspended(
    state: axum::extract::State<Arc<IpSuspender>>,
) -> Json<ApiResponse> {
    let ips = state.get_suspended_ips().await;
    Json(ApiResponse {
        success: true,
        message: format!("IPs suspendues: {}", ips.iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ")),
    })
} 