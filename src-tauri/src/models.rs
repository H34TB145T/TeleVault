use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultFile {
    pub id: String,
    pub name: String,
    pub folder_path: String,
    pub category: String,
    pub size: u64,
    pub mime_type: String,
    pub encrypted: bool,
    pub cached: bool,
    pub chunk_count: u32,
    pub account_id: String,
    pub account_name: String,
    pub created_at: String,
    pub status: String,
    pub thumbnail: Option<String>,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub last_opened_at: Option<String>,
    pub deleted_at: Option<String>,
    pub purge_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultFolder {
    pub id: String,
    pub path: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transfer {
    pub id: String,
    pub file_id: Option<String>,
    pub file_name: String,
    pub direction: String,
    pub state: String,
    pub progress: f64,
    pub transferred: u64,
    pub total: u64,
    pub speed: u64,
    pub eta_seconds: Option<u64>,
    pub message: Option<String>,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    pub name: String,
    pub phone: String,
    pub connected: bool,
    pub color: String,
    pub initials: String,
    pub file_count: u64,
    pub stored_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct AccountCredentials {
    pub id: String,
    pub name: String,
    pub phone: String,
    pub api_id: i32,
    pub api_hash: String,
    pub session_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchFolder {
    pub id: String,
    pub path: String,
    pub enabled: bool,
    pub encrypt: bool,
    pub account_id: String,
    pub uploaded_count: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewWatchFolder {
    pub path: String,
    pub enabled: bool,
    pub encrypt: bool,
    pub account_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dashboard {
    pub files: Vec<VaultFile>,
    pub folders: Vec<VaultFolder>,
    pub transfers: Vec<Transfer>,
    pub accounts: Vec<Account>,
    pub watch_folders: Vec<WatchFolder>,
    pub cache_used: u64,
    pub cache_limit: u64,
    pub preview_cache_limit: u64,
    pub preview_cache_ttl_minutes: u64,
    pub stored_bytes: u64,
    pub encryption_ready: bool,
    pub keychain_backed: bool,
    pub app_lock_enabled: bool,
    pub app_lock_timeout_minutes: u64,
    pub speed_profile: String,
    pub recycle_retention_days: u64,
    pub automatic_retry_count: u64,
    pub notifications_enabled: bool,
    pub health_checks_enabled: bool,
    pub health_check_interval_days: u64,
    pub latest_health_report: Option<HealthReport>,
    pub automatic_updates_configured: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockStatus {
    pub enabled: bool,
    pub locked: bool,
    pub keychain_backed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReport {
    pub scanned_messages: u64,
    pub manifests_found: u64,
    pub restored: u64,
    pub skipped: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryTestReport {
    pub checked_at: String,
    pub key_valid: bool,
    pub files_sampled: u64,
    pub manifests_valid: u64,
    pub chunks_available: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthReport {
    pub checked_at: String,
    pub account_id: String,
    pub files_sampled: u64,
    pub chunks_checked: u64,
    pub hashes_verified: u64,
    pub missing: u64,
    pub corrupted: u64,
    pub healthy: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewInfo {
    pub token: String,
    pub url: String,
    pub kind: String,
    pub mime_type: String,
    pub size: u64,
    pub cache_limit: u64,
    pub expires_at: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewText {
    pub content: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareRecipient {
    pub token: String,
    pub username: String,
    pub display_name: String,
    pub initials: String,
    pub kind: String,
    pub verified: bool,
    pub expires_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadOptions {
    pub paths: Vec<String>,
    pub folder_root: Option<String>,
    pub destination_folder: Option<String>,
    pub encrypt: bool,
    pub account_id: String,
    #[serde(default = "default_duplicate_policy")]
    pub duplicate_policy: String,
}

fn default_duplicate_policy() -> String {
    "skip".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub account_id: Option<String>,
    pub name: String,
    pub phone: String,
    pub api_id: i32,
    pub api_hash: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResult {
    pub flow_id: String,
    pub status: String,
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qr_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRecord {
    pub index: u32,
    pub message_id: i64,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultManifest {
    pub format: String,
    pub file_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_path: Option<String>,
    pub original_size: u64,
    pub mime_type: String,
    pub category: String,
    pub encrypted: bool,
    pub original_sha256: String,
    pub wrapped_key: Option<String>,
    pub key_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_metadata: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_nonce: Option<String>,
    pub chunks: Vec<ChunkRecord>,
    pub created_at: String,
}
