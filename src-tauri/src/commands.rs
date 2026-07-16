use crate::core::Core;
use crate::error::{AppError, AppResult};
use crate::models::{
    Dashboard, HealthReport, LockStatus, LoginRequest, LoginResult, NewWatchFolder, PreviewInfo,
    PreviewText, RecoveryReport, RecoveryTestReport, ShareRecipient, UploadOptions, VaultFile,
    VaultFolder, WatchFolder,
};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;
use tauri::State;

pub struct AppState(pub Arc<Core>);

#[tauri::command]
pub fn get_lock_status(state: State<'_, AppState>) -> AppResult<LockStatus> {
    state.0.lock_status()
}

#[tauri::command]
pub fn record_activity(state: State<'_, AppState>) -> AppResult<LockStatus> {
    state.0.record_activity()
}

#[tauri::command]
pub fn unlock_app(password: String, state: State<'_, AppState>) -> AppResult<LockStatus> {
    state.0.unlock(&password)
}

#[tauri::command]
pub fn configure_app_lock(password: String, state: State<'_, AppState>) -> AppResult<LockStatus> {
    state.0.configure_app_lock(&password)
}

#[tauri::command]
pub fn disable_app_lock(password: String, state: State<'_, AppState>) -> AppResult<LockStatus> {
    state.0.disable_app_lock(&password)
}

#[tauri::command]
pub fn lock_app(state: State<'_, AppState>) -> AppResult<LockStatus> {
    state.0.lock()
}

#[tauri::command]
pub fn get_dashboard(state: State<'_, AppState>) -> AppResult<Dashboard> {
    state.0.ensure_unlocked()?;
    state
        .0
        .catalog
        .dashboard(state.0.master.is_ready(), state.0.master.keychain_backed())
}

#[tauri::command]
pub async fn get_account_avatar(
    account_id: String,
    state: State<'_, AppState>,
) -> AppResult<Option<String>> {
    state.0.ensure_unlocked()?;
    state.0.account_avatar(&account_id).await
}

#[tauri::command]
pub async fn queue_uploads(
    options: UploadOptions,
    state: State<'_, AppState>,
) -> AppResult<Vec<VaultFile>> {
    state.0.ensure_unlocked()?;
    state.0.queue_paths(options).await
}

#[tauri::command]
pub async fn clear_preview_cache(state: State<'_, AppState>) -> AppResult<u64> {
    state.0.ensure_unlocked()?;
    state.0.clear_preview_cache().await
}

#[tauri::command]
pub async fn recover_vault(
    account_id: String,
    state: State<'_, AppState>,
) -> AppResult<RecoveryReport> {
    state.0.ensure_unlocked()?;
    state.0.recover_vault(&account_id).await
}

#[tauri::command]
pub async fn test_recovery(
    account_id: String,
    recovery_key: String,
    state: State<'_, AppState>,
) -> AppResult<RecoveryTestReport> {
    state.0.ensure_unlocked()?;
    state.0.test_recovery(&account_id, &recovery_key).await
}

#[tauri::command]
pub async fn run_health_check(
    account_id: String,
    sample_count: u64,
    state: State<'_, AppState>,
) -> AppResult<HealthReport> {
    state.0.ensure_unlocked()?;
    state.0.health_check(&account_id, sample_count).await
}

#[tauri::command]
pub fn set_file_favorite(id: String, favorite: bool, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.set_favorite(&id, favorite)
}

#[tauri::command]
pub fn set_file_tags(id: String, tags: Vec<String>, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.set_tags(&id, tags)
}

#[tauri::command]
pub async fn rename_file(
    id: String,
    new_name: String,
    state: State<'_, AppState>,
) -> AppResult<VaultFile> {
    state.0.ensure_unlocked()?;
    state.0.rename_file(&id, &new_name).await
}

#[tauri::command]
pub async fn move_file(
    id: String,
    folder_path: String,
    state: State<'_, AppState>,
) -> AppResult<VaultFile> {
    state.0.ensure_unlocked()?;
    state.0.move_file(&id, &folder_path).await
}

#[tauri::command]
pub async fn copy_file(
    id: String,
    new_name: String,
    folder_path: String,
    state: State<'_, AppState>,
) -> AppResult<VaultFile> {
    state.0.ensure_unlocked()?;
    state.0.copy_file(&id, &new_name, &folder_path).await
}

#[tauri::command]
pub fn expand_upload_paths(
    paths: Vec<String>,
    state: State<'_, AppState>,
) -> AppResult<Vec<String>> {
    state.0.ensure_unlocked()?;
    state.0.expand_upload_paths(paths)
}

#[tauri::command]
pub fn dismiss_transfer(id: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.dismiss_transfer_history(&[id]).map(|_| ())
}

#[tauri::command]
pub fn dismiss_transfers(ids: Vec<String>, state: State<'_, AppState>) -> AppResult<usize> {
    state.0.ensure_unlocked()?;
    state.0.dismiss_transfer_history(&ids)
}

#[tauri::command]
pub fn clear_transfer_history(state: State<'_, AppState>) -> AppResult<usize> {
    state.0.ensure_unlocked()?;
    state.0.clear_transfer_history()
}

#[tauri::command]
pub fn pause_transfer(id: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.pause(&id)
}

#[tauri::command]
pub fn resume_transfer(id: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.resume(&id)
}

#[tauri::command]
pub fn cancel_transfer(id: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.cancel(&id)
}

#[tauri::command]
pub fn download_file(id: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.spawn_download(id)
}

#[tauri::command]
pub fn start_preview(id: String, state: State<'_, AppState>) -> AppResult<PreviewInfo> {
    state.0.ensure_unlocked()?;
    state.0.start_preview(&id)
}

#[tauri::command]
pub async fn preview_text(token: String, state: State<'_, AppState>) -> AppResult<PreviewText> {
    state.0.ensure_unlocked()?;
    state.0.preview_text(&token).await
}

#[tauri::command]
pub async fn stop_preview(token: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.stop_preview(&token).await
}

#[tauri::command]
pub async fn lookup_share_recipient(
    file_id: String,
    username: String,
    state: State<'_, AppState>,
) -> AppResult<ShareRecipient> {
    state.0.ensure_unlocked()?;
    state.0.lookup_share_recipient(&file_id, &username).await
}

#[tauri::command]
pub async fn recent_share_recipients(
    file_id: String,
    state: State<'_, AppState>,
) -> AppResult<Vec<ShareRecipient>> {
    state.0.ensure_unlocked()?;
    state.0.recent_share_recipients(&file_id).await
}

#[tauri::command]
pub fn share_file(
    file_id: String,
    recipient_token: String,
    allow_decrypt: bool,
    state: State<'_, AppState>,
) -> AppResult<String> {
    state.0.ensure_unlocked()?;
    state
        .0
        .spawn_share(&file_id, &recipient_token, allow_decrypt)
}

#[tauri::command]
pub async fn lookup_folder_share_recipient(
    path: String,
    username: String,
    state: State<'_, AppState>,
) -> AppResult<ShareRecipient> {
    state.0.ensure_unlocked()?;
    state
        .0
        .lookup_folder_share_recipient(&path, &username)
        .await
}

#[tauri::command]
pub async fn recent_folder_share_recipients(
    path: String,
    state: State<'_, AppState>,
) -> AppResult<Vec<ShareRecipient>> {
    state.0.ensure_unlocked()?;
    state.0.recent_folder_share_recipients(&path).await
}

#[tauri::command]
pub fn share_folder(
    path: String,
    recipient_token: String,
    allow_decrypt: bool,
    state: State<'_, AppState>,
) -> AppResult<Vec<String>> {
    state.0.ensure_unlocked()?;
    state
        .0
        .spawn_folder_share(&path, &recipient_token, allow_decrypt)
}

#[tauri::command]
pub fn create_folder(
    parent_path: String,
    name: String,
    state: State<'_, AppState>,
) -> AppResult<VaultFolder> {
    state.0.ensure_unlocked()?;
    state.0.create_folder(&parent_path, &name)
}

#[tauri::command]
pub fn download_folder(path: String, state: State<'_, AppState>) -> AppResult<usize> {
    state.0.ensure_unlocked()?;
    state.0.spawn_folder_download(&path)
}

#[tauri::command]
pub async fn delete_folder(path: String, state: State<'_, AppState>) -> AppResult<usize> {
    state.0.ensure_unlocked()?;
    state.0.move_folder_to_trash(&path).await
}

#[tauri::command]
pub async fn delete_file(id: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.move_to_trash(&id).await
}

#[tauri::command]
pub async fn delete_files(ids: Vec<String>, state: State<'_, AppState>) -> AppResult<usize> {
    state.0.ensure_unlocked()?;
    state.0.move_many_to_trash(&ids).await
}

#[tauri::command]
pub fn restore_file(id: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.restore_from_trash(&id)
}

#[tauri::command]
pub async fn permanently_delete_file(id: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.permanently_delete(&id).await
}

#[tauri::command]
pub async fn permanently_delete_files(
    ids: Vec<String>,
    state: State<'_, AppState>,
) -> AppResult<usize> {
    state.0.ensure_unlocked()?;
    state.0.permanently_delete_many(&ids).await
}

#[tauri::command]
pub async fn empty_trash(state: State<'_, AppState>) -> AppResult<usize> {
    state.0.ensure_unlocked()?;
    state.0.empty_trash().await
}

#[tauri::command]
pub async fn disconnect_account(account_id: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.disconnect_account(&account_id).await
}

#[tauri::command]
pub async fn remove_account(account_id: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.remove_account(&account_id).await
}

#[tauri::command]
pub fn reveal_cached_file(id: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    let path = state
        .0
        .catalog
        .cached_path(&id)?
        .ok_or_else(|| AppError::Message("This file is not available offline".into()))?;
    if !Path::new(&path).exists() {
        return Err(AppError::Message(
            "The cached copy has moved or been deleted".into(),
        ));
    }
    Ok(())
}

#[tauri::command]
pub fn add_watch_folder(
    folder: NewWatchFolder,
    state: State<'_, AppState>,
) -> AppResult<WatchFolder> {
    state.0.ensure_unlocked()?;
    if !Path::new(&folder.path).is_dir() {
        return Err(AppError::Message("Choose a folder to watch".into()));
    }
    let complete = WatchFolder {
        id: uuid::Uuid::new_v4().to_string(),
        path: folder.path,
        enabled: folder.enabled,
        encrypt: folder.encrypt,
        account_id: folder.account_id,
        uploaded_count: 0,
    };
    state.0.catalog.add_watch_folder(&complete)?;
    Ok(complete)
}

#[tauri::command]
pub fn remove_watch_folder(id: String, state: State<'_, AppState>) -> AppResult<()> {
    state.0.ensure_unlocked()?;
    state.0.catalog.remove_watch_folder(&id)
}

#[tauri::command]
pub fn update_settings(settings: Value, state: State<'_, AppState>) -> AppResult<Dashboard> {
    state.0.ensure_unlocked()?;
    let object = settings
        .as_object()
        .ok_or_else(|| AppError::Message("Settings payload is invalid".into()))?;
    for (key, value) in object {
        let (db_key, db_value) = match key.as_str() {
            "speedProfile" => (
                "speed_profile",
                value.as_str().unwrap_or("balanced").to_string(),
            ),
            "cacheLimitGb" => (
                "cache_limit",
                (value.as_u64().unwrap_or(25) * 1024 * 1024 * 1024).to_string(),
            ),
            "previewCacheLimitMb" => (
                "preview_cache_limit",
                (value.as_u64().unwrap_or(512).clamp(128, 512) * 1024 * 1024).to_string(),
            ),
            "previewCacheTtlMinutes" => (
                "preview_cache_ttl_minutes",
                value.as_u64().unwrap_or(15).clamp(5, 60).to_string(),
            ),
            "appLockTimeoutMinutes" => (
                "app_lock_timeout_minutes",
                value.as_u64().unwrap_or(15).clamp(1, 120).to_string(),
            ),
            "recycleRetentionDays" => (
                "recycle_retention_days",
                match value.as_u64().unwrap_or(30) {
                    7 => "7",
                    14 => "14",
                    _ => "30",
                }
                .to_string(),
            ),
            "automaticRetryCount" => (
                "automatic_retry_count",
                value.as_u64().unwrap_or(3).clamp(0, 5).to_string(),
            ),
            "notificationsEnabled" => (
                "notifications_enabled",
                value.as_bool().unwrap_or(false).to_string(),
            ),
            "healthChecksEnabled" => (
                "health_checks_enabled",
                value.as_bool().unwrap_or(true).to_string(),
            ),
            "healthCheckIntervalDays" => (
                "health_check_interval_days",
                value.as_u64().unwrap_or(7).clamp(1, 30).to_string(),
            ),
            "encryptByDefault" => (
                "encrypt_by_default",
                value.as_bool().unwrap_or(true).to_string(),
            ),
            "hideEncryptedNames" => (
                "hide_encrypted_names",
                value.as_bool().unwrap_or(true).to_string(),
            ),
            _ => continue,
        };
        state.0.catalog.set_setting(db_key, db_value)?;
    }
    state
        .0
        .catalog
        .dashboard(state.0.master.is_ready(), state.0.master.keychain_backed())
}

#[tauri::command]
pub async fn start_telegram_login(
    request: LoginRequest,
    state: State<'_, AppState>,
) -> AppResult<LoginResult> {
    state.0.ensure_unlocked()?;
    state.0.telegram.start_login(request).await
}
#[tauri::command]
pub async fn start_telegram_qr_login(
    request: LoginRequest,
    state: State<'_, AppState>,
) -> AppResult<LoginResult> {
    state.0.ensure_unlocked()?;
    state.0.telegram.start_qr_login(request).await
}
#[tauri::command]
pub async fn poll_telegram_qr_login(
    flow_id: String,
    state: State<'_, AppState>,
) -> AppResult<LoginResult> {
    state.0.ensure_unlocked()?;
    state.0.telegram.poll_qr_login(&flow_id).await
}
#[tauri::command]
pub async fn complete_telegram_login(
    flow_id: String,
    code: String,
    state: State<'_, AppState>,
) -> AppResult<LoginResult> {
    state.0.ensure_unlocked()?;
    state.0.telegram.complete_login(&flow_id, &code).await
}
#[tauri::command]
pub async fn complete_telegram_password(
    flow_id: String,
    password: String,
    state: State<'_, AppState>,
) -> AppResult<LoginResult> {
    state.0.ensure_unlocked()?;
    state
        .0
        .telegram
        .complete_password(&flow_id, &password)
        .await
}

#[tauri::command]
pub fn export_recovery_key(state: State<'_, AppState>) -> AppResult<String> {
    state.0.ensure_unlocked()?;
    Ok(state.0.master.export_recovery())
}
