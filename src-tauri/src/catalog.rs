use crate::error::{AppError, AppResult};
use crate::models::{
    Account, AccountCredentials, ChunkRecord, Dashboard, HealthReport, Transfer, VaultFile,
    VaultFolder, VaultManifest, WatchFolder,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

const DEFAULT_CACHE_LIMIT: u64 = 25 * 1024 * 1024 * 1024;
const DEFAULT_PREVIEW_CACHE_LIMIT: u64 = 512 * 1024 * 1024;

#[derive(Clone)]
pub struct Catalog {
    path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FileContext {
    pub id: String,
    pub name: String,
    pub folder_path: String,
    pub source_path: Option<String>,
    pub size: u64,
    pub mime_type: String,
    pub category: String,
    pub encrypted: bool,
    pub account_id: String,
    pub original_sha256: Option<String>,
    pub wrapped_key: Option<String>,
    pub key_nonce: Option<String>,
    pub manifest_message_id: Option<i64>,
    pub duplicate_policy: String,
    pub status: String,
}

impl Catalog {
    pub fn new(path: impl AsRef<Path>) -> AppResult<Self> {
        let catalog = Self {
            path: path.as_ref().to_path_buf(),
        };
        catalog.migrate()?;
        Ok(catalog)
    }

    fn connection(&self) -> AppResult<Connection> {
        let connection = Connection::open(&self.path)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(connection)
    }

    fn migrate(&self) -> AppResult<()> {
        let connection = self.connection()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                api_id INTEGER NOT NULL,
                api_hash TEXT NOT NULL,
                session_path TEXT NOT NULL,
                connected INTEGER NOT NULL DEFAULT 1,
                color TEXT NOT NULL DEFAULT '#2f7cff',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vault_files (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                source_path TEXT,
                category TEXT NOT NULL,
                size INTEGER NOT NULL,
                mime_type TEXT NOT NULL,
                encrypted INTEGER NOT NULL,
                cached INTEGER NOT NULL DEFAULT 0,
                cache_path TEXT,
                chunk_count INTEGER NOT NULL DEFAULT 1,
                account_id TEXT NOT NULL REFERENCES accounts(id),
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'uploading',
                original_sha256 TEXT,
                wrapped_key TEXT,
                key_nonce TEXT,
                manifest_message_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS chunks (
                file_id TEXT NOT NULL REFERENCES vault_files(id) ON DELETE CASCADE,
                chunk_index INTEGER NOT NULL,
                message_id INTEGER NOT NULL,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                PRIMARY KEY(file_id, chunk_index)
            );
            CREATE TABLE IF NOT EXISTS vault_folders (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transfers (
                id TEXT PRIMARY KEY,
                file_id TEXT REFERENCES vault_files(id) ON DELETE CASCADE,
                file_name TEXT NOT NULL,
                direction TEXT NOT NULL,
                state TEXT NOT NULL,
                progress REAL NOT NULL DEFAULT 0,
                transferred INTEGER NOT NULL DEFAULT 0,
                total INTEGER NOT NULL,
                speed INTEGER NOT NULL DEFAULT 0,
                eta_seconds INTEGER,
                message TEXT,
                encrypted INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS watch_folders (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                encrypt INTEGER NOT NULL DEFAULT 1,
                account_id TEXT NOT NULL REFERENCES accounts(id),
                uploaded_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS watch_seen (
                watch_id TEXT NOT NULL REFERENCES watch_folders(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                size INTEGER NOT NULL,
                modified INTEGER NOT NULL,
                PRIMARY KEY(watch_id, path)
            );",
        )?;
        if !column_exists(&connection, "vault_files", "folder_path")? {
            connection.execute(
                "ALTER TABLE vault_files ADD COLUMN folder_path TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        if !column_exists(&connection, "vault_files", "duplicate_policy")? {
            connection.execute(
                "ALTER TABLE vault_files ADD COLUMN duplicate_policy TEXT NOT NULL DEFAULT 'skip'",
                [],
            )?;
        }
        for (column, definition) in [
            ("favorite", "INTEGER NOT NULL DEFAULT 0"),
            ("tags_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("last_opened_at", "TEXT"),
            ("deleted_at", "TEXT"),
            ("purge_at", "TEXT"),
        ] {
            if !column_exists(&connection, "vault_files", column)? {
                connection.execute(
                    &format!("ALTER TABLE vault_files ADD COLUMN {column} {definition}"),
                    [],
                )?;
            }
        }
        let existing_paths = {
            let mut statement = connection
                .prepare("SELECT DISTINCT folder_path FROM vault_files WHERE folder_path!=''")?;
            let paths = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            paths
        };
        for path in existing_paths {
            ensure_vault_folder_path_with(&connection, &path)?;
        }
        connection.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES('cache_limit', ?1)",
            [DEFAULT_CACHE_LIMIT.to_string()],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES('speed_profile', 'balanced')",
            [],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES('encrypt_by_default', 'true')",
            [],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES('hide_encrypted_names', 'true')",
            [],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES('preview_cache_limit', ?1)",
            [DEFAULT_PREVIEW_CACHE_LIMIT.to_string()],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES('preview_cache_ttl_minutes', '15')",
            [],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES('app_lock_timeout_minutes', '15')",
            [],
        )?;
        for (key, value) in [
            ("recycle_retention_days", "30"),
            ("automatic_retry_count", "3"),
            ("notifications_enabled", "false"),
            ("health_checks_enabled", "true"),
            ("health_check_interval_days", "7"),
        ] {
            connection.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES(?1,?2)",
                params![key, value],
            )?;
        }
        connection.execute("UPDATE transfers SET state='failed', message='Sharing was interrupted by restart — start sharing again' WHERE direction='share' AND state IN ('queued','preparing','uploading','downloading','waiting','paused')", [])?;
        connection.execute("UPDATE transfers SET state='paused', message='Interrupted by restart — ready to resume' WHERE direction!='share' AND state IN ('preparing','uploading','downloading','waiting')", [])?;
        Ok(())
    }

    pub fn dashboard(&self, encryption_ready: bool, keychain_backed: bool) -> AppResult<Dashboard> {
        let connection = self.connection()?;
        let files = {
            let mut statement = connection.prepare(
                "SELECT f.id,f.name,COALESCE(f.folder_path,''),f.category,f.size,f.mime_type,f.encrypted,f.cached,f.chunk_count,
                        f.account_id,a.name,f.created_at,f.status,f.favorite,f.tags_json,f.last_opened_at,f.deleted_at,f.purge_at
                 FROM vault_files f JOIN accounts a ON a.id=f.account_id
                 ORDER BY f.created_at DESC"
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok(VaultFile {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        folder_path: row.get(2)?,
                        category: row.get(3)?,
                        size: row.get::<_, i64>(4)? as u64,
                        mime_type: row.get(5)?,
                        encrypted: row.get::<_, i64>(6)? != 0,
                        cached: row.get::<_, i64>(7)? != 0,
                        chunk_count: row.get::<_, i64>(8)? as u32,
                        account_id: row.get(9)?,
                        account_name: row.get(10)?,
                        created_at: row.get(11)?,
                        status: row.get(12)?,
                        thumbnail: None,
                        favorite: row.get::<_, i64>(13)? != 0,
                        tags: serde_json::from_str(&row.get::<_, String>(14)?).unwrap_or_default(),
                        last_opened_at: row.get(15)?,
                        deleted_at: row.get(16)?,
                        purge_at: row.get(17)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let transfers = {
            let mut statement = connection.prepare(
                "SELECT id,file_id,file_name,direction,state,progress,transferred,total,speed,eta_seconds,message,encrypted
                 FROM transfers ORDER BY CASE WHEN state IN ('complete','failed') THEN 1 ELSE 0 END, updated_at DESC LIMIT 100"
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok(Transfer {
                        id: row.get(0)?,
                        file_id: row.get(1)?,
                        file_name: row.get(2)?,
                        direction: row.get(3)?,
                        state: row.get(4)?,
                        progress: row.get(5)?,
                        transferred: row.get::<_, i64>(6)? as u64,
                        total: row.get::<_, i64>(7)? as u64,
                        speed: row.get::<_, i64>(8)? as u64,
                        eta_seconds: row.get::<_, Option<i64>>(9)?.map(|x| x as u64),
                        message: row.get(10)?,
                        encrypted: row.get::<_, i64>(11)? != 0,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let folders = self.vault_folders_with(&connection)?;
        let accounts = {
            let mut statement = connection.prepare(
                "SELECT a.id,a.name,a.phone,a.connected,a.color,
                        SUM(CASE WHEN f.status!='trashed' THEN 1 ELSE 0 END),COALESCE(SUM(CASE WHEN f.status='ready' THEN f.size ELSE 0 END),0)
                 FROM accounts a LEFT JOIN vault_files f ON f.account_id=a.id GROUP BY a.id ORDER BY a.created_at"
            )?;
            let rows = statement
                .query_map([], |row| {
                    let name: String = row.get(1)?;
                    Ok(Account {
                        id: row.get(0)?,
                        initials: initials(&name),
                        name,
                        phone: mask_phone(&row.get::<_, String>(2)?),
                        connected: row.get::<_, i64>(3)? != 0,
                        color: row.get(4)?,
                        file_count: row.get::<_, i64>(5)? as u64,
                        stored_bytes: row.get::<_, i64>(6)? as u64,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let watch_folders = self.watch_folders_with(&connection)?;
        let stored_bytes = files
            .iter()
            .filter(|f| f.status == "ready")
            .map(|f| f.size)
            .sum();
        let cache_used = connection.query_row(
            "SELECT COALESCE(SUM(size),0) FROM vault_files WHERE cache_path IS NOT NULL",
            [],
            |row| row.get::<_, i64>(0),
        )? as u64;
        let cache_limit = self
            .setting_with(&connection, "cache_limit")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_CACHE_LIMIT);
        let preview_cache_limit = self
            .setting_with(&connection, "preview_cache_limit")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_PREVIEW_CACHE_LIMIT);
        let preview_cache_ttl_minutes = self
            .setting_with(&connection, "preview_cache_ttl_minutes")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(15);
        let app_lock_enabled = self.setting_with(&connection, "app_lock_hash")?.is_some();
        let app_lock_timeout_minutes = self
            .setting_with(&connection, "app_lock_timeout_minutes")?
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(15);
        let speed_profile = self
            .setting_with(&connection, "speed_profile")?
            .unwrap_or_else(|| "balanced".into());
        let recycle_retention_days = setting_u64(&connection, "recycle_retention_days", 30);
        let automatic_retry_count = setting_u64(&connection, "automatic_retry_count", 3);
        let notifications_enabled = setting_bool(&connection, "notifications_enabled", false);
        let health_checks_enabled = setting_bool(&connection, "health_checks_enabled", true);
        let health_check_interval_days = setting_u64(&connection, "health_check_interval_days", 7);
        let latest_health_report = self
            .setting_with(&connection, "latest_health_report")?
            .and_then(|json| serde_json::from_str::<HealthReport>(&json).ok());
        Ok(Dashboard {
            files,
            folders,
            transfers,
            accounts,
            watch_folders,
            cache_used,
            cache_limit,
            preview_cache_limit,
            preview_cache_ttl_minutes,
            stored_bytes,
            encryption_ready,
            keychain_backed,
            app_lock_enabled,
            app_lock_timeout_minutes,
            speed_profile,
            recycle_retention_days,
            automatic_retry_count,
            notifications_enabled,
            health_checks_enabled,
            health_check_interval_days,
            latest_health_report,
            automatic_updates_configured: option_env!("TELEVAULT_UPDATE_PUBLIC_KEY").is_some()
                && option_env!("TELEVAULT_UPDATE_ENDPOINT").is_some(),
        })
    }

    pub fn set_setting(&self, key: &str, value: impl ToString) -> AppResult<()> {
        self.connection()?.execute(
            "INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value.to_string()]
        )?;
        Ok(())
    }

    pub fn setting(&self, key: &str) -> AppResult<Option<String>> {
        let connection = self.connection()?;
        self.setting_with(&connection, key)
    }

    pub fn delete_setting(&self, key: &str) -> AppResult<()> {
        self.connection()?
            .execute("DELETE FROM settings WHERE key=?1", [key])?;
        Ok(())
    }

    pub fn set_favorite(&self, file_id: &str, favorite: bool) -> AppResult<()> {
        self.connection()?.execute(
            "UPDATE vault_files SET favorite=?2 WHERE id=?1 AND status='ready'",
            params![file_id, favorite as i64],
        )?;
        Ok(())
    }

    pub fn set_tags(&self, file_id: &str, tags: &[String]) -> AppResult<()> {
        self.connection()?.execute(
            "UPDATE vault_files SET tags_json=?2 WHERE id=?1 AND status='ready'",
            params![file_id, serde_json::to_string(tags)?],
        )?;
        Ok(())
    }

    pub fn touch_file(&self, file_id: &str) -> AppResult<()> {
        self.connection()?.execute(
            "UPDATE vault_files SET last_opened_at=?2 WHERE id=?1 AND status='ready'",
            params![file_id, now()],
        )?;
        Ok(())
    }

    pub fn trash_file(&self, file_id: &str, retention_days: u64) -> AppResult<Option<String>> {
        let connection = self.connection()?;
        let cached_path = connection
            .query_row(
                "SELECT cache_path FROM vault_files WHERE id=?1 AND status='ready'",
                [file_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        let deleted_at = chrono::Utc::now();
        let purge_at = deleted_at + chrono::Duration::days(retention_days.clamp(7, 30) as i64);
        let changed = connection.execute(
            "UPDATE vault_files SET status='trashed',deleted_at=?2,purge_at=?3,cached=0,cache_path=NULL WHERE id=?1 AND status='ready'",
            params![file_id, deleted_at.to_rfc3339(), purge_at.to_rfc3339()],
        )?;
        if changed == 0 {
            return Err(AppError::Message(
                "Only stored files can be moved to the Recycle Bin".into(),
            ));
        }
        Ok(cached_path)
    }

    pub fn restore_file(&self, file_id: &str) -> AppResult<()> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let folder_path = transaction
            .query_row(
                "SELECT folder_path FROM vault_files WHERE id=?1 AND status='trashed'",
                [file_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| AppError::Message("The file is not in the Recycle Bin".into()))?;
        ensure_vault_folder_path_with(&transaction, &folder_path)?;
        transaction.execute(
            "UPDATE vault_files SET status='ready',deleted_at=NULL,purge_at=NULL WHERE id=?1",
            [file_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn expired_trash_ids(&self) -> AppResult<Vec<String>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id FROM vault_files WHERE status='trashed' AND purge_at<=?1 ORDER BY purge_at",
        )?;
        let ids = statement
            .query_map([now()], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    pub fn trashed_file_ids(&self) -> AppResult<Vec<String>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare("SELECT id FROM vault_files WHERE status='trashed' ORDER BY deleted_at")?;
        let ids = statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    pub fn ensure_vault_folder_path(&self, path: &str) -> AppResult<()> {
        if path.is_empty() {
            return Ok(());
        }
        let connection = self.connection()?;
        ensure_vault_folder_path_with(&connection, path)
    }

    pub fn create_vault_folder(&self, path: &str) -> AppResult<VaultFolder> {
        if self.vault_folder_exists(path)? {
            return Err(AppError::Message(format!(
                "A folder named '{}' already exists here",
                path.rsplit('/').next().unwrap_or(path)
            )));
        }
        self.ensure_vault_folder_path(path)?;
        self.connection()?
            .query_row(
                "SELECT id,path,created_at FROM vault_folders WHERE path=?1",
                [path],
                map_vault_folder,
            )
            .map_err(Into::into)
    }

    pub fn vault_folder_exists(&self, path: &str) -> AppResult<bool> {
        let connection = self.connection()?;
        let folder_exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_folders WHERE path=?1)",
            [path],
            |row| row.get::<_, i64>(0),
        )? != 0;
        if folder_exists {
            return Ok(true);
        }
        Ok(connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM vault_files
                WHERE status!='trashed' AND (folder_path=?1 OR substr(folder_path,1,length(?1)+1)=?1||'/')
            )",
            [path],
            |row| row.get::<_, i64>(0),
        )? != 0)
    }

    pub fn ready_file_ids_in_folder(&self, path: &str) -> AppResult<Vec<String>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id FROM vault_files
             WHERE status='ready' AND (folder_path=?1 OR substr(folder_path,1,length(?1)+1)=?1||'/')
             ORDER BY created_at",
        )?;
        let ids = statement
            .query_map([path], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    pub fn active_file_count_in_folder(&self, path: &str) -> AppResult<u64> {
        Ok(self.connection()?.query_row(
            "SELECT COUNT(*) FROM vault_files
             WHERE status NOT IN ('ready','trashed') AND (folder_path=?1 OR substr(folder_path,1,length(?1)+1)=?1||'/')",
            [path],
            |row| row.get::<_, i64>(0),
        )? as u64)
    }

    pub fn active_transfer_count_for_file(&self, file_id: &str) -> AppResult<u64> {
        Ok(self.connection()?.query_row(
            "SELECT COUNT(*) FROM transfers WHERE file_id=?1 AND state NOT IN ('complete','failed')",
            [file_id],
            |row| row.get::<_, i64>(0),
        )? as u64)
    }

    pub fn folder_paths_in_tree(&self, path: &str) -> AppResult<Vec<String>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT path FROM vault_folders
             WHERE path=?1 OR substr(path,1,length(?1)+1)=?1||'/'
             ORDER BY length(path),path",
        )?;
        let paths = statement
            .query_map([path], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(paths)
    }

    pub fn delete_vault_folder_tree(&self, path: &str) -> AppResult<()> {
        self.connection()?.execute(
            "DELETE FROM vault_folders
             WHERE path=?1 OR substr(path,1,length(?1)+1)=?1||'/'",
            [path],
        )?;
        Ok(())
    }

    fn vault_folders_with(&self, connection: &Connection) -> AppResult<Vec<VaultFolder>> {
        let mut statement = connection
            .prepare("SELECT id,path,created_at FROM vault_folders ORDER BY path COLLATE NOCASE")?;
        let folders = statement
            .query_map([], map_vault_folder)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(folders)
    }

    fn setting_with(&self, connection: &Connection, key: &str) -> AppResult<Option<String>> {
        Ok(connection
            .query_row("SELECT value FROM settings WHERE key=?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn insert_account(&self, credentials: &AccountCredentials) -> AppResult<()> {
        let color = account_color(&credentials.id);
        self.connection()?.execute(
            "INSERT INTO accounts(id,name,phone,api_id,api_hash,session_path,connected,color,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,1,?7,?8)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name,phone=excluded.phone,api_id=excluded.api_id,api_hash=excluded.api_hash,session_path=excluded.session_path,connected=1",
            params![credentials.id, credentials.name, credentials.phone, credentials.api_id, credentials.api_hash, credentials.session_path, color, now()]
        )?;
        Ok(())
    }

    pub fn set_account_connected(&self, id: &str, connected: bool) -> AppResult<()> {
        self.connection()?.execute(
            "UPDATE accounts SET connected=?2 WHERE id=?1",
            params![id, connected as i64],
        )?;
        Ok(())
    }

    pub fn active_transfer_count_for_account(&self, account_id: &str) -> AppResult<u64> {
        Ok(self.connection()?.query_row(
            "SELECT COUNT(*) FROM transfers t JOIN vault_files f ON f.id=t.file_id
             WHERE f.account_id=?1 AND t.state NOT IN ('complete','failed')",
            [account_id],
            |row| row.get::<_, i64>(0),
        )? as u64)
    }

    pub fn remove_account_local(&self, account_id: &str) -> AppResult<()> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "DELETE FROM watch_folders WHERE account_id=?1",
            [account_id],
        )?;
        transaction.execute(
            "DELETE FROM transfers WHERE file_id IN (SELECT id FROM vault_files WHERE account_id=?1)",
            [account_id],
        )?;
        transaction.execute("DELETE FROM vault_files WHERE account_id=?1", [account_id])?;
        let changed = transaction.execute("DELETE FROM accounts WHERE id=?1", [account_id])?;
        if changed == 0 {
            return Err(AppError::Message("Telegram account was not found".into()));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn account_credentials(&self, id: &str) -> AppResult<AccountCredentials> {
        self.connection()?
            .query_row(
                "SELECT id,name,phone,api_id,api_hash,session_path FROM accounts WHERE id=?1",
                [id],
                |row| {
                    Ok(AccountCredentials {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        phone: row.get(2)?,
                        api_id: row.get(3)?,
                        api_hash: row.get(4)?,
                        session_path: row.get(5)?,
                    })
                },
            )
            .map_err(AppError::from)
    }

    pub fn insert_queued_file(
        &self,
        file: &VaultFile,
        source_path: &str,
        transfer_id: &str,
        duplicate_policy: &str,
    ) -> AppResult<()> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO vault_files(id,name,folder_path,source_path,category,size,mime_type,encrypted,cached,chunk_count,account_id,created_at,status,duplicate_policy)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1,?9,?10,?11,'uploading',?12)",
            params![file.id,file.name,file.folder_path,source_path,file.category,file.size as i64,file.mime_type,file.encrypted as i64,file.chunk_count as i64,file.account_id,file.created_at,duplicate_policy]
        )?;
        transaction.execute(
            "INSERT INTO transfers(id,file_id,file_name,direction,state,progress,transferred,total,speed,encrypted,created_at,updated_at)
             VALUES(?1,?2,?3,'upload','queued',0,0,?4,0,?5,?6,?6)",
            params![transfer_id,file.id,file.name,file.size as i64,file.encrypted as i64,now()]
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn file_context(&self, id: &str) -> AppResult<FileContext> {
        self.connection()?.query_row(
            "SELECT id,name,COALESCE(folder_path,''),source_path,size,mime_type,category,encrypted,account_id,original_sha256,wrapped_key,key_nonce,manifest_message_id,duplicate_policy,status FROM vault_files WHERE id=?1",
            [id], |row| Ok(FileContext { id: row.get(0)?, name: row.get(1)?, folder_path: row.get(2)?, source_path: row.get(3)?, size: row.get::<_,i64>(4)? as u64,
                mime_type: row.get(5)?, category: row.get(6)?, encrypted: row.get::<_,i64>(7)? != 0, account_id: row.get(8)?,
                original_sha256: row.get(9)?, wrapped_key: row.get(10)?, key_nonce: row.get(11)?, manifest_message_id: row.get(12)?, duplicate_policy: row.get(13)?, status: row.get(14)? })
        ).map_err(AppError::from)
    }

    pub fn sample_ready_files(&self, account_id: &str, limit: u64) -> AppResult<Vec<FileContext>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id FROM vault_files WHERE account_id=?1 AND status='ready'
             ORDER BY RANDOM() LIMIT ?2",
        )?;
        let ids = statement
            .query_map(params![account_id, limit.clamp(1, 25) as i64], |row| {
                row.get(0)
            })?
            .collect::<Result<Vec<String>, _>>()?;
        ids.iter().map(|id| self.file_context(id)).collect()
    }

    pub fn file_exists(&self, id: &str) -> AppResult<bool> {
        Ok(self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_files WHERE id=?1)",
            [id],
            |row| row.get::<_, i64>(0),
        )? != 0)
    }

    pub fn duplicate_by_hash(
        &self,
        account_id: &str,
        size: u64,
        sha256: &str,
        excluding_id: &str,
    ) -> AppResult<Option<String>> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT name FROM vault_files
             WHERE account_id=?1 AND size=?2 AND original_sha256=?3 AND id!=?4 AND status='ready'
             ORDER BY created_at LIMIT 1",
                params![account_id, size as i64, sha256, excluding_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn has_duplicate_size(
        &self,
        account_id: &str,
        size: u64,
        excluding_id: &str,
    ) -> AppResult<bool> {
        Ok(self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_files WHERE account_id=?1 AND size=?2 AND id!=?3 AND status='ready' AND original_sha256 IS NOT NULL)",
            params![account_id, size as i64, excluding_id],
            |row| row.get::<_, i64>(0),
        )? != 0)
    }

    pub fn mark_duplicate_skipped(
        &self,
        file_id: &str,
        transfer_id: &str,
        existing_name: &str,
    ) -> AppResult<()> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE transfers SET file_id=NULL,state='failed',progress=0,speed=0,message=?2,updated_at=?3 WHERE id=?1",
            params![transfer_id, format!("Skipped exact duplicate of {existing_name}"), now()],
        )?;
        transaction.execute("DELETE FROM vault_files WHERE id=?1", [file_id])?;
        transaction.commit()?;
        Ok(())
    }

    pub fn update_file_metadata(
        &self,
        file_id: &str,
        name: &str,
        folder_path: &str,
        mime_type: &str,
        category: &str,
        manifest_message_id: i64,
    ) -> AppResult<()> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        ensure_vault_folder_path_with(&transaction, folder_path)?;
        transaction.execute(
            "UPDATE vault_files SET name=?2,folder_path=?3,mime_type=?4,category=?5,manifest_message_id=?6 WHERE id=?1",
            params![file_id, name, folder_path, mime_type, category, manifest_message_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn insert_copy(
        &self,
        source: &FileContext,
        new_id: &str,
        name: &str,
        folder_path: &str,
        manifest_message_id: i64,
    ) -> AppResult<()> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        ensure_vault_folder_path_with(&transaction, folder_path)?;
        transaction.execute(
            "INSERT INTO vault_files(id,name,folder_path,source_path,category,size,mime_type,encrypted,cached,cache_path,chunk_count,account_id,created_at,status,original_sha256,wrapped_key,key_nonce,manifest_message_id)
             SELECT ?2,?3,?4,NULL,category,size,mime_type,encrypted,0,NULL,chunk_count,account_id,?5,'ready',original_sha256,wrapped_key,key_nonce,?6
             FROM vault_files WHERE id=?1",
            params![source.id, new_id, name, folder_path, now(), manifest_message_id],
        )?;
        transaction.execute(
            "INSERT INTO chunks(file_id,chunk_index,message_id,size,sha256)
             SELECT ?2,chunk_index,message_id,size,sha256 FROM chunks WHERE file_id=?1",
            params![source.id, new_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn recover_manifest(
        &self,
        account_id: &str,
        manifest_message_id: i64,
        manifest: &VaultManifest,
        name: &str,
        folder_path: &str,
        mime_type: &str,
        category: &str,
    ) -> AppResult<()> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        ensure_vault_folder_path_with(&transaction, folder_path)?;
        transaction.execute(
            "INSERT INTO vault_files(id,name,folder_path,source_path,category,size,mime_type,encrypted,cached,cache_path,chunk_count,account_id,created_at,status,original_sha256,wrapped_key,key_nonce,manifest_message_id)
             VALUES(?1,?2,?3,NULL,?4,?5,?6,?7,0,NULL,?8,?9,?10,'ready',?11,?12,?13,?14)",
            params![manifest.file_id,name,folder_path,category,manifest.original_size as i64,mime_type,manifest.encrypted as i64,manifest.chunks.len() as i64,account_id,manifest.created_at,manifest.original_sha256,manifest.wrapped_key,manifest.key_nonce,manifest_message_id],
        )?;
        for chunk in &manifest.chunks {
            transaction.execute(
                "INSERT INTO chunks(file_id,chunk_index,message_id,size,sha256) VALUES(?1,?2,?3,?4,?5)",
                params![manifest.file_id,chunk.index as i64,chunk.message_id,chunk.size as i64,chunk.sha256],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn set_prepared(
        &self,
        file_id: &str,
        original_sha256: &str,
        chunk_count: u32,
        wrapped_key: Option<&str>,
        key_nonce: Option<&str>,
    ) -> AppResult<()> {
        self.connection()?.execute(
            "UPDATE vault_files SET original_sha256=?2,chunk_count=?3,wrapped_key=?4,key_nonce=?5 WHERE id=?1",
            params![file_id,original_sha256,chunk_count as i64,wrapped_key,key_nonce]
        )?;
        Ok(())
    }

    pub fn add_chunk(&self, file_id: &str, chunk: &ChunkRecord) -> AppResult<()> {
        self.connection()?.execute(
            "INSERT INTO chunks(file_id,chunk_index,message_id,size,sha256) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(file_id,chunk_index) DO UPDATE SET message_id=excluded.message_id,size=excluded.size,sha256=excluded.sha256",
            params![file_id,chunk.index as i64,chunk.message_id,chunk.size as i64,chunk.sha256]
        )?;
        Ok(())
    }

    pub fn chunks(&self, file_id: &str) -> AppResult<Vec<ChunkRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT chunk_index,message_id,size,sha256 FROM chunks WHERE file_id=?1 ORDER BY chunk_index")?;
        let rows = statement
            .query_map([file_id], |row| {
                Ok(ChunkRecord {
                    index: row.get::<_, i64>(0)? as u32,
                    message_id: row.get(1)?,
                    size: row.get::<_, i64>(2)? as u64,
                    sha256: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn set_manifest_and_complete(
        &self,
        file_id: &str,
        transfer_id: &str,
        manifest_message_id: i64,
    ) -> AppResult<()> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE vault_files SET status='ready',manifest_message_id=?2 WHERE id=?1",
            params![file_id, manifest_message_id],
        )?;
        transaction.execute("UPDATE transfers SET state='complete',progress=1,transferred=total,speed=0,eta_seconds=0,message='Integrity verified',updated_at=?2 WHERE id=?1", params![transfer_id,now()])?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_transfer(
        &self,
        id: &str,
        state: &str,
        progress: f64,
        transferred: u64,
        speed: u64,
        eta: Option<u64>,
        message: Option<&str>,
    ) -> AppResult<()> {
        self.connection()?.execute(
            "UPDATE transfers SET state=?2,progress=?3,transferred=?4,speed=?5,eta_seconds=?6,message=?7,updated_at=?8 WHERE id=?1",
            params![id,state,progress,transferred as i64,speed as i64,eta.map(|x|x as i64),message,now()]
        )?;
        Ok(())
    }

    pub fn transfer_file_id(&self, transfer_id: &str) -> AppResult<String> {
        self.connection()?
            .query_row(
                "SELECT file_id FROM transfers WHERE id=?1",
                [transfer_id],
                |row| row.get(0),
            )
            .map_err(AppError::from)
    }

    pub fn transfer_direction(&self, transfer_id: &str) -> AppResult<String> {
        self.connection()?
            .query_row(
                "SELECT direction FROM transfers WHERE id=?1",
                [transfer_id],
                |row| row.get(0),
            )
            .map_err(AppError::from)
    }

    pub fn transfer_state(&self, transfer_id: &str) -> AppResult<String> {
        self.connection()?
            .query_row(
                "SELECT state FROM transfers WHERE id=?1",
                [transfer_id],
                |row| row.get(0),
            )
            .map_err(AppError::from)
    }

    pub fn remove_transfer(&self, transfer_id: &str) -> AppResult<()> {
        self.connection()?
            .execute("DELETE FROM transfers WHERE id=?1", [transfer_id])?;
        Ok(())
    }

    pub fn history_transfer_ids(&self) -> AppResult<Vec<String>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id FROM transfers WHERE state IN ('complete','failed') ORDER BY updated_at DESC",
        )?;
        let ids = statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    pub fn set_file_status(&self, file_id: &str, status: &str) -> AppResult<()> {
        self.connection()?.execute(
            "UPDATE vault_files SET status=?2 WHERE id=?1",
            params![file_id, status],
        )?;
        Ok(())
    }

    pub fn set_transfer_state(
        &self,
        id: &str,
        state: &str,
        message: Option<&str>,
    ) -> AppResult<()> {
        self.connection()?.execute(
            "UPDATE transfers SET state=?2,message=?3,updated_at=?4 WHERE id=?1",
            params![id, state, message, now()],
        )?;
        Ok(())
    }

    pub fn fail_transfer(&self, transfer_id: &str, message: &str) -> AppResult<()> {
        let connection = self.connection()?;
        connection.execute(
            "UPDATE transfers SET state='failed',message=?2,speed=0,updated_at=?3 WHERE id=?1",
            params![transfer_id, message, now()],
        )?;
        connection.execute("UPDATE vault_files SET status='missing' WHERE id=(SELECT file_id FROM transfers WHERE id=?1) AND status='uploading'", [transfer_id])?;
        Ok(())
    }

    pub fn create_download_transfer(&self, file: &FileContext) -> AppResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        self.connection()?.execute(
            "INSERT INTO transfers(id,file_id,file_name,direction,state,progress,transferred,total,speed,encrypted,created_at,updated_at)
             VALUES(?1,?2,?3,'download','queued',0,0,?4,0,?5,?6,?6)",
            params![id,file.id,file.name,file.size as i64,file.encrypted as i64,now()]
        )?;
        Ok(id)
    }

    pub fn create_share_transfer(&self, file: &FileContext, recipient: &str) -> AppResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        self.connection()?.execute(
            "INSERT INTO transfers(id,file_id,file_name,direction,state,progress,transferred,total,speed,message,encrypted,created_at,updated_at)
             VALUES(?1,?2,?3,'share','queued',0,0,?4,0,?5,?6,?7,?7)",
            params![
                id,
                file.id,
                file.name,
                file.size as i64,
                format!("Preparing to send to {recipient}"),
                file.encrypted as i64,
                now()
            ],
        )?;
        Ok(id)
    }

    pub fn set_cached(&self, file_id: &str, path: &str) -> AppResult<()> {
        self.connection()?.execute(
            "UPDATE vault_files SET cached=1,cache_path=?2,status='ready' WHERE id=?1",
            params![file_id, path],
        )?;
        Ok(())
    }

    pub fn cached_path(&self, file_id: &str) -> AppResult<Option<String>> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT cache_path FROM vault_files WHERE id=?1",
                [file_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten())
    }

    pub fn message_ids_for_delete(&self, file_id: &str) -> AppResult<Vec<i64>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT c.message_id FROM chunks c JOIN vault_files owner ON owner.id=c.file_id
             WHERE c.file_id=?1 AND NOT EXISTS(
               SELECT 1 FROM chunks other JOIN vault_files other_owner ON other_owner.id=other.file_id
               WHERE other.message_id=c.message_id AND other.file_id!=c.file_id AND other_owner.account_id=owner.account_id
             ) ORDER BY c.chunk_index",
        )?;
        let mut ids = statement
            .query_map([file_id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(id) = connection
            .query_row(
                "SELECT manifest_message_id FROM vault_files WHERE id=?1",
                [file_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten()
        {
            ids.push(id);
        }
        Ok(ids)
    }

    pub fn permanent_delete_local(&self, file_id: &str) -> AppResult<()> {
        self.connection()?
            .execute("DELETE FROM vault_files WHERE id=?1", [file_id])?;
        Ok(())
    }

    pub fn add_watch_folder(&self, folder: &WatchFolder) -> AppResult<()> {
        self.connection()?.execute(
            "INSERT INTO watch_folders(id,path,enabled,encrypt,account_id,uploaded_count,created_at) VALUES(?1,?2,?3,?4,?5,0,?6)",
            params![folder.id,folder.path,folder.enabled as i64,folder.encrypt as i64,folder.account_id,now()]
        )?;
        Ok(())
    }

    pub fn remove_watch_folder(&self, id: &str) -> AppResult<()> {
        self.connection()?
            .execute("DELETE FROM watch_folders WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn watch_folders(&self) -> AppResult<Vec<WatchFolder>> {
        let connection = self.connection()?;
        self.watch_folders_with(&connection)
    }

    pub fn watch_seen(
        &self,
        watch_id: &str,
        path: &str,
        size: u64,
        modified: i64,
    ) -> AppResult<bool> {
        let connection = self.connection()?;
        Ok(connection.query_row(
            "SELECT 1 FROM watch_seen WHERE watch_id=?1 AND path=?2 AND size=?3 AND modified=?4",
            params![watch_id,path,size as i64,modified], |_| Ok(())
        ).optional()?.is_some())
    }

    pub fn mark_watch_seen(
        &self,
        watch_id: &str,
        path: &str,
        size: u64,
        modified: i64,
    ) -> AppResult<()> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO watch_seen(watch_id,path,size,modified) VALUES(?1,?2,?3,?4)
             ON CONFLICT(watch_id,path) DO UPDATE SET size=excluded.size,modified=excluded.modified",
            params![watch_id,path,size as i64,modified]
        )?;
        transaction.execute(
            "UPDATE watch_folders SET uploaded_count=uploaded_count+1 WHERE id=?1",
            [watch_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn watch_folders_with(&self, connection: &Connection) -> AppResult<Vec<WatchFolder>> {
        let mut statement = connection.prepare("SELECT id,path,enabled,encrypt,account_id,uploaded_count FROM watch_folders ORDER BY created_at")?;
        let rows = statement
            .query_map([], |row| {
                Ok(WatchFolder {
                    id: row.get(0)?,
                    path: row.get(1)?,
                    enabled: row.get::<_, i64>(2)? != 0,
                    encrypt: row.get::<_, i64>(3)? != 0,
                    account_id: row.get(4)?,
                    uploaded_count: row.get::<_, i64>(5)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

fn column_exists(connection: &Connection, table: &str, column: &str) -> AppResult<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(columns.iter().any(|name| name == column))
}

fn ensure_vault_folder_path_with(connection: &Connection, path: &str) -> AppResult<()> {
    let mut current = String::new();
    for component in path.split('/').filter(|part| !part.is_empty()) {
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(component);
        connection.execute(
            "INSERT OR IGNORE INTO vault_folders(id,path,created_at) VALUES(?1,?2,?3)",
            params![uuid::Uuid::new_v4().to_string(), current, now()],
        )?;
    }
    Ok(())
}

fn map_vault_folder(row: &rusqlite::Row<'_>) -> rusqlite::Result<VaultFolder> {
    let path: String = row.get(1)?;
    Ok(VaultFolder {
        id: row.get(0)?,
        name: path.rsplit('/').next().unwrap_or(&path).to_string(),
        path,
        created_at: row.get(2)?,
    })
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn setting_u64(connection: &Connection, key: &str, fallback: u64) -> u64 {
    connection
        .query_row("SELECT value FROM settings WHERE key=?1", [key], |row| {
            row.get::<_, String>(0)
        })
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}
fn setting_bool(connection: &Connection, key: &str, fallback: bool) -> bool {
    connection
        .query_row("SELECT value FROM settings WHERE key=?1", [key], |row| {
            row.get::<_, String>(0)
        })
        .ok()
        .map(|value| value == "true")
        .unwrap_or(fallback)
}
fn mask_phone(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    if chars.len() <= 4 {
        return "••••".into();
    }
    format!(
        "{} •••• {}",
        chars[0],
        chars[chars.len() - 4..].iter().collect::<String>()
    )
}
fn initials(name: &str) -> String {
    name.split_whitespace()
        .filter_map(|part| part.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase()
}
fn account_color(id: &str) -> &'static str {
    const COLORS: &[&str] = &["#2f7cff", "#7657e8", "#e85b75", "#16a77b", "#e28b27"];
    COLORS[id.bytes().fold(0usize, |a, b| a + b as usize) % COLORS.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_account(catalog: &Catalog) {
        catalog
            .insert_account(&AccountCredentials {
                id: "account-1".into(),
                name: "Personal".into(),
                phone: "+440000000000".into(),
                api_id: 12345,
                api_hash: "test-hash".into(),
                session_path: "/tmp/test-session".into(),
            })
            .unwrap();
    }

    #[test]
    fn virtual_folders_persist_with_empty_nested_children() {
        let temp = tempfile::tempdir().unwrap();
        let catalog = Catalog::new(temp.path().join("catalog.sqlite3")).unwrap();

        let created = catalog
            .create_vault_folder("Projects/Design Assets")
            .unwrap();
        assert_eq!(created.name, "Design Assets");
        assert_eq!(created.path, "Projects/Design Assets");

        let paths = catalog
            .dashboard(false, false)
            .unwrap()
            .folders
            .into_iter()
            .map(|folder| folder.path)
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["Projects", "Projects/Design Assets"]);
        assert!(catalog
            .create_vault_folder("Projects/Design Assets")
            .unwrap_err()
            .to_string()
            .contains("already exists"));

        catalog.delete_vault_folder_tree("Projects").unwrap();
        assert!(catalog.dashboard(false, false).unwrap().folders.is_empty());
    }

    #[test]
    fn logical_copies_keep_shared_telegram_chunks_until_the_last_copy_is_deleted() {
        let temp = tempfile::tempdir().unwrap();
        let catalog = Catalog::new(temp.path().join("catalog.sqlite3")).unwrap();
        test_account(&catalog);
        let file = VaultFile {
            id: "file-1".into(),
            name: "photo.jpg".into(),
            folder_path: "Photos".into(),
            category: "Photos".into(),
            size: 4096,
            mime_type: "image/jpeg".into(),
            encrypted: true,
            cached: false,
            chunk_count: 1,
            account_id: "account-1".into(),
            account_name: "Personal".into(),
            created_at: now(),
            status: "uploading".into(),
            thumbnail: None,
            favorite: false,
            tags: Vec::new(),
            last_opened_at: None,
            deleted_at: None,
            purge_at: None,
        };
        catalog
            .insert_queued_file(&file, "/tmp/photo.jpg", "transfer-1", "skip")
            .unwrap();
        catalog
            .set_prepared("file-1", "abc123", 1, Some("wrapped"), Some("nonce"))
            .unwrap();
        catalog
            .add_chunk(
                "file-1",
                &ChunkRecord {
                    index: 0,
                    message_id: 42,
                    size: 4096,
                    sha256: "chunk-hash".into(),
                },
            )
            .unwrap();
        catalog
            .set_manifest_and_complete("file-1", "transfer-1", 101)
            .unwrap();

        let source = catalog.file_context("file-1").unwrap();
        catalog
            .insert_copy(&source, "file-2", "photo copy.jpg", "Copies", 202)
            .unwrap();
        assert_eq!(catalog.chunks("file-2").unwrap()[0].message_id, 42);
        assert_eq!(catalog.message_ids_for_delete("file-1").unwrap(), vec![101]);
        assert_eq!(catalog.message_ids_for_delete("file-2").unwrap(), vec![202]);

        catalog.permanent_delete_local("file-1").unwrap();
        assert_eq!(
            catalog.message_ids_for_delete("file-2").unwrap(),
            vec![42, 202]
        );
    }

    #[test]
    fn duplicate_detection_requires_an_exact_hash_match() {
        let temp = tempfile::tempdir().unwrap();
        let catalog = Catalog::new(temp.path().join("catalog.sqlite3")).unwrap();
        test_account(&catalog);
        let file = VaultFile {
            id: "file-1".into(),
            name: "first.bin".into(),
            folder_path: String::new(),
            category: "Other".into(),
            size: 8192,
            mime_type: "application/octet-stream".into(),
            encrypted: false,
            cached: false,
            chunk_count: 0,
            account_id: "account-1".into(),
            account_name: "Personal".into(),
            created_at: now(),
            status: "uploading".into(),
            thumbnail: None,
            favorite: false,
            tags: Vec::new(),
            last_opened_at: None,
            deleted_at: None,
            purge_at: None,
        };
        catalog
            .insert_queued_file(&file, "/tmp/first.bin", "transfer-1", "skip")
            .unwrap();
        catalog
            .set_prepared("file-1", "same-content", 0, None, None)
            .unwrap();
        catalog
            .set_manifest_and_complete("file-1", "transfer-1", 101)
            .unwrap();

        assert!(catalog
            .has_duplicate_size("account-1", 8192, "new-id")
            .unwrap());
        assert_eq!(
            catalog
                .duplicate_by_hash("account-1", 8192, "same-content", "new-id")
                .unwrap(),
            Some("first.bin".into())
        );
        assert_eq!(
            catalog
                .duplicate_by_hash("account-1", 8192, "different", "new-id")
                .unwrap(),
            None
        );
    }

    #[test]
    fn recycle_bin_retains_telegram_records_until_restore_or_purge() {
        let temp = tempfile::tempdir().unwrap();
        let catalog = Catalog::new(temp.path().join("catalog.sqlite3")).unwrap();
        test_account(&catalog);
        let file = VaultFile {
            id: "file-trash".into(),
            name: "recoverable.txt".into(),
            folder_path: "Notes".into(),
            category: "Documents".into(),
            size: 5,
            mime_type: "text/plain".into(),
            encrypted: true,
            cached: false,
            chunk_count: 1,
            account_id: "account-1".into(),
            account_name: "Personal".into(),
            created_at: now(),
            status: "uploading".into(),
            thumbnail: None,
            favorite: false,
            tags: vec!["important".into()],
            last_opened_at: None,
            deleted_at: None,
            purge_at: None,
        };
        catalog
            .insert_queued_file(&file, "/tmp/recoverable.txt", "transfer-trash", "keep")
            .unwrap();
        catalog
            .set_prepared(
                "file-trash",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                1,
                Some("wrapped"),
                Some("nonce"),
            )
            .unwrap();
        catalog
            .add_chunk(
                "file-trash",
                &ChunkRecord {
                    index: 0,
                    message_id: 501,
                    size: 5,
                    sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .into(),
                },
            )
            .unwrap();
        catalog
            .set_manifest_and_complete("file-trash", "transfer-trash", 502)
            .unwrap();

        catalog.trash_file("file-trash", 14).unwrap();
        let trashed = catalog
            .dashboard(false, false)
            .unwrap()
            .files
            .pop()
            .unwrap();
        assert_eq!(trashed.status, "trashed");
        assert!(trashed.deleted_at.is_some());
        assert!(trashed.purge_at.is_some());
        assert_eq!(
            catalog.message_ids_for_delete("file-trash").unwrap(),
            vec![501, 502]
        );

        catalog.restore_file("file-trash").unwrap();
        let restored = catalog
            .dashboard(false, false)
            .unwrap()
            .files
            .pop()
            .unwrap();
        assert_eq!(restored.status, "ready");
        assert!(restored.deleted_at.is_none());
        assert!(restored.purge_at.is_none());
    }
}
