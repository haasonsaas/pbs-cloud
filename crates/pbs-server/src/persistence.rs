//! Persistence layer for users, tokens, and tenants
//!
//! Stores authentication state to JSON files on disk.

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::{info, warn, error};

use crate::auth::{User, ApiToken, Permission};
use crate::tenant::Tenant;
use crate::protocol::ApiError;

/// Persistence configuration
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// Base directory for data files
    pub data_dir: PathBuf,
}

impl PersistenceConfig {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self {
            data_dir: data_dir.as_ref().to_path_buf(),
        }
    }

    fn users_file(&self) -> PathBuf {
        self.data_dir.join("users.json")
    }

    fn tokens_file(&self) -> PathBuf {
        self.data_dir.join("tokens.json")
    }

    fn tenants_file(&self) -> PathBuf {
        self.data_dir.join("tenants.json")
    }
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        // Default to ~/.pbs-cloud/
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self::new(format!("{}/.pbs-cloud", home))
    }
}

/// Data format for users file
#[derive(Debug, Serialize, Deserialize)]
struct UsersData {
    version: u32,
    users: Vec<User>,
}

impl Default for UsersData {
    fn default() -> Self {
        Self {
            version: 1,
            users: Vec::new(),
        }
    }
}

/// Data format for tokens file
#[derive(Debug, Serialize, Deserialize)]
struct TokensData {
    version: u32,
    tokens: Vec<StoredToken>,
}

/// Token stored with hash (not the actual token)
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredToken {
    pub id: String,
    pub token_hash: String,
    pub user_id: String,
    pub name: String,
    pub permission: Permission,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<&ApiToken> for StoredToken {
    fn from(token: &ApiToken) -> Self {
        Self {
            id: token.id.clone(),
            token_hash: token.token_hash.clone(),
            user_id: token.user_id.clone(),
            name: token.name.clone(),
            permission: token.permission,
            active: token.active,
            created_at: token.created_at,
            expires_at: token.expires_at,
            last_used: token.last_used,
        }
    }
}

impl From<StoredToken> for ApiToken {
    fn from(stored: StoredToken) -> Self {
        Self {
            id: stored.id,
            token_hash: stored.token_hash,
            user_id: stored.user_id,
            name: stored.name,
            permission: stored.permission,
            active: stored.active,
            created_at: stored.created_at,
            expires_at: stored.expires_at,
            last_used: stored.last_used,
        }
    }
}

impl Default for TokensData {
    fn default() -> Self {
        Self {
            version: 1,
            tokens: Vec::new(),
        }
    }
}

/// Data format for tenants file
#[derive(Debug, Serialize, Deserialize)]
struct TenantsData {
    version: u32,
    tenants: Vec<Tenant>,
}

impl Default for TenantsData {
    fn default() -> Self {
        Self {
            version: 1,
            tenants: Vec::new(),
        }
    }
}

/// Persistence manager
pub struct PersistenceManager {
    config: PersistenceConfig,
}

impl PersistenceManager {
    /// Create a new persistence manager
    pub async fn new(config: PersistenceConfig) -> anyhow::Result<Self> {
        // Create data directory if it doesn't exist
        fs::create_dir_all(&config.data_dir).await?;

        info!("Persistence initialized at {:?}", config.data_dir);
        Ok(Self { config })
    }

    /// Load users from disk
    pub async fn load_users(&self) -> anyhow::Result<Vec<User>> {
        let path = self.config.users_file();
        if !path.exists() {
            info!("No users file found, starting fresh");
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&path).await?;
        let data: UsersData = serde_json::from_str(&content)?;

        info!("Loaded {} users from disk", data.users.len());
        Ok(data.users)
    }

    /// Save users to disk
    pub async fn save_users(&self, users: &[User]) -> anyhow::Result<()> {
        let data = UsersData {
            version: 1,
            users: users.to_vec(),
        };

        let content = serde_json::to_string_pretty(&data)?;
        let path = self.config.users_file();

        // Write to temp file first, then rename (atomic)
        let temp_path = path.with_extension("json.tmp");
        fs::write(&temp_path, &content).await?;
        fs::rename(&temp_path, &path).await?;

        Ok(())
    }

    /// Load tokens from disk
    pub async fn load_tokens(&self) -> anyhow::Result<Vec<ApiToken>> {
        let path = self.config.tokens_file();
        if !path.exists() {
            info!("No tokens file found, starting fresh");
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&path).await?;
        let data: TokensData = serde_json::from_str(&content)?;

        let tokens: Vec<ApiToken> = data.tokens.into_iter().map(|t| t.into()).collect();
        info!("Loaded {} tokens from disk", tokens.len());
        Ok(tokens)
    }

    /// Save tokens to disk
    pub async fn save_tokens(&self, tokens: &[ApiToken]) -> anyhow::Result<()> {
        let stored: Vec<StoredToken> = tokens.iter().map(StoredToken::from).collect();
        let data = TokensData {
            version: 1,
            tokens: stored,
        };

        let content = serde_json::to_string_pretty(&data)?;
        let path = self.config.tokens_file();

        // Write to temp file first, then rename (atomic)
        let temp_path = path.with_extension("json.tmp");
        fs::write(&temp_path, &content).await?;
        fs::rename(&temp_path, &path).await?;

        Ok(())
    }

    /// Load tenants from disk
    pub async fn load_tenants(&self) -> anyhow::Result<Vec<Tenant>> {
        let path = self.config.tenants_file();
        if !path.exists() {
            info!("No tenants file found, starting fresh");
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&path).await?;
        let data: TenantsData = serde_json::from_str(&content)?;

        info!("Loaded {} tenants from disk", data.tenants.len());
        Ok(data.tenants)
    }

    /// Save tenants to disk
    pub async fn save_tenants(&self, tenants: &[Tenant]) -> anyhow::Result<()> {
        let data = TenantsData {
            version: 1,
            tenants: tenants.to_vec(),
        };

        let content = serde_json::to_string_pretty(&data)?;
        let path = self.config.tenants_file();

        // Write to temp file first, then rename (atomic)
        let temp_path = path.with_extension("json.tmp");
        fs::write(&temp_path, &content).await?;
        fs::rename(&temp_path, &path).await?;

        Ok(())
    }

    /// Get the data directory path
    pub fn data_dir(&self) -> &Path {
        &self.config.data_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_user_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig::new(temp_dir.path());
        let manager = PersistenceManager::new(config).await.unwrap();

        // Create some users
        let users = vec![
            User::new("user1@pam", "tenant1", Permission::Admin),
            User::new("user2@pam", "tenant1", Permission::Backup),
        ];

        // Save
        manager.save_users(&users).await.unwrap();

        // Load
        let loaded = manager.load_users().await.unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].username, "user1@pam");
    }

    #[tokio::test]
    async fn test_tenant_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig::new(temp_dir.path());
        let manager = PersistenceManager::new(config).await.unwrap();

        // Create some tenants
        let tenants = vec![
            Tenant::new("tenant1"),
            Tenant::new("tenant2"),
        ];

        // Save
        manager.save_tenants(&tenants).await.unwrap();

        // Load
        let loaded = manager.load_tenants().await.unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "tenant1");
    }
}
