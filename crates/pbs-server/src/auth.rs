//! Authentication and authorization
//!
//! Supports API tokens and PBS-compatible authentication.

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::protocol::ApiError;

/// Permission level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Permission {
    /// Can only read/restore backups
    Read,
    /// Can create backups
    Backup,
    /// Can manage datastores (prune, GC, etc.)
    DatastoreAdmin,
    /// Full administrative access
    Admin,
}

impl Permission {
    /// Check if this permission allows an action
    pub fn allows(&self, required: Permission) -> bool {
        *self >= required
    }
}

/// User/service account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// User ID
    pub id: String,
    /// Username
    pub username: String,
    /// Tenant ID (for multi-tenancy)
    pub tenant_id: String,
    /// Permission level
    pub permission: Permission,
    /// Whether the user is active
    pub active: bool,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last login time
    pub last_login: Option<DateTime<Utc>>,
}

impl User {
    /// Create a new user
    pub fn new(username: &str, tenant_id: &str, permission: Permission) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            tenant_id: tenant_id.to_string(),
            permission,
            active: true,
            created_at: Utc::now(),
            last_login: None,
        }
    }
}

/// API token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    /// Token ID (public, used as identifier)
    pub id: String,
    /// Token hash (SHA-256 of the actual token)
    #[serde(skip_serializing)]
    pub token_hash: String,
    /// User ID this token belongs to
    pub user_id: String,
    /// Token name/description
    pub name: String,
    /// Permission level (can be lower than user's permission)
    pub permission: Permission,
    /// Whether the token is active
    pub active: bool,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Expiration time (None = never expires)
    pub expires_at: Option<DateTime<Utc>>,
    /// Last used time
    pub last_used: Option<DateTime<Utc>>,
}

impl ApiToken {
    /// Generate a new API token
    /// Returns (token_struct, actual_token_string)
    pub fn generate(
        user_id: &str,
        name: &str,
        permission: Permission,
        expires_at: Option<DateTime<Utc>>,
    ) -> (Self, String) {
        // Generate random token
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token_string = format!("pbs_{}", hex::encode(token_bytes));

        // Hash the token for storage
        let mut hasher = Sha256::new();
        hasher.update(token_string.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let token = Self {
            id: uuid::Uuid::new_v4().to_string(),
            token_hash: hash,
            user_id: user_id.to_string(),
            name: name.to_string(),
            permission,
            active: true,
            created_at: Utc::now(),
            expires_at,
            last_used: None,
        };

        (token, token_string)
    }

    /// Verify a token string against this token
    pub fn verify(&self, token_string: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(token_string.as_bytes());
        let hash = hex::encode(hasher.finalize());
        self.token_hash == hash
    }

    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires) => Utc::now() > expires,
            None => false,
        }
    }

    /// Check if the token is valid (active and not expired)
    pub fn is_valid(&self) -> bool {
        self.active && !self.is_expired()
    }
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Authenticated user
    pub user: User,
    /// Token used (if token auth)
    pub token_id: Option<String>,
    /// Effective permission
    pub permission: Permission,
}

impl AuthContext {
    /// Check if this context allows an action
    pub fn allows(&self, required: Permission) -> bool {
        self.permission.allows(required)
    }

    /// Require a permission level, returning error if not allowed
    pub fn require(&self, required: Permission) -> Result<(), ApiError> {
        if self.allows(required) {
            Ok(())
        } else {
            Err(ApiError::unauthorized("Insufficient permissions"))
        }
    }
}

/// Authentication manager
pub struct AuthManager {
    users: RwLock<HashMap<String, User>>,
    tokens: RwLock<HashMap<String, ApiToken>>,
    /// Index: username -> user_id
    username_index: RwLock<HashMap<String, String>>,
}

impl AuthManager {
    /// Create a new auth manager
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            tokens: RwLock::new(HashMap::new()),
            username_index: RwLock::new(HashMap::new()),
        }
    }

    /// Create a user
    pub async fn create_user(
        &self,
        username: &str,
        tenant_id: &str,
        permission: Permission,
    ) -> Result<User, ApiError> {
        // Check if username exists
        {
            let index = self.username_index.read().await;
            if index.contains_key(username) {
                return Err(ApiError::bad_request("Username already exists"));
            }
        }

        let user = User::new(username, tenant_id, permission);

        {
            let mut users = self.users.write().await;
            let mut index = self.username_index.write().await;
            users.insert(user.id.clone(), user.clone());
            index.insert(username.to_string(), user.id.clone());
        }

        Ok(user)
    }

    /// Get a user by ID
    pub async fn get_user(&self, user_id: &str) -> Option<User> {
        let users = self.users.read().await;
        users.get(user_id).cloned()
    }

    /// Get a user by username
    pub async fn get_user_by_username(&self, username: &str) -> Option<User> {
        let index = self.username_index.read().await;
        let user_id = index.get(username)?;
        let users = self.users.read().await;
        users.get(user_id).cloned()
    }

    /// List users for a tenant
    pub async fn list_users(&self, tenant_id: Option<&str>) -> Vec<User> {
        let users = self.users.read().await;
        users
            .values()
            .filter(|u| tenant_id.is_none_or(|t| u.tenant_id == t))
            .cloned()
            .collect()
    }

    /// Update user permission
    pub async fn update_user_permission(
        &self,
        user_id: &str,
        permission: Permission,
    ) -> Result<User, ApiError> {
        let mut users = self.users.write().await;
        let user = users
            .get_mut(user_id)
            .ok_or_else(|| ApiError::not_found("User not found"))?;
        user.permission = permission;
        Ok(user.clone())
    }

    /// Deactivate a user
    pub async fn deactivate_user(&self, user_id: &str) -> Result<User, ApiError> {
        let mut users = self.users.write().await;
        let user = users
            .get_mut(user_id)
            .ok_or_else(|| ApiError::not_found("User not found"))?;
        user.active = false;
        Ok(user.clone())
    }

    /// Delete a user permanently (also deletes all their tokens)
    pub async fn delete_user(&self, user_id: &str) -> Result<User, ApiError> {
        // First, delete all tokens belonging to this user
        {
            let mut tokens = self.tokens.write().await;
            tokens.retain(|_, t| t.user_id != user_id);
        }

        // Then delete the user
        let mut users = self.users.write().await;
        let mut index = self.username_index.write().await;

        let user = users
            .remove(user_id)
            .ok_or_else(|| ApiError::not_found("User not found"))?;

        index.remove(&user.username);

        Ok(user)
    }

    /// Create an API token
    pub async fn create_token(
        &self,
        user_id: &str,
        name: &str,
        permission: Permission,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(ApiToken, String), ApiError> {
        // Verify user exists and is active
        {
            let users = self.users.read().await;
            let user = users
                .get(user_id)
                .ok_or_else(|| ApiError::not_found("User not found"))?;
            if !user.active {
                return Err(ApiError::bad_request("User is not active"));
            }
            // Token permission can't exceed user permission
            if permission > user.permission {
                return Err(ApiError::bad_request(
                    "Token permission exceeds user permission",
                ));
            }
        }

        let (token, token_string) = ApiToken::generate(user_id, name, permission, expires_at);

        {
            let mut tokens = self.tokens.write().await;
            tokens.insert(token.id.clone(), token.clone());
        }

        Ok((token, token_string))
    }

    /// Get a token by ID
    pub async fn get_token(&self, token_id: &str) -> Option<ApiToken> {
        let tokens = self.tokens.read().await;
        tokens.get(token_id).cloned()
    }

    /// List tokens for a user
    pub async fn list_tokens(&self, user_id: &str) -> Vec<ApiToken> {
        let tokens = self.tokens.read().await;
        tokens
            .values()
            .filter(|t| t.user_id == user_id)
            .cloned()
            .collect()
    }

    /// Revoke a token
    pub async fn revoke_token(&self, token_id: &str) -> Result<(), ApiError> {
        let mut tokens = self.tokens.write().await;
        let token = tokens
            .get_mut(token_id)
            .ok_or_else(|| ApiError::not_found("Token not found"))?;
        token.active = false;
        Ok(())
    }

    /// Delete a token
    pub async fn delete_token(&self, token_id: &str) -> Result<(), ApiError> {
        let mut tokens = self.tokens.write().await;
        tokens
            .remove(token_id)
            .ok_or_else(|| ApiError::not_found("Token not found"))?;
        Ok(())
    }

    /// Authenticate with an API token
    pub async fn authenticate_token(&self, token_string: &str) -> Result<AuthContext, ApiError> {
        // Find the token by verifying against all tokens
        // In production, we'd use a more efficient lookup
        let token = {
            let tokens = self.tokens.read().await;
            tokens.values().find(|t| t.verify(token_string)).cloned()
        };

        let token = token.ok_or_else(|| ApiError::unauthorized("Invalid token"))?;

        if !token.is_valid() {
            return Err(ApiError::unauthorized("Token is expired or inactive"));
        }

        // Update last used time
        {
            let mut tokens = self.tokens.write().await;
            if let Some(t) = tokens.get_mut(&token.id) {
                t.last_used = Some(Utc::now());
            }
        }

        // Get the user
        let user = {
            let users = self.users.read().await;
            users.get(&token.user_id).cloned()
        };

        let user = user.ok_or_else(|| ApiError::unauthorized("User not found"))?;

        if !user.active {
            return Err(ApiError::unauthorized("User is not active"));
        }

        // Update user's last login
        {
            let mut users = self.users.write().await;
            if let Some(u) = users.get_mut(&user.id) {
                u.last_login = Some(Utc::now());
            }
        }

        Ok(AuthContext {
            permission: token.permission, // Use token's permission (may be lower than user's)
            user,
            token_id: Some(token.id),
        })
    }

    /// Authenticate from HTTP Authorization header
    pub async fn authenticate_header(&self, auth_header: &str) -> Result<AuthContext, ApiError> {
        // Support "Bearer <token>" format
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            return self.authenticate_token(token.trim()).await;
        }

        // Support "PBSAPIToken=<user>:<token>" format (PBS compatible)
        if let Some(rest) = auth_header.strip_prefix("PBSAPIToken=") {
            if let Some((_, token)) = rest.split_once(':') {
                return self.authenticate_token(token.trim()).await;
            }
        }

        Err(ApiError::unauthorized("Invalid authorization header"))
    }

    /// Create a root/bootstrap user (for initial setup)
    pub async fn create_root_user(&self, tenant_id: &str) -> Result<(User, String), ApiError> {
        let user = self
            .create_user("root@pam", tenant_id, Permission::Admin)
            .await?;
        let (_, token_string) = self
            .create_token(&user.id, "root-token", Permission::Admin, None)
            .await?;
        Ok((user, token_string))
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthManager {
    /// Restore a user from persistence (for loading from disk)
    pub async fn restore_user(&self, user: User) {
        let mut users = self.users.write().await;
        let mut index = self.username_index.write().await;
        index.insert(user.username.clone(), user.id.clone());
        users.insert(user.id.clone(), user);
    }

    /// Restore a token from persistence (for loading from disk)
    pub async fn restore_token(&self, token: ApiToken) {
        let mut tokens = self.tokens.write().await;
        tokens.insert(token.id.clone(), token);
    }

    /// Get the number of users
    pub async fn user_count(&self) -> usize {
        self.users.read().await.len()
    }

    /// Get the number of tokens
    pub async fn token_count(&self) -> usize {
        self.tokens.read().await.len()
    }

    /// List all tokens (for persistence)
    pub async fn list_all_tokens(&self) -> Vec<ApiToken> {
        let tokens = self.tokens.read().await;
        tokens.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_user_creation() {
        let auth = AuthManager::new();
        let user = auth
            .create_user("test@pam", "tenant1", Permission::Backup)
            .await
            .unwrap();
        assert_eq!(user.username, "test@pam");
        assert_eq!(user.permission, Permission::Backup);
    }

    #[tokio::test]
    async fn test_token_auth() {
        let auth = AuthManager::new();
        let user = auth
            .create_user("test@pam", "tenant1", Permission::Admin)
            .await
            .unwrap();

        let (token, token_string) = auth
            .create_token(&user.id, "test-token", Permission::Backup, None)
            .await
            .unwrap();

        // Authenticate with the token
        let ctx = auth.authenticate_token(&token_string).await.unwrap();
        assert_eq!(ctx.user.id, user.id);
        assert_eq!(ctx.permission, Permission::Backup); // Token's permission, not user's
    }

    #[tokio::test]
    async fn test_token_expiration() {
        let auth = AuthManager::new();
        let user = auth
            .create_user("test@pam", "tenant1", Permission::Admin)
            .await
            .unwrap();

        // Create an already-expired token
        let expires_at = Utc::now() - chrono::Duration::hours(1);
        let (_, token_string) = auth
            .create_token(
                &user.id,
                "expired-token",
                Permission::Backup,
                Some(expires_at),
            )
            .await
            .unwrap();

        // Should fail to authenticate
        let result = auth.authenticate_token(&token_string).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_permission_hierarchy() {
        assert!(Permission::Admin.allows(Permission::DatastoreAdmin));
        assert!(Permission::Admin.allows(Permission::Backup));
        assert!(Permission::Admin.allows(Permission::Read));
        assert!(Permission::Backup.allows(Permission::Read));
        assert!(!Permission::Read.allows(Permission::Backup));
    }
}
