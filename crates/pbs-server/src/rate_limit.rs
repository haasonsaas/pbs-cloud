//! Rate limiting to protect against abuse
//!
//! Implements per-IP and per-tenant rate limiting using token bucket algorithm.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use governor::{Quota, RateLimiter};
use tracing::{debug, info, warn};

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests per minute for unauthenticated endpoints
    pub unauthenticated_rpm: u32,
    /// Requests per minute for authenticated endpoints
    pub authenticated_rpm: u32,
    /// Upload bytes per hour per tenant (0 = unlimited)
    pub upload_bytes_per_hour: u64,
    /// Whether rate limiting is enabled
    pub enabled: bool,
    /// TTL for inactive rate limiters (seconds)
    pub limiter_ttl_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            unauthenticated_rpm: 60, // 1 request per second for unauth
            authenticated_rpm: 1000, // ~17 requests per second for auth
            upload_bytes_per_hour: 10 * 1024 * 1024 * 1024, // 10 GB/hour
            enabled: true,
            limiter_ttl_secs: 3600, // 1 hour TTL for inactive limiters
        }
    }
}

impl RateLimitConfig {
    /// Create a permissive config for testing
    pub fn permissive() -> Self {
        Self {
            unauthenticated_rpm: 10000,
            authenticated_rpm: 100000,
            upload_bytes_per_hour: 0, // unlimited
            enabled: true,
            limiter_ttl_secs: 3600,
        }
    }

    /// Disable rate limiting
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

/// Rate limiter entry with last access time for TTL-based eviction
struct LimiterEntry {
    limiter: Arc<KeyedLimiter>,
    last_access: Instant,
}

/// Per-key rate limiter using governor
type KeyedLimiter = governor::RateLimiter<
    governor::state::direct::NotKeyed,
    governor::state::InMemoryState,
    governor::clock::DefaultClock,
>;

/// Rate limiter for the server
pub struct RateLimiter_ {
    config: RateLimitConfig,
    /// Per-IP limiters for unauthenticated requests
    ip_limiters: DashMap<IpAddr, LimiterEntry>,
    /// Per-tenant limiters for authenticated requests
    tenant_limiters: DashMap<String, LimiterEntry>,
    /// Per-tenant upload byte tracking
    tenant_upload_bytes: DashMap<String, u64>,
    /// Last reset time for upload tracking
    last_upload_reset: parking_lot::RwLock<Instant>,
}

impl RateLimiter_ {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            ip_limiters: DashMap::new(),
            tenant_limiters: DashMap::new(),
            tenant_upload_bytes: DashMap::new(),
            last_upload_reset: parking_lot::RwLock::new(Instant::now()),
        }
    }

    /// Check if rate limiting is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check rate limit for an IP (unauthenticated requests)
    pub fn check_ip(&self, ip: IpAddr) -> RateLimitResult {
        if !self.config.enabled {
            return RateLimitResult::Allowed;
        }

        let mut entry = self.ip_limiters.entry(ip).or_insert_with(|| {
            let quota = Quota::per_minute(
                NonZeroU32::new(self.config.unauthenticated_rpm).unwrap_or(NonZeroU32::MIN),
            );
            LimiterEntry {
                limiter: Arc::new(RateLimiter::direct(quota)),
                last_access: Instant::now(),
            }
        });

        // Update last access time
        entry.last_access = Instant::now();

        match entry.limiter.check() {
            Ok(_) => RateLimitResult::Allowed,
            Err(_) => {
                warn!("Rate limit exceeded for IP {}", ip);
                RateLimitResult::Limited {
                    retry_after_secs: 60, // Wait a minute
                    limit: self.config.unauthenticated_rpm,
                    remaining: 0,
                }
            }
        }
    }

    /// Check rate limit for a tenant (authenticated requests)
    pub fn check_tenant(&self, tenant_id: &str) -> RateLimitResult {
        if !self.config.enabled {
            return RateLimitResult::Allowed;
        }

        let mut entry = self
            .tenant_limiters
            .entry(tenant_id.to_string())
            .or_insert_with(|| {
                let quota = Quota::per_minute(
                    NonZeroU32::new(self.config.authenticated_rpm).unwrap_or(NonZeroU32::MIN),
                );
                LimiterEntry {
                    limiter: Arc::new(RateLimiter::direct(quota)),
                    last_access: Instant::now(),
                }
            });

        // Update last access time
        entry.last_access = Instant::now();

        match entry.limiter.check() {
            Ok(_) => RateLimitResult::Allowed,
            Err(_) => {
                warn!("Rate limit exceeded for tenant {}", tenant_id);
                RateLimitResult::Limited {
                    retry_after_secs: 60, // Wait a minute
                    limit: self.config.authenticated_rpm,
                    remaining: 0,
                }
            }
        }
    }

    /// Check and record upload bytes for a tenant
    pub fn check_upload(&self, tenant_id: &str, bytes: u64) -> RateLimitResult {
        if !self.config.enabled || self.config.upload_bytes_per_hour == 0 {
            return RateLimitResult::Allowed;
        }

        // Reset counters hourly
        {
            let mut last_reset = self.last_upload_reset.write();
            if last_reset.elapsed() > Duration::from_secs(3600) {
                self.tenant_upload_bytes.clear();
                *last_reset = std::time::Instant::now();
                debug!("Reset upload byte counters");
            }
        }

        let mut entry = self
            .tenant_upload_bytes
            .entry(tenant_id.to_string())
            .or_insert(0);
        let current = *entry;
        let new_total = current + bytes;

        if new_total > self.config.upload_bytes_per_hour {
            let remaining = self.config.upload_bytes_per_hour.saturating_sub(current);
            warn!(
                "Upload rate limit exceeded for tenant {}: {} bytes used of {} allowed",
                tenant_id, current, self.config.upload_bytes_per_hour
            );
            return RateLimitResult::Limited {
                retry_after_secs: 3600, // Wait until next hour
                limit: self.config.upload_bytes_per_hour as u32,
                remaining: remaining as u32,
            };
        }

        *entry = new_total;
        RateLimitResult::Allowed
    }

    /// Get current usage stats for a tenant
    pub fn get_tenant_stats(&self, tenant_id: &str) -> TenantRateLimitStats {
        let upload_bytes = self
            .tenant_upload_bytes
            .get(tenant_id)
            .map(|r| *r)
            .unwrap_or(0);

        TenantRateLimitStats {
            upload_bytes_used: upload_bytes,
            upload_bytes_limit: self.config.upload_bytes_per_hour,
            requests_per_minute_limit: self.config.authenticated_rpm,
        }
    }

    /// Clean up stale limiters (call periodically)
    /// Removes entries that haven't been accessed within the TTL period
    pub fn cleanup(&self) {
        let ttl = Duration::from_secs(self.config.limiter_ttl_secs);
        let now = Instant::now();

        // Clean up IP limiters
        let ip_keys_to_remove: Vec<_> = self
            .ip_limiters
            .iter()
            .filter(|r| now.duration_since(r.last_access) > ttl)
            .map(|r| *r.key())
            .collect();

        let ip_removed = ip_keys_to_remove.len();
        for key in ip_keys_to_remove {
            self.ip_limiters.remove(&key);
        }

        // Clean up tenant limiters
        let tenant_keys_to_remove: Vec<_> = self
            .tenant_limiters
            .iter()
            .filter(|r| now.duration_since(r.last_access) > ttl)
            .map(|r| r.key().clone())
            .collect();

        let tenant_removed = tenant_keys_to_remove.len();
        for key in tenant_keys_to_remove {
            self.tenant_limiters.remove(&key);
        }

        if ip_removed > 0 || tenant_removed > 0 {
            info!(
                "Rate limiter cleanup: removed {} IP limiters, {} tenant limiters (remaining: {} IP, {} tenant)",
                ip_removed, tenant_removed,
                self.ip_limiters.len(), self.tenant_limiters.len()
            );
        }
    }

    /// Get current limiter counts for monitoring
    pub fn get_limiter_counts(&self) -> (usize, usize) {
        (self.ip_limiters.len(), self.tenant_limiters.len())
    }
}

impl Default for RateLimiter_ {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

/// Result of a rate limit check
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed,
    /// Request is rate limited
    Limited {
        /// Seconds until rate limit resets
        retry_after_secs: u32,
        /// The rate limit
        limit: u32,
        /// Remaining requests/bytes
        remaining: u32,
    },
}

impl RateLimitResult {
    /// Check if the request was allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed)
    }

    /// Get rate limit headers for HTTP response
    pub fn headers(&self) -> Vec<(String, String)> {
        match self {
            RateLimitResult::Allowed => vec![],
            RateLimitResult::Limited {
                retry_after_secs,
                limit,
                remaining,
            } => {
                vec![
                    ("Retry-After".to_string(), retry_after_secs.to_string()),
                    ("X-RateLimit-Limit".to_string(), limit.to_string()),
                    ("X-RateLimit-Remaining".to_string(), remaining.to_string()),
                ]
            }
        }
    }
}

/// Rate limit statistics for a tenant
#[derive(Debug, Clone)]
pub struct TenantRateLimitStats {
    pub upload_bytes_used: u64,
    pub upload_bytes_limit: u64,
    pub requests_per_minute_limit: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ip_rate_limit() {
        let config = RateLimitConfig {
            unauthenticated_rpm: 2,
            ..Default::default()
        };
        let limiter = RateLimiter_::new(config);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First two should pass
        assert!(limiter.check_ip(ip).is_allowed());
        assert!(limiter.check_ip(ip).is_allowed());

        // Third should be limited
        assert!(!limiter.check_ip(ip).is_allowed());
    }

    #[test]
    fn test_tenant_rate_limit() {
        let config = RateLimitConfig {
            authenticated_rpm: 2,
            ..Default::default()
        };
        let limiter = RateLimiter_::new(config);

        let tenant = "tenant1";

        // First two should pass
        assert!(limiter.check_tenant(tenant).is_allowed());
        assert!(limiter.check_tenant(tenant).is_allowed());

        // Third should be limited
        assert!(!limiter.check_tenant(tenant).is_allowed());
    }

    #[test]
    fn test_upload_rate_limit() {
        let config = RateLimitConfig {
            upload_bytes_per_hour: 1000,
            ..Default::default()
        };
        let limiter = RateLimiter_::new(config);

        let tenant = "tenant1";

        // Should allow up to 1000 bytes
        assert!(limiter.check_upload(tenant, 500).is_allowed());
        assert!(limiter.check_upload(tenant, 400).is_allowed());

        // This should exceed the limit
        assert!(!limiter.check_upload(tenant, 200).is_allowed());
    }

    #[test]
    fn test_disabled_rate_limit() {
        let config = RateLimitConfig::disabled();
        let limiter = RateLimiter_::new(config);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // All should pass when disabled
        for _ in 0..100 {
            assert!(limiter.check_ip(ip).is_allowed());
        }
    }
}
