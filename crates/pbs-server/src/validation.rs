//! Input validation for security
//!
//! Validates user input to prevent path traversal, injection, and other attacks.

use lazy_static::lazy_static;
use regex::Regex;

use crate::protocol::ApiError;

lazy_static! {
    /// Valid backup type: vm, ct, or host
    static ref BACKUP_TYPE_RE: Regex = Regex::new(r"^(vm|ct|host)$").unwrap();

    /// Valid backup ID: alphanumeric with dots, underscores, hyphens (1-64 chars)
    static ref BACKUP_ID_RE: Regex = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$").unwrap();

    /// Valid ISO 8601 timestamp: YYYY-MM-DDTHH:MM:SSZ or with timezone
    static ref BACKUP_TIME_RE: Regex = Regex::new(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$"
    ).unwrap();

    /// Valid index/blob name: simple filename without path separators
    static ref FILENAME_RE: Regex = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$").unwrap();

    /// Valid username: alphanumeric with dots, underscores, hyphens, @
    static ref USERNAME_RE: Regex = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,63}$").unwrap();

    /// Valid tenant name: alphanumeric with spaces, dots, underscores, hyphens
    static ref TENANT_NAME_RE: Regex = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,127}$").unwrap();

    /// Valid datastore name
    static ref DATASTORE_NAME_RE: Regex = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$").unwrap();

    /// Valid chunk digest: 64 hex characters (SHA-256)
    static ref DIGEST_RE: Regex = Regex::new(r"^[a-fA-F0-9]{64}$").unwrap();
}

/// Reserved names that cannot be used
const RESERVED_NAMES: &[&str] = &[
    ".", "..", "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    "admin", "root", "system", "null", "undefined",
];

/// Validate backup type (vm, ct, host)
pub fn validate_backup_type(backup_type: &str) -> Result<(), ApiError> {
    if !BACKUP_TYPE_RE.is_match(backup_type) {
        return Err(ApiError::bad_request(
            "Invalid backup type: must be 'vm', 'ct', or 'host'"
        ));
    }
    Ok(())
}

/// Validate backup ID
pub fn validate_backup_id(backup_id: &str) -> Result<(), ApiError> {
    if backup_id.is_empty() {
        return Err(ApiError::bad_request("Backup ID cannot be empty"));
    }
    if !BACKUP_ID_RE.is_match(backup_id) {
        return Err(ApiError::bad_request(
            "Invalid backup ID: must be 1-64 alphanumeric characters, dots, underscores, or hyphens"
        ));
    }
    if is_reserved_name(backup_id) {
        return Err(ApiError::bad_request("Backup ID uses a reserved name"));
    }
    Ok(())
}

/// Validate backup timestamp (ISO 8601)
pub fn validate_backup_time(backup_time: &str) -> Result<(), ApiError> {
    if backup_time.is_empty() {
        return Err(ApiError::bad_request("Backup time cannot be empty"));
    }
    if !BACKUP_TIME_RE.is_match(backup_time) {
        return Err(ApiError::bad_request(
            "Invalid backup time: must be ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)"
        ));
    }
    // Verify it's a valid date/time
    if chrono::DateTime::parse_from_rfc3339(backup_time).is_err() {
        return Err(ApiError::bad_request("Invalid backup time: not a valid timestamp"));
    }
    Ok(())
}

/// Validate file/index/blob name (no path traversal)
pub fn validate_filename(name: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::bad_request("Filename cannot be empty"));
    }
    if !FILENAME_RE.is_match(name) {
        return Err(ApiError::bad_request(
            "Invalid filename: must be 1-128 alphanumeric characters, dots, underscores, or hyphens"
        ));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(ApiError::bad_request("Invalid filename: path separators not allowed"));
    }
    if is_reserved_name(name) {
        return Err(ApiError::bad_request("Filename uses a reserved name"));
    }
    Ok(())
}

/// Validate username
pub fn validate_username(username: &str) -> Result<(), ApiError> {
    if username.is_empty() {
        return Err(ApiError::bad_request("Username cannot be empty"));
    }
    if !USERNAME_RE.is_match(username) {
        return Err(ApiError::bad_request(
            "Invalid username: must be 1-64 alphanumeric characters, dots, underscores, @, or hyphens"
        ));
    }
    if is_reserved_name(username) {
        return Err(ApiError::bad_request("Username uses a reserved name"));
    }
    Ok(())
}

/// Validate tenant name
pub fn validate_tenant_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::bad_request("Tenant name cannot be empty"));
    }
    if !TENANT_NAME_RE.is_match(name) {
        return Err(ApiError::bad_request(
            "Invalid tenant name: must be 1-128 alphanumeric characters, spaces, dots, underscores, or hyphens"
        ));
    }
    Ok(())
}

/// Validate datastore name
pub fn validate_datastore_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::bad_request("Datastore name cannot be empty"));
    }
    if !DATASTORE_NAME_RE.is_match(name) {
        return Err(ApiError::bad_request(
            "Invalid datastore name: must be 1-64 alphanumeric characters, dots, underscores, or hyphens"
        ));
    }
    if is_reserved_name(name) {
        return Err(ApiError::bad_request("Datastore name uses a reserved name"));
    }
    Ok(())
}

/// Validate chunk digest (hex string)
pub fn validate_digest(digest: &str) -> Result<(), ApiError> {
    if digest.is_empty() {
        return Err(ApiError::bad_request("Digest cannot be empty"));
    }
    if !DIGEST_RE.is_match(digest) {
        return Err(ApiError::bad_request(
            "Invalid digest: must be 64 hexadecimal characters (SHA-256)"
        ));
    }
    Ok(())
}

/// Check if a name is reserved
fn is_reserved_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    RESERVED_NAMES.contains(&lower.as_str())
}

/// Validate all backup parameters
pub fn validate_backup_params(
    backup_type: &str,
    backup_id: &str,
    backup_time: &str,
) -> Result<(), ApiError> {
    validate_backup_type(backup_type)?;
    validate_backup_id(backup_id)?;
    validate_backup_time(backup_time)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_backup_types() {
        assert!(validate_backup_type("vm").is_ok());
        assert!(validate_backup_type("ct").is_ok());
        assert!(validate_backup_type("host").is_ok());
    }

    #[test]
    fn test_invalid_backup_types() {
        assert!(validate_backup_type("").is_err());
        assert!(validate_backup_type("invalid").is_err());
        assert!(validate_backup_type("VM").is_err()); // case sensitive
        assert!(validate_backup_type("vm/ct").is_err());
    }

    #[test]
    fn test_valid_backup_ids() {
        assert!(validate_backup_id("my-backup").is_ok());
        assert!(validate_backup_id("backup_123").is_ok());
        assert!(validate_backup_id("test.backup").is_ok());
        assert!(validate_backup_id("a").is_ok());
    }

    #[test]
    fn test_invalid_backup_ids() {
        assert!(validate_backup_id("").is_err());
        assert!(validate_backup_id("../etc/passwd").is_err());
        assert!(validate_backup_id("-invalid").is_err()); // starts with dash
        assert!(validate_backup_id("a".repeat(65).as_str()).is_err()); // too long
    }

    #[test]
    fn test_reserved_names() {
        assert!(validate_backup_id("..").is_err());
        assert!(validate_backup_id("CON").is_err());
        assert!(validate_backup_id("admin").is_err());
        assert!(validate_username("root").is_err());
    }

    #[test]
    fn test_valid_backup_times() {
        assert!(validate_backup_time("2024-01-15T10:30:00Z").is_ok());
        assert!(validate_backup_time("2024-01-15T10:30:00+00:00").is_ok());
        assert!(validate_backup_time("2024-01-15T10:30:00-05:00").is_ok());
    }

    #[test]
    fn test_invalid_backup_times() {
        assert!(validate_backup_time("").is_err());
        assert!(validate_backup_time("2024-01-15").is_err()); // date only
        assert!(validate_backup_time("not-a-date").is_err());
        assert!(validate_backup_time("2024-13-15T10:30:00Z").is_err()); // invalid month
    }

    #[test]
    fn test_valid_filenames() {
        assert!(validate_filename("drive-scsi0.img.fidx").is_ok());
        assert!(validate_filename("qemu-server.conf.blob").is_ok());
        assert!(validate_filename("index.json").is_ok());
    }

    #[test]
    fn test_invalid_filenames() {
        assert!(validate_filename("").is_err());
        assert!(validate_filename("../../../etc/passwd").is_err());
        assert!(validate_filename("/etc/passwd").is_err());
        assert!(validate_filename("..").is_err());
    }

    #[test]
    fn test_valid_usernames() {
        assert!(validate_username("admin@pbs").is_ok());
        assert!(validate_username("user.name").is_ok());
        assert!(validate_username("test-user").is_ok());
    }

    #[test]
    fn test_invalid_usernames() {
        assert!(validate_username("").is_err());
        assert!(validate_username("../admin").is_err());
        assert!(validate_username("-user").is_err()); // starts with dash
    }

    #[test]
    fn test_valid_digests() {
        assert!(validate_digest("a".repeat(64).as_str()).is_ok());
        assert!(validate_digest("0123456789abcdef".repeat(4).as_str()).is_ok());
        assert!(validate_digest("ABCDEF0123456789".repeat(4).as_str()).is_ok());
    }

    #[test]
    fn test_invalid_digests() {
        assert!(validate_digest("").is_err());
        assert!(validate_digest("abc").is_err()); // too short
        assert!(validate_digest("g".repeat(64).as_str()).is_err()); // non-hex
        assert!(validate_digest("a".repeat(63).as_str()).is_err()); // too short
        assert!(validate_digest("a".repeat(65).as_str()).is_err()); // too long
    }

    // === Security-focused tests ===

    #[test]
    fn test_path_traversal_attacks() {
        // Various path traversal attempts that should all fail
        let attacks = [
            "../",
            "..\\",
            "../..",
            "..%2f",
            "..%5c",
            "%2e%2e/",
            "....//",
            "..../",
            "..\\/",
            "..;/",
            "..%00/",
            "..%0d/",
            "..%0a/",
            "foo/../bar",
            "foo/..\\bar",
        ];

        for attack in attacks {
            assert!(
                validate_backup_id(attack).is_err(),
                "Path traversal should be blocked: {}",
                attack
            );
            assert!(
                validate_filename(attack).is_err(),
                "Path traversal should be blocked: {}",
                attack
            );
        }
    }

    #[test]
    fn test_null_byte_injection() {
        // Null bytes can be used to truncate strings in some systems
        let attacks = [
            "file\x00.txt",
            "file%00.txt",
            "\x00malicious",
        ];

        for attack in attacks {
            // These should either fail or be sanitized
            let result = validate_filename(attack);
            assert!(
                result.is_err(),
                "Null byte should be blocked: {:?}",
                attack
            );
        }
    }

    #[test]
    fn test_command_injection_in_names() {
        // Characters that could be dangerous in shell contexts
        let attacks = [
            "$(whoami)",
            "`id`",
            "; rm -rf /",
            "| cat /etc/passwd",
            "& echo pwned",
            "$(cat /etc/passwd)",
        ];

        for attack in attacks {
            assert!(
                validate_backup_id(attack).is_err(),
                "Command injection should be blocked: {}",
                attack
            );
            assert!(
                validate_filename(attack).is_err(),
                "Command injection should be blocked: {}",
                attack
            );
        }
    }

    #[test]
    fn test_unicode_normalization_attacks() {
        // Unicode lookalikes and normalization issues
        let attacks = [
            "ａｄｍｉｎ", // fullwidth characters
            "admin\u{200b}", // zero-width space
            "\u{202e}nimda", // right-to-left override
        ];

        for attack in attacks {
            let result = validate_backup_id(attack);
            // These should fail because they don't match the ASCII regex
            assert!(
                result.is_err(),
                "Unicode attack should be blocked: {:?}",
                attack
            );
        }
    }

    #[test]
    fn test_windows_reserved_names() {
        // Windows reserved device names
        let reserved = [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4",
            "LPT1", "LPT2", "LPT3",
            "con", "prn", "aux", // lowercase
        ];

        for name in reserved {
            assert!(
                validate_backup_id(name).is_err(),
                "Windows reserved name should be blocked: {}",
                name
            );
        }
    }

    #[test]
    fn test_sql_injection_in_names() {
        // SQL injection patterns that should be blocked by regex
        let attacks = [
            "'; DROP TABLE backups;--",
            "1' OR '1'='1",
            "admin'--",
            "UNION SELECT * FROM users",
        ];

        for attack in attacks {
            assert!(
                validate_backup_id(attack).is_err(),
                "SQL injection should be blocked: {}",
                attack
            );
            assert!(
                validate_username(attack).is_err(),
                "SQL injection should be blocked: {}",
                attack
            );
        }
    }

    #[test]
    fn test_special_filenames() {
        // Special files that should be blocked
        let specials = [
            ".",
            "..",
            ".htaccess",
            ".git",
            ".svn",
            ".env",
            ".ssh",
        ];

        for name in specials {
            // Either blocked by reserved names or by starting-char validation
            let result = validate_filename(name);
            assert!(
                result.is_err(),
                "Special filename should be blocked: {}",
                name
            );
        }
    }

    #[test]
    fn test_boundary_lengths() {
        // Test exact boundary conditions

        // backup_id max is 64 characters
        let max_id = "a".repeat(64);
        assert!(validate_backup_id(&max_id).is_ok());
        let too_long_id = "a".repeat(65);
        assert!(validate_backup_id(&too_long_id).is_err());

        // filename max is 128 characters
        let max_filename = "a".repeat(128);
        assert!(validate_filename(&max_filename).is_ok());
        let too_long_filename = "a".repeat(129);
        assert!(validate_filename(&too_long_filename).is_err());

        // username max is 64 characters
        let max_username = "a".repeat(64);
        assert!(validate_username(&max_username).is_ok());
        let too_long_username = "a".repeat(65);
        assert!(validate_username(&too_long_username).is_err());
    }

    #[test]
    fn test_combined_attack_vectors() {
        // Combinations of attack techniques
        let attacks = [
            "../etc/passwd\x00.txt",
            "..\\..\\windows\\system32",
            "$(cat ../../../etc/passwd)",
            "`cat ../../../etc/passwd`",
            "file.txt; rm -rf /",
        ];

        for attack in attacks {
            assert!(
                validate_backup_id(attack).is_err(),
                "Combined attack should be blocked: {}",
                attack
            );
            assert!(
                validate_filename(attack).is_err(),
                "Combined attack should be blocked: {}",
                attack
            );
        }
    }
}
