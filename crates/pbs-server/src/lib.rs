//! PBS-compatible HTTP/2 backup server
//!
//! This crate implements the PBS backup protocol over HTTP/2,
//! enabling compatibility with the stock proxmox-backup-client.

pub mod api;
pub mod config;
pub mod protocol;
pub mod server;
pub mod tenant;
