//! persistence — SQLite, Caching und Scan-Historie
//! persistence — SQLite, caching, and scan history

pub mod db;
pub mod delta;
pub mod identity_cache;
pub mod migrations;
pub mod scan_store;

pub use db::Database;
pub use delta::{compare_scans, DeltaEntry, DeltaKind};
pub use identity_cache::IdentityCache;
pub use scan_store::ScanStore;
