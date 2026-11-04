//! Warden library: scan engine, checks, signatures, sandbox, and report model.
//!
//! The CLI (`src/main.rs`) and the desktop app (`apps/warden-gui`) share this
//! crate so detection logic and report rendering never fork.

pub mod allowlist;
pub mod baseline;
pub mod checks;
pub mod clamav;
pub mod ctx;
pub mod defaults;
pub mod engine;
pub mod heuristics;
pub mod intel;
pub mod malicious;
pub mod model;
pub mod osv;
pub mod output;
pub mod policy;
pub mod sandbox;
pub mod selftest;
pub mod signatures;
pub mod tui;
pub mod util;
