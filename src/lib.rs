//! Pure contracts for SkillRanker. Effects belong at explicit application boundaries.
#![forbid(unsafe_code)]

pub mod adapter;
pub mod allowance;
pub mod authorized_read;
pub mod blocking;
pub mod breaker;
pub mod cache;
pub mod capabilities;
pub mod cli;
pub mod config;
pub mod context;
pub mod demo;
pub mod effects;
pub mod eligibility;
pub mod evaluation;
pub mod experiments;
// Descriptor filesystem classification for Unix-only persistent state.
#[cfg(unix)]
mod filesystem_policy;
pub mod identity;
pub mod installer;
pub mod jev;
pub mod learning;
pub mod limits;
mod os_random;
pub mod output;
pub mod pipeline;
mod platform_path;
pub mod platform_support;
pub mod privacy;
pub mod readiness;
pub mod replay;
pub mod roster;
pub mod runtime;
pub mod scoring;
pub mod snooze;
pub mod sqlite_engine;
// Compiled everywhere. Unix and Windows (`storage::windows_private`) admit
// private store directories; on other platforms every store open reports
// `UnsupportedFilesystem`.
pub mod storage;
pub mod subprocess;
