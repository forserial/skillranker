//! Win32 security-descriptor and volume reads for SkillRanker's Windows
//! storage port (sr-winpar.2), plus the one thread call that cancels a stalled
//! stdin read (sr-winpar.15).
//!
//! `sr` itself forbids unsafe code. This package is the one place that may call
//! Win32, and only in [`windows`]: every call takes a borrowed, already-open
//! handle (or the process token), copies what it returns into owned values,
//! and frees what Windows allocated before returning. Everything that
//! interprets those bytes ([`sid`], [`acl`]) is safe code that also builds and
//! is tested on Unix.
//!
//! The policy these reads serve is docs/windows-private-storage.md. Deciding
//! whether a descriptor or volume satisfies it belongs to the caller, not here.

#![cfg_attr(not(windows), forbid(unsafe_code))]

pub mod acl;
pub mod sid;

#[cfg(windows)]
pub mod windows;

pub use acl::{Ace, AceKind, Descriptor};
pub use sid::Sid;
