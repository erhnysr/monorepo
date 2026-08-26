//! Recover certificates for every position in a fixed per-epoch range.
//!
//! Each [`Engine`] has one immutable epoch, inclusive global position range, and signing scheme.
//! The signing scheme is the sole source of the application namespace. The engine requests and
//! signs every position in that range. It keeps a bounded window anchored at the lowest
//! uncertified position. The engine returns `Completed` only after the entire range is certified;
//! shutdown returns `Stopped`. A durable header binds the journal to its committee, epoch, range,
//! and window. Replay revalidates each signed record because the header cannot fingerprint all
//! scheme verification material.
//!
//! ## Epoch-independent signatures
//!
//! An [`Item`](types::Item) signature covers only its position and digest. Acknowledgments travel
//! over an epoch-specific channel, which associates each share with the engine's epoch. The epoch
//! in an exported [`Certificate`](types::Certificate) is unsigned lookup metadata. Before
//! verification, a consumer must derive the expected epoch, inclusive position range, and signing
//! scheme from authenticated history. [`Certificate::verify_for`](types::Certificate::verify_for)
//! checks the epoch and range before verifying the signature.
//!
//! This module is the live aggregation core. Resolving certificates missed while offline is a
//! sibling recovery responsibility. Archiving the complete range and retiring the engine and its
//! journal are application/orchestrator responsibilities. Recovered certificates enter an active
//! engine through [`Mailbox`], which applies the same range and signature checks used by recovery.

pub mod scheme;
pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::{CertificateOutcome, Engine, EngineOutcome, Mailbox};
        mod metrics;

        #[cfg(test)]
        pub mod mocks;
    }
}

#[cfg(test)]
mod tests;
