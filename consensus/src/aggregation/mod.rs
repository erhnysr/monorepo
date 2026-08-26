//! Recover certificates for every position in a fixed per-epoch range.
//!
//! Each [`Engine`] has one immutable epoch, inclusive global position range, and signing scheme.
//! The signing scheme is the sole source of the application namespace. The engine requests and
//! signs every position in that range, keeps a bounded
//! window anchored at the lowest uncertified position, and exits only after the entire range is
//! certified. A durable identity header prevents a journal from being replayed under different
//! configuration.
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
