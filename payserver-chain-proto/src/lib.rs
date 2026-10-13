//! The chain adapter wire contract.
//!
//! `proto/payserver/chain/v1/chain.proto` is the contract; this crate is its
//! Rust rendering. The generated messages live in [`v1`]. The validating
//! domain types in [`event`] are the boundary: a malformed amount or address
//! becomes a named [`ProtocolError`] here rather than an opaque failure in
//! whatever consumes it later.
//!
//! Kept out of `types` on purpose, which is compiled into the browser client;
//! prost and tonic must not enter that dependency graph.

pub mod event;
pub mod negotiate;

/// Generated messages and the tonic service.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod v1 {
    tonic::include_proto!("payserver.chain.v1");
}

/// The package name of the contract this crate implements.
pub const CONTRACT_V1: &str = "payserver.chain.v1";

pub use event::{
    AdapterState, Amount, ChainEvent, ChainEventKind, ChainText, PaymentRef, ProtocolError,
    WatchSpec,
};
pub use negotiate::{NegotiationError, negotiate};
