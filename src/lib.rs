//! # fdb_driver
//!
//! A pure-Rust, asynchronous driver for **Firebird 5+**, speaking the native
//! wire protocol directly over TCP — no `libfbclient` dependency.
//!
//! Highlights:
//! - Async/await on [Tokio](https://tokio.rs).
//! - SRP / Srp256 authentication with optional ARC4 / ChaCha20 wire encryption.
//! - Prepared statements, scrollable cursors (FB5), transactions.
//! - **Batch / array DML** via the FB4+ batch protocol (`op_batch_*`).
//! - Connection pooling.
//!
//! The crate is built up in layers; see the module documentation for details.
//! This is work in progress — see the crate README for the implemented surface.

#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod connection;
pub mod error;
pub mod transaction;
pub mod wire;

pub use config::{ConnectConfig, WireCrypt};
pub use connection::Connection;
pub use error::{DatabaseError, Error, Result, StatusArg, StatusVector};
pub use transaction::{AccessMode, IsolationLevel, LockResolution, Transaction, TransactionBuilder};
