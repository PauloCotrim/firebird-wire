//! # fdb_driver
//!
//! Um driver assíncrono, puramente em Rust, para o **Firebird 5+**, que fala o
//! protocolo de comunicação nativo (wire protocol) diretamente sobre TCP — sem
//! dependência do `libfbclient`.
//!
//! Destaques:
//! - Async/await com [Tokio](https://tokio.rs).
//! - Autenticação SRP / Srp256 com criptografia de comunicação opcional ARC4 / ChaCha20.
//! - Prepared statements, cursores roláveis (FB5), transações.
//! - **DML em lote / array** via o protocolo de batch do FB4+ (`op_batch_*`).
//! - Pool de conexões.
//!
//! A crate é construída em camadas; veja a documentação dos módulos para detalhes.
//! Isto é um trabalho em andamento — veja o README da crate para a superfície já implementada.

#![forbid(unsafe_code)]

pub mod auth;
pub mod blr;
pub mod config;
pub mod connection;
pub mod error;
pub mod message;
pub mod statement;
pub mod transaction;
pub mod value;
pub mod wire;

pub use config::{ConnectConfig, WireCrypt};
pub use connection::Connection;
pub use error::{DatabaseError, Error, Result, StatusArg, StatusVector};
pub use statement::Statement;
pub use transaction::{AccessMode, IsolationLevel, LockResolution, Transaction, TransactionBuilder};
pub use value::{ColumnMeta, Value};
