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
pub mod batch;
pub mod blob;
pub mod charset;
pub mod blr;
pub mod config;
pub mod connection;
pub mod error;
pub mod message;
pub mod pool;
pub mod statement;
pub mod transaction;
pub mod value;
pub mod wire;

pub use batch::{Batch, BatchError, BatchResult};
pub use blob::{Blob, BlobWriter};
pub use charset::Charset;
pub use config::{ConnectConfig, WireCrypt};
pub use connection::Connection;
pub use error::{DatabaseError, Error, Result, StatusArg, StatusVector};
pub use pool::{Pool, PoolConfig, PooledConnection};
pub use statement::{RowStream, RowsAffected, Statement};
pub use transaction::{AccessMode, IsolationLevel, LockResolution, Transaction, TransactionBuilder};
pub use value::{CivilDate, CivilTime, CivilTimestamp, ColumnMeta, Value};

/// Emite um aviso (apenas em builds de debug) quando um recurso com estado no
/// servidor (`Statement`, `Transaction`, `Blob`, `BlobWriter`) é solto sem ser
/// liberado explicitamente. O handle permanece alocado no servidor até o
/// `detach`; este aviso ajuda a localizar vazamentos durante o desenvolvimento.
/// Em builds de release é um no-op (sem custo).
#[inline]
pub(crate) fn warn_unclosed(kind: &str, handle: i32) {
    if cfg!(debug_assertions) {
        eprintln!(
            "[fdb] aviso: {kind} (handle {handle}) foi descartado sem fechar/liberar; \
             o estado fica no servidor até o detach. Chame o método de fechamento adequado."
        );
    }
}
