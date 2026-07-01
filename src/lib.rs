//! # firebird-wire
//!
//! Um driver síncrono, puramente em Rust, para o **Firebird 5+**, que fala o
//! protocolo de comunicação nativo (wire protocol) diretamente sobre TCP — sem
//! dependência do `libfbclient`.
//!
//! ## Por onde começar
//!
//! Se você só quer usar o banco, comece por estes tipos:
//!
//! - [`ConnectConfig`]: dados de host, banco, usuário e senha.
//! - [`Connection`]: a conexão aberta com o Firebird.
//! - [`Transaction`]: o bloco de trabalho confirmado por `commit` ou desfeito
//!   por `rollback`.
//! - [`Statement`]: um SQL preparado para executar e buscar linhas.
//! - [`Value`]: valores enviados como parâmetros ou recebidos em linhas.
//!
//! Um primeiro uso costuma seguir esta ordem:
//!
//! ```no_run
//! use firebird_wire::{ConnectConfig, Connection, Value};
//!
//! fn main() -> firebird_wire::Result<()> {
//!     let cfg = ConnectConfig::new()
//!         .host("127.0.0.1")
//!         .port(3050)
//!         .database("/dados/app.fdb")
//!         .user("SYSDBA")
//!         .password("masterkey");
//!
//!     let mut conn = Connection::connect(&cfg)?;
//!     let tx = conn.begin()?;
//!
//!     let mut stmt = conn.prepare(&tx, "SELECT ? FROM RDB$DATABASE")?;
//!     stmt.execute(&mut conn, &tx, &[Value::Int(42)])?;
//!     if let Some(row) = stmt.fetch(&mut conn)? {
//!         println!("{:?}", row[0]);
//!     }
//!     stmt.drop_statement(&mut conn)?;
//!
//!     tx.commit(&mut conn)?;
//!     conn.close()?;
//!     Ok(())
//! }
//! ```
//!
//! Para uma explicação mais didática, leia `COMECE-AQUI.md` no repositório.
//!
//! Destaques:
//! - API bloqueante baseada na biblioteca padrão.
//! - Autenticação SRP / Srp256 com criptografia de comunicação opcional ARC4 / ChaCha20.
//! - Prepared statements, cursores roláveis (FB5), transações.
//! - **DML em lote / array** via o protocolo de batch do FB4+ (`op_batch_*`).
//! - Pool de conexões.
//! - **Gerenciador de serviços** (`op_service_*`): versão do servidor, log, etc.
//!
//! A crate é construída em camadas. Os módulos `wire`, `auth`, `blr`, `message`
//! e similares são implementação de baixo nível; para uso comum prefira os tipos
//! reexportados no topo da crate.
//! Isto é um trabalho em andamento — veja o README da crate para a superfície já implementada.

#![forbid(unsafe_code)]

pub mod array;
pub mod auth;
pub mod batch;
pub mod blob;
pub mod blr;
pub mod charset;
pub mod config;
pub mod connection;
pub mod decfloat;
pub mod dos;
pub mod error;
pub mod events;
pub mod message;
pub mod pool;
pub mod service;
pub mod statement;
pub mod transaction;
pub mod tz;
pub mod value;
pub mod wire;

pub use array::{ArrayDesc, Dimension};
pub use batch::{Batch, BatchError, BatchOptions, BatchResult};
pub use blob::{Blob, BlobWriter};
pub use charset::Charset;
pub use config::{ConnectConfig, WireCrypt};
pub use connection::Connection;
pub use decfloat::{DecFloat, ParseDecFloatError};
pub use error::{DatabaseError, Error, Result, StatusArg, StatusVector};
pub use events::EventListener;
pub use pool::{Pool, PoolConfig, PooledConnection};
pub use service::{ServiceManager, UserInfo, UserParams};
pub use statement::{RowStream, RowsAffected, Statement};
pub use transaction::{
    AccessMode, IsolationLevel, LockResolution, Transaction, TransactionBuilder,
};
pub use value::{
    CivilDate, CivilTime, CivilTimestamp, ColumnMeta, TimeTz, TimestampTz, Value, ValueRef,
};

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
