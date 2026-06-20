//! Transações: construção do TPB, início e commit/rollback (com variantes
//! retentivas).
//!
//! Uma [`Transaction`] é um handle leve; os métodos reais de I/O recebem a
//! [`Connection`] proprietária para que apenas um empréstimo mutável esteja
//! ativo por vez. `commit`/`rollback` consomem o handle; as variantes
//! retentivas o mantêm. Descartar uma `Transaction` sem finalizá-la deixa a
//! transação do lado do servidor aberta até a conexão se desconectar — sempre
//! finalize explicitamente.

use crate::connection::Connection;
use crate::error::Result;
use crate::wire::consts::*;
use crate::wire::response::read_response;
use crate::wire::stream::op_packet;
use crate::wire::xdr::ParameterBuffer;

/// Nível de isolamento da transação.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsolationLevel {
    /// `SNAPSHOT` (Firebird `concurrency`) — o padrão do engine.
    #[default]
    Snapshot,
    /// `SNAPSHOT TABLE STABILITY` (Firebird `consistency`).
    SnapshotTableStability,
    /// `READ COMMITTED` retornando a última versão de registro commitada.
    ReadCommittedRecordVersion,
    /// `READ COMMITTED` sem versões de registro (conflitos esperam/falham).
    ReadCommittedNoRecordVersion,
    /// `READ COMMITTED READ CONSISTENCY` (FB4+): snapshot estável por instrução.
    ReadCommittedReadConsistency,
}

/// Modo de acesso de leitura e escrita.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessMode {
    #[default]
    ReadWrite,
    ReadOnly,
}

/// Comportamento em caso de conflito de bloqueio (lock).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockResolution {
    #[default]
    Wait,
    NoWait,
}

/// Construtor (builder) para o Transaction Parameter Buffer.
#[derive(Debug, Clone, Default)]
pub struct TransactionBuilder {
    pub isolation: IsolationLevel,
    pub access: AccessMode,
    pub lock_resolution: LockResolution,
    /// Timeout de bloqueio (lock) em segundos (só faz sentido com [`LockResolution::Wait`]).
    pub lock_timeout: Option<i32>,
    /// Desabilita o log de undo por instrução (mais rápido, sem savepoints).
    pub no_auto_undo: bool,
    /// Faz commit automático de cada instrução DML no lado do servidor.
    pub auto_commit: bool,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn isolation(mut self, level: IsolationLevel) -> Self {
        self.isolation = level;
        self
    }
    pub fn read_only(mut self) -> Self {
        self.access = AccessMode::ReadOnly;
        self
    }
    pub fn read_write(mut self) -> Self {
        self.access = AccessMode::ReadWrite;
        self
    }
    pub fn no_wait(mut self) -> Self {
        self.lock_resolution = LockResolution::NoWait;
        self
    }
    pub fn lock_timeout(mut self, seconds: i32) -> Self {
        self.lock_resolution = LockResolution::Wait;
        self.lock_timeout = Some(seconds);
        self
    }

    /// Serializa para um buffer de bytes TPB.
    pub fn build(&self) -> Vec<u8> {
        let mut pb = ParameterBuffer::new(TPB_VERSION3);

        match self.access {
            AccessMode::ReadWrite => pb.tag(tpb::WRITE),
            AccessMode::ReadOnly => pb.tag(tpb::READ),
        };

        match self.isolation {
            IsolationLevel::Snapshot => {
                pb.tag(tpb::CONCURRENCY);
            }
            IsolationLevel::SnapshotTableStability => {
                pb.tag(tpb::CONSISTENCY);
            }
            IsolationLevel::ReadCommittedRecordVersion => {
                pb.tag(tpb::READ_COMMITTED);
                pb.tag(tpb::REC_VERSION);
            }
            IsolationLevel::ReadCommittedNoRecordVersion => {
                pb.tag(tpb::READ_COMMITTED);
                pb.tag(tpb::NO_REC_VERSION);
            }
            IsolationLevel::ReadCommittedReadConsistency => {
                pb.tag(tpb::READ_COMMITTED);
                pb.tag(tpb::READ_CONSISTENCY);
            }
        }

        match self.lock_resolution {
            LockResolution::Wait => pb.tag(tpb::WAIT),
            LockResolution::NoWait => pb.tag(tpb::NOWAIT),
        };

        if let Some(t) = self.lock_timeout {
            pb.int(tpb::LOCK_TIMEOUT, t);
        }
        if self.no_auto_undo {
            pb.tag(tpb::NO_AUTO_UNDO);
        }
        if self.auto_commit {
            pb.tag(tpb::AUTOCOMMIT);
        }

        pb.into_vec()
    }
}

/// Uma transação iniciada (handle do servidor).
#[derive(Debug)]
pub struct Transaction {
    handle: i32,
    finished: bool,
}

impl Transaction {
    pub(crate) fn new(handle: i32) -> Self {
        Transaction { handle, finished: false }
    }

    /// O handle da transação do lado do servidor.
    pub fn handle(&self) -> i32 {
        self.handle
    }

    /// Faz commit e libera a transação.
    pub async fn commit(mut self, conn: &mut Connection) -> Result<()> {
        self.finish(conn, op::COMMIT).await
    }

    /// Faz rollback e libera a transação.
    pub async fn rollback(mut self, conn: &mut Connection) -> Result<()> {
        self.finish(conn, op::ROLLBACK).await
    }

    /// Faz commit mas mantém o contexto da transação (e o handle) ativo.
    pub async fn commit_retaining(&self, conn: &mut Connection) -> Result<()> {
        self.retain(conn, op::COMMIT_RETAINING).await
    }

    /// Faz rollback mas mantém o contexto da transação (e o handle) ativo.
    pub async fn rollback_retaining(&self, conn: &mut Connection) -> Result<()> {
        self.retain(conn, op::ROLLBACK_RETAINING).await
    }

    async fn finish(&mut self, conn: &mut Connection, opcode: i32) -> Result<()> {
        let mut w = op_packet(opcode);
        w.put_i32(self.handle);
        conn.io().send(&w).await?;
        read_response(conn.io()).await?;
        self.finished = true;
        Ok(())
    }

    async fn retain(&self, conn: &mut Connection, opcode: i32) -> Result<()> {
        let mut w = op_packet(opcode);
        w.put_i32(self.handle);
        conn.io().send(&w).await?;
        read_response(conn.io()).await?;
        Ok(())
    }
}

impl Connection {
    /// Inicia uma transação com parâmetros padrão (snapshot, leitura e escrita, wait).
    pub async fn begin(&mut self) -> Result<Transaction> {
        self.begin_with(&TransactionBuilder::default()).await
    }

    /// Inicia uma transação com parâmetros explícitos.
    pub async fn begin_with(&mut self, builder: &TransactionBuilder) -> Result<Transaction> {
        let tpb = builder.build();
        let mut w = op_packet(op::TRANSACTION);
        w.put_i32(self.db_handle());
        w.put_bytes(&tpb);
        self.io().send(&w).await?;
        let resp = read_response(self.io()).await?;
        Ok(Transaction::new(resp.handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tpb_is_write_concurrency_wait() {
        let tpb = TransactionBuilder::default().build();
        assert_eq!(tpb, vec![TPB_VERSION3, tpb::WRITE, tpb::CONCURRENCY, tpb::WAIT]);
    }

    #[test]
    fn read_committed_read_consistency_tpb() {
        let tpb = TransactionBuilder::new()
            .isolation(IsolationLevel::ReadCommittedReadConsistency)
            .read_only()
            .build();
        assert_eq!(
            tpb,
            vec![TPB_VERSION3, tpb::READ, tpb::READ_COMMITTED, tpb::READ_CONSISTENCY, tpb::WAIT]
        );
    }

    #[test]
    fn lock_timeout_tpb() {
        let tpb = TransactionBuilder::new().lock_timeout(10).build();
        // ... WAIT, depois o clumplet LOCK_TIMEOUT (tag, len=1, value=10).
        assert!(tpb.windows(3).any(|w| w == [tpb::LOCK_TIMEOUT, 1, 10]));
    }
}
