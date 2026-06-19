//! Transactions: TPB construction, start, and commit/rollback (with retaining
//! variants).
//!
//! A [`Transaction`] is a lightweight handle; the actual I/O methods take the
//! owning [`Connection`] so that only one mutable borrow is live at a time.
//! `commit`/`rollback` consume the handle; the retaining variants keep it.
//! Dropping a `Transaction` without finishing it leaves the server-side
//! transaction open until the connection detaches — always finish explicitly.

use crate::connection::Connection;
use crate::error::Result;
use crate::wire::consts::*;
use crate::wire::response::read_response;
use crate::wire::stream::op_packet;
use crate::wire::xdr::ParameterBuffer;

/// Transaction isolation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsolationLevel {
    /// `SNAPSHOT` (Firebird `concurrency`) — the engine default.
    #[default]
    Snapshot,
    /// `SNAPSHOT TABLE STABILITY` (Firebird `consistency`).
    SnapshotTableStability,
    /// `READ COMMITTED` returning the latest committed record version.
    ReadCommittedRecordVersion,
    /// `READ COMMITTED` without record versions (conflicts wait/fail).
    ReadCommittedNoRecordVersion,
    /// `READ COMMITTED READ CONSISTENCY` (FB4+): statement-stable snapshot.
    ReadCommittedReadConsistency,
}

/// Read/write access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessMode {
    #[default]
    ReadWrite,
    ReadOnly,
}

/// Behaviour on lock conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockResolution {
    #[default]
    Wait,
    NoWait,
}

/// Builder for the Transaction Parameter Buffer.
#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    pub isolation: IsolationLevel,
    pub access: AccessMode,
    pub lock_resolution: LockResolution,
    /// Lock timeout in seconds (only meaningful with [`LockResolution::Wait`]).
    pub lock_timeout: Option<i32>,
    /// Disable the per-statement undo log (faster, no savepoints).
    pub no_auto_undo: bool,
    /// Auto-commit each DML statement on the server side.
    pub auto_commit: bool,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        TransactionBuilder {
            isolation: IsolationLevel::default(),
            access: AccessMode::default(),
            lock_resolution: LockResolution::default(),
            lock_timeout: None,
            no_auto_undo: false,
            auto_commit: false,
        }
    }
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

    /// Serialise to a TPB byte buffer.
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

/// A started transaction (server handle).
#[derive(Debug)]
pub struct Transaction {
    handle: i32,
    finished: bool,
}

impl Transaction {
    pub(crate) fn new(handle: i32) -> Self {
        Transaction { handle, finished: false }
    }

    /// The server-side transaction handle.
    pub fn handle(&self) -> i32 {
        self.handle
    }

    /// Commit and release the transaction.
    pub async fn commit(mut self, conn: &mut Connection) -> Result<()> {
        self.finish(conn, op::COMMIT).await
    }

    /// Roll back and release the transaction.
    pub async fn rollback(mut self, conn: &mut Connection) -> Result<()> {
        self.finish(conn, op::ROLLBACK).await
    }

    /// Commit but keep the transaction context (and handle) active.
    pub async fn commit_retaining(&self, conn: &mut Connection) -> Result<()> {
        self.retain(conn, op::COMMIT_RETAINING).await
    }

    /// Roll back but keep the transaction context (and handle) active.
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
    /// Start a transaction with default parameters (snapshot, read-write, wait).
    pub async fn begin(&mut self) -> Result<Transaction> {
        self.begin_with(&TransactionBuilder::default()).await
    }

    /// Start a transaction with explicit parameters.
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
        // ... WAIT, then LOCK_TIMEOUT clumplet (tag, len=1, value=10).
        assert!(tpb.windows(3).any(|w| w == [tpb::LOCK_TIMEOUT, 1, 10]));
    }
}
