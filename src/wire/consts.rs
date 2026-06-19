//! Firebird wire-protocol constants.
//!
//! These mirror the public/impl headers shipped with Firebird
//! (`firebird/impl/consts_pub.h`, `iberror_c.h`, `Protocol.h`, `sqlda_pub.h`).
//! Only the subset needed by this driver is reproduced. Values are stable
//! across the wire and must not be changed.

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Operations (Protocol.h `P_OP`)
// ---------------------------------------------------------------------------

pub mod op {
    pub const VOID: i32 = 0;
    pub const CONNECT: i32 = 1;
    pub const EXIT: i32 = 2;
    pub const ACCEPT: i32 = 3;
    pub const REJECT: i32 = 4;
    pub const DISCONNECT: i32 = 6;
    pub const RESPONSE: i32 = 9;

    pub const ATTACH: i32 = 19;
    pub const CREATE: i32 = 20;
    pub const DETACH: i32 = 21;

    pub const TRANSACTION: i32 = 29;
    pub const COMMIT: i32 = 30;
    pub const ROLLBACK: i32 = 31;
    pub const PREPARE: i32 = 32;

    pub const INFO_DATABASE: i32 = 40;
    pub const INFO_TRANSACTION: i32 = 42;

    pub const COMMIT_RETAINING: i32 = 50;

    pub const OPEN_BLOB2: i32 = 55;
    pub const CREATE_BLOB2: i32 = 56;
    pub const GET_SEGMENT: i32 = 36;
    pub const PUT_SEGMENT: i32 = 37;
    pub const CANCEL_BLOB: i32 = 38;
    pub const CLOSE_BLOB: i32 = 39;
    pub const INFO_BLOB: i32 = 43;
    pub const SEEK_BLOB: i32 = 60;

    pub const ALLOCATE_STATEMENT: i32 = 62;
    pub const EXECUTE: i32 = 63;
    pub const EXEC_IMMEDIATE: i32 = 64;
    pub const FETCH: i32 = 65;
    pub const FETCH_RESPONSE: i32 = 66;
    pub const FREE_STATEMENT: i32 = 67;
    pub const PREPARE_STATEMENT: i32 = 68;
    pub const SET_CURSOR: i32 = 69;
    pub const INFO_SQL: i32 = 70;

    pub const DUMMY: i32 = 71;

    pub const EXEC_IMMEDIATE2: i32 = 75;
    pub const EXECUTE2: i32 = 76;
    pub const SQL_RESPONSE: i32 = 78;

    pub const DROP_DATABASE: i32 = 81;

    pub const SERVICE_ATTACH: i32 = 82;
    pub const SERVICE_DETACH: i32 = 83;
    pub const SERVICE_INFO: i32 = 84;
    pub const SERVICE_START: i32 = 85;

    pub const ROLLBACK_RETAINING: i32 = 86;

    pub const TRUSTED_AUTH: i32 = 90;
    pub const CANCEL: i32 = 91;
    pub const CONT_AUTH: i32 = 92;
    pub const PING: i32 = 93;
    pub const ACCEPT_DATA: i32 = 94;
    pub const ABORT_AUX_CONNECTION: i32 = 95;
    pub const CRYPT: i32 = 96;
    pub const CRYPT_KEY_CALLBACK: i32 = 97;
    pub const COND_ACCEPT: i32 = 98;

    // Batch (FB4+) — the headline array-DML feature.
    pub const BATCH_CREATE: i32 = 99;
    pub const BATCH_MSG: i32 = 100;
    pub const BATCH_EXEC: i32 = 101;
    pub const BATCH_RLS: i32 = 102;
    pub const BATCH_CS: i32 = 103;
    pub const BATCH_REGBLOB: i32 = 104;
    pub const BATCH_BLOB_STREAM: i32 = 105;
    pub const BATCH_SET_BPB: i32 = 106;

    pub const REPL_DATA: i32 = 107;
    pub const REPL_REQ: i32 = 108;

    pub const BATCH_CANCEL: i32 = 109;
    pub const BATCH_SYNC: i32 = 110;
    pub const INFO_BATCH: i32 = 111;

    // FB5
    pub const FETCH_SCROLL: i32 = 112;
    pub const INFO_CURSOR: i32 = 113;
}

// ---------------------------------------------------------------------------
// Protocol versions and connection negotiation
// ---------------------------------------------------------------------------

/// High bit set on every protocol version offered/accepted in modern Firebird.
pub const FB_PROTOCOL_FLAG: i32 = 0x8000;
/// Mask used to recover the base version from an accepted protocol value.
pub const FB_PROTOCOL_MASK: i32 = !FB_PROTOCOL_FLAG;

pub const PROTOCOL_VERSION10: i32 = 10;
pub const PROTOCOL_VERSION11: i32 = FB_PROTOCOL_FLAG | 11;
pub const PROTOCOL_VERSION12: i32 = FB_PROTOCOL_FLAG | 12;
pub const PROTOCOL_VERSION13: i32 = FB_PROTOCOL_FLAG | 13;
pub const PROTOCOL_VERSION14: i32 = FB_PROTOCOL_FLAG | 14;
pub const PROTOCOL_VERSION15: i32 = FB_PROTOCOL_FLAG | 15;
pub const PROTOCOL_VERSION16: i32 = FB_PROTOCOL_FLAG | 16; // FB4: batch, stmt timeout
pub const PROTOCOL_VERSION17: i32 = FB_PROTOCOL_FLAG | 17; // FB4: cancel, etc.
pub const PROTOCOL_VERSION18: i32 = FB_PROTOCOL_FLAG | 18; // FB5: fetch scroll, info batch
pub const PROTOCOL_VERSION19: i32 = FB_PROTOCOL_FLAG | 19; // FB5.0.x

/// `p_cnct_cversion` — connect block version (CONNECT_VERSION3 carries crypt info).
pub const CONNECT_VERSION3: i32 = 3;

/// Architecture identifier (`arch_generic`).
pub const ARCH_GENERIC: i32 = 1;

/// `ptype_*` — minimum/maximum acceptable protocol *type* per offered version.
pub const PTYPE_PAGE: i32 = 1; // page-server (unused)
pub const PTYPE_RPC: i32 = 2; // simple remote procedure call
pub const PTYPE_BATCH_SEND: i32 = 3; // batch sends, no asynchrony
pub const PTYPE_OUT_OF_BAND: i32 = 4; // batch sends w/ out-of-band notification
pub const PTYPE_LAZY_SEND: i32 = 5; // deferred packet delivery

/// Bit OR-ed into `p_acpt_type` to indicate compression and architecture, FB-specific.
pub const PFLAG_COMPRESS: i32 = 0x100;

// ---------------------------------------------------------------------------
// CNCT clumplet tags (connect block, user identification)
// ---------------------------------------------------------------------------

pub mod cnct {
    pub const USER: u8 = 1; // OS user name
    pub const PASSWD: u8 = 2;
    pub const HOST: u8 = 4; // client host name
    pub const GROUP: u8 = 5; // effective Unix group id
    pub const USER_VERIFICATION: u8 = 6;
    pub const SPECIFIC_DATA: u8 = 7; // auth plugin data, chunked
    pub const PLUGIN_NAME: u8 = 8; // plugin that produced specific_data
    pub const LOGIN: u8 = 9; // modern login (same as isc_dpb_user_name)
    pub const PLUGIN_LIST: u8 = 10; // plugins available on the client
    pub const CLIENT_CRYPT: u8 = 11; // desired wire-crypt level
}

/// Values for `cnct::CLIENT_CRYPT` (and DPB wire-crypt level).
pub mod wire_crypt {
    pub const DISABLED: i32 = 0;
    pub const ENABLED: i32 = 1;
    pub const REQUIRED: i32 = 2;
}

// ---------------------------------------------------------------------------
// DPB — Database Parameter Buffer (consts_pub.h `isc_dpb_*`)
// ---------------------------------------------------------------------------

/// DPB version byte that prefixes the buffer.
pub const DPB_VERSION1: u8 = 1;
pub const DPB_VERSION2: u8 = 2; // strings as UTF-8, lengths as 4 bytes

pub mod dpb {
    pub const PAGE_SIZE: u8 = 4;
    pub const NUM_BUFFERS: u8 = 5;
    pub const DBKEY_SCOPE: u8 = 13;
    pub const SQL_DIALECT: u8 = 63;
    pub const SET_DB_CHARSET: u8 = 68;
    pub const FORCE_WRITE: u8 = 24;
    pub const NO_RESERVE: u8 = 27;
    pub const USER_NAME: u8 = 28;
    pub const PASSWORD: u8 = 29;
    pub const PASSWORD_ENC: u8 = 30;
    pub const LC_CTYPE: u8 = 48; // connection charset
    pub const ROLE_NAME: u8 = 60;
    pub const CONNECT_TIMEOUT: u8 = 57;
    pub const PROCESS_ID: u8 = 71;
    pub const PROCESS_NAME: u8 = 112;
    pub const TRUSTED_AUTH: u8 = 111;
    pub const UTF8_FILENAME: u8 = 77;
    pub const SPECIFIC_AUTH_DATA: u8 = 84;
    pub const AUTH_PLUGIN_LIST: u8 = 85;
    pub const AUTH_PLUGIN_NAME: u8 = 86;
    pub const CONFIG: u8 = 87;
    pub const NOLINGER: u8 = 88;
    pub const RESET_ICU: u8 = 89;
    pub const MAP_ATTACH: u8 = 90;
    pub const SESSION_TIME_ZONE: u8 = 91;
    pub const SET_DB_REPLICA: u8 = 92;
    pub const SET_BIND: u8 = 93;
    pub const DECFLOAT_ROUND: u8 = 94;
    pub const DECFLOAT_TRAPS: u8 = 95;
    pub const CLIENT_VERSION: u8 = 80;
    pub const PARALLEL_WORKERS: u8 = 100; // FB5
}

// ---------------------------------------------------------------------------
// TPB — Transaction Parameter Buffer (`isc_tpb_*`)
// ---------------------------------------------------------------------------

pub const TPB_VERSION3: u8 = 3;

pub mod tpb {
    pub const CONSISTENCY: u8 = 1;
    pub const CONCURRENCY: u8 = 2;
    pub const SHARED: u8 = 3;
    pub const PROTECTED: u8 = 4;
    pub const EXCLUSIVE: u8 = 5;
    pub const WAIT: u8 = 6;
    pub const NOWAIT: u8 = 7;
    pub const READ: u8 = 8;
    pub const WRITE: u8 = 9;
    pub const LOCK_READ: u8 = 10;
    pub const LOCK_WRITE: u8 = 11;
    pub const VERB_TIME: u8 = 12;
    pub const COMMIT_TIME: u8 = 13;
    pub const IGNORE_LIMBO: u8 = 14;
    pub const READ_COMMITTED: u8 = 15;
    pub const AUTOCOMMIT: u8 = 16;
    pub const REC_VERSION: u8 = 17;
    pub const NO_REC_VERSION: u8 = 18;
    pub const RESTART_REQUESTS: u8 = 19;
    pub const NO_AUTO_UNDO: u8 = 20;
    pub const LOCK_TIMEOUT: u8 = 21;
    pub const READ_CONSISTENCY: u8 = 22; // FB4+
    pub const AT_SNAPSHOT_NUMBER: u8 = 23; // FB4+
}

// ---------------------------------------------------------------------------
// SQL information items (`isc_info_sql_*`) used after prepare
// ---------------------------------------------------------------------------

pub mod isql {
    pub const SELECT: u8 = 4;
    pub const BIND: u8 = 5;
    pub const NUM_VARIABLES: u8 = 6;
    pub const DESCRIBE_VARS: u8 = 7;
    pub const DESCRIBE_END: u8 = 8;
    pub const SQLDA_SEQ: u8 = 9;
    pub const MESSAGE_SEQ: u8 = 10;
    pub const TYPE: u8 = 11;
    pub const SUB_TYPE: u8 = 12;
    pub const SCALE: u8 = 13;
    pub const LENGTH: u8 = 14;
    pub const NULL_IND: u8 = 15;
    pub const FIELD: u8 = 16;
    pub const RELATION: u8 = 17;
    pub const ALIAS: u8 = 18;
    pub const OWNER: u8 = 19;
    pub const RELATION_ALIAS: u8 = 20;
    pub const STMT_TYPE: u8 = 21;
    pub const BATCH_FETCH: u8 = 22;
    pub const RECORDS: u8 = 23;
    pub const AFFECTED_RECORDS: u8 = 24;
    pub const EXPLAIN_PLAN: u8 = 25;
    pub const FLAGS: u8 = 26;
}

/// Statement types returned by `isc_info_sql_stmt_type`.
pub mod stmt_type {
    pub const SELECT: i32 = 1;
    pub const INSERT: i32 = 2;
    pub const UPDATE: i32 = 3;
    pub const DELETE: i32 = 4;
    pub const DDL: i32 = 5;
    pub const GET_SEGMENT: i32 = 6;
    pub const PUT_SEGMENT: i32 = 7;
    pub const EXEC_PROCEDURE: i32 = 8;
    pub const START_TRANS: i32 = 9;
    pub const COMMIT: i32 = 10;
    pub const ROLLBACK: i32 = 11;
    pub const SELECT_FOR_UPD: i32 = 12;
    pub const SET_GENERATOR: i32 = 13;
    pub const SAVEPOINT: i32 = 14;
}

/// `op_free_statement` modes.
pub mod free {
    pub const CLOSE: i32 = 1;
    pub const DROP: i32 = 2;
    pub const UNPREPARE: i32 = 4;
}

/// `op_fetch_scroll` directions (FB5).
pub mod scroll {
    pub const NEXT: i32 = 0;
    pub const PRIOR: i32 = 1;
    pub const FIRST: i32 = 2;
    pub const LAST: i32 = 3;
    pub const ABSOLUTE: i32 = 4;
    pub const RELATIVE: i32 = 5;
}

// ---------------------------------------------------------------------------
// Generic info-buffer terminators / status
// ---------------------------------------------------------------------------

pub const INFO_END: u8 = 1;
pub const INFO_TRUNCATED: u8 = 2;
pub const INFO_ERROR: u8 = 3;
pub const INFO_DATA_NOT_READY: u8 = 4;

// ---------------------------------------------------------------------------
// Status vector tags (`isc_arg_*`)
// ---------------------------------------------------------------------------

pub mod arg {
    pub const END: i32 = 0;
    pub const GDS: i32 = 1; // Firebird error code
    pub const STRING: i32 = 2;
    pub const CSTRING: i32 = 3;
    pub const NUMBER: i32 = 4;
    pub const INTERPRETED: i32 = 5;
    pub const VMS: i32 = 6;
    pub const UNIX: i32 = 7;
    pub const DOMAIN: i32 = 8;
    pub const DOS: i32 = 9;
    pub const MPEXL: i32 = 10;
    pub const WARNING: i32 = 18;
    pub const SQL_STATE: i32 = 19; // SQLSTATE string (FB2.5+)
}

// ---------------------------------------------------------------------------
// SQL data types (`SQL_*`, sqlda_pub.h). Low bit = nullable flag.
// ---------------------------------------------------------------------------

pub mod sql_type {
    pub const TEXT: i32 = 452;
    pub const VARYING: i32 = 448;
    pub const SHORT: i32 = 500;
    pub const LONG: i32 = 496;
    pub const FLOAT: i32 = 482;
    pub const DOUBLE: i32 = 480;
    pub const D_FLOAT: i32 = 530;
    pub const TIMESTAMP: i32 = 510;
    pub const BLOB: i32 = 520;
    pub const ARRAY: i32 = 540;
    pub const QUAD: i32 = 550;
    pub const TYPE_TIME: i32 = 560;
    pub const TYPE_DATE: i32 = 570;
    pub const INT64: i32 = 580;
    pub const INT128: i32 = 32752; // FB4+
    pub const TIMESTAMP_TZ_EX: i32 = 32748;
    pub const TIME_TZ_EX: i32 = 32750;
    pub const TIMESTAMP_TZ: i32 = 32754; // FB4+
    pub const TIME_TZ: i32 = 32756; // FB4+
    pub const DEC16: i32 = 32760; // DECFLOAT(16), FB4+
    pub const DEC34: i32 = 32762; // DECFLOAT(34), FB4+
    pub const BOOLEAN: i32 = 32764; // FB3+
    pub const NULL: i32 = 32766;

    /// Strip the nullable low bit to get the base type.
    #[inline]
    pub const fn base(t: i32) -> i32 {
        t & !1
    }
    /// True when the type's low bit marks it nullable.
    #[inline]
    pub const fn is_nullable(t: i32) -> bool {
        t & 1 != 0
    }
}

// ---------------------------------------------------------------------------
// Blob parameter buffer (`isc_bpb_*`) and blob info
// ---------------------------------------------------------------------------

pub const BPB_VERSION1: u8 = 1;

pub mod bpb {
    pub const SOURCE_TYPE: u8 = 1;
    pub const TARGET_TYPE: u8 = 2;
    pub const TYPE: u8 = 3;
    pub const STORAGE: u8 = 7;
}

/// Blob subtypes.
pub mod blob_type {
    pub const SEGMENTED: i32 = 0;
    pub const STREAM: i32 = 1;
}

// ---------------------------------------------------------------------------
// Batch parameter buffer (`IBatch` tags) and info items (FB4+)
// ---------------------------------------------------------------------------

/// Tags for the batch creation parameter buffer (`Firebird::IBatch::TAG_*`).
pub mod batch_tag {
    pub const MULTIERROR: u8 = 1; // continue after per-row errors
    pub const RECORD_COUNTS: u8 = 2; // report per-message affected counts
    pub const BUFFER_BYTES_SIZE: u8 = 3; // server-side buffer cap
    pub const BLOB_POLICY: u8 = 4;
    pub const DETAILED_ERRORS: u8 = 5;
}

/// Values for `batch_tag::BLOB_POLICY`.
pub mod blob_policy {
    pub const NONE: u8 = 0;
    pub const ID_ENGINE: u8 = 1; // engine assigns ids
    pub const ID_USER: u8 = 2; // caller assigns ids
    pub const STREAM: u8 = 3;
}

/// Batch info items (`IBatch` info, FB4+) returned by `op_info_batch`.
pub mod batch_info {
    pub const VERSION: u8 = 1;
    pub const BLOB_ALIGNMENT: u8 = 2;
    pub const BLOB_HEADER: u8 = 3;
    pub const ROW_SIZE: u8 = 4;
    pub const BUFFER_BYTES_SIZE: u8 = 5;
}

/// Completion-state codes from `op_batch_cs` (`IBatchCompletionState`).
pub mod batch_cs {
    /// Per-message return code meaning "no records affected info available".
    pub const NO_MORE_ERRORS: i32 = -1;
    pub const EXECUTE_FAILED: i32 = -2;
    pub const SUCCESS_NO_INFO: i32 = -3;
}
