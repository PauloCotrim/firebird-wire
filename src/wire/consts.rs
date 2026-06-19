//! Constantes do protocolo de comunicação (wire protocol) do Firebird.
//!
//! Estas espelham os cabeçalhos public/impl distribuídos com o Firebird
//! (`firebird/impl/consts_pub.h`, `iberror_c.h`, `Protocol.h`, `sqlda_pub.h`).
//! Apenas o subconjunto necessário para este driver é reproduzido. Os valores são estáveis
//! ao longo do wire protocol e não devem ser alterados.

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Operações (Protocol.h `P_OP`)
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

    // Op codes de blob. A faixa baixa (34-43) é a clássica; os *_blob2 ficam na
    // faixa alta, logo antes de op_allocate_statement(62), e a enum é sequencial:
    // op_ddl=55, op_open_blob2=56, op_create_blob2=57, op_get_slice=58,
    // op_put_slice=59, op_slice=60, op_seek_blob=61.
    pub const CREATE_BLOB: i32 = 34;
    pub const OPEN_BLOB: i32 = 35;
    pub const GET_SEGMENT: i32 = 36;
    pub const PUT_SEGMENT: i32 = 37;
    pub const CANCEL_BLOB: i32 = 38;
    pub const CLOSE_BLOB: i32 = 39;
    pub const INFO_BLOB: i32 = 43;
    pub const OPEN_BLOB2: i32 = 56;
    pub const CREATE_BLOB2: i32 = 57;
    pub const SEEK_BLOB: i32 = 61;

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

    // Batch (FB4+) — o recurso principal de DML em array.
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
// Versões de protocolo e negociação de conexão
// ---------------------------------------------------------------------------

/// Bit alto setado em toda versão de protocolo oferecida/aceita no Firebird moderno.
pub const FB_PROTOCOL_FLAG: i32 = 0x8000;
/// Máscara usada para recuperar a versão base a partir de um valor de protocolo aceito.
pub const FB_PROTOCOL_MASK: i32 = !FB_PROTOCOL_FLAG;

pub const PROTOCOL_VERSION10: i32 = 10;
pub const PROTOCOL_VERSION11: i32 = FB_PROTOCOL_FLAG | 11;
pub const PROTOCOL_VERSION12: i32 = FB_PROTOCOL_FLAG | 12;
pub const PROTOCOL_VERSION13: i32 = FB_PROTOCOL_FLAG | 13;
pub const PROTOCOL_VERSION14: i32 = FB_PROTOCOL_FLAG | 14;
pub const PROTOCOL_VERSION15: i32 = FB_PROTOCOL_FLAG | 15;
pub const PROTOCOL_VERSION16: i32 = FB_PROTOCOL_FLAG | 16; // FB4: batch, timeout de stmt
pub const PROTOCOL_VERSION17: i32 = FB_PROTOCOL_FLAG | 17; // FB4: cancel, etc.
pub const PROTOCOL_VERSION18: i32 = FB_PROTOCOL_FLAG | 18; // FB5: fetch scroll, info batch
pub const PROTOCOL_VERSION19: i32 = FB_PROTOCOL_FLAG | 19; // FB5.0.x

/// `p_cnct_cversion` — versão do bloco connect (CONNECT_VERSION3 carrega info de crypt).
pub const CONNECT_VERSION3: i32 = 3;

/// Identificador de arquitetura (`arch_generic`).
pub const ARCH_GENERIC: i32 = 1;

/// `ptype_*` — *tipo* de protocolo mínimo/máximo aceitável por versão oferecida.
pub const PTYPE_PAGE: i32 = 1; // page-server (não usado)
pub const PTYPE_RPC: i32 = 2; // chamada de procedimento remoto simples
pub const PTYPE_BATCH_SEND: i32 = 3; // envios em batch, sem assincronia
pub const PTYPE_OUT_OF_BAND: i32 = 4; // envios em batch com notificação out-of-band
pub const PTYPE_LAZY_SEND: i32 = 5; // entrega de pacotes adiada

/// Bit feito OR em `p_acpt_type` para indicar compressão e arquitetura, específico do FB.
pub const PFLAG_COMPRESS: i32 = 0x100;

// ---------------------------------------------------------------------------
// Tags de clumplet CNCT (bloco connect, identificação de usuário)
// ---------------------------------------------------------------------------

pub mod cnct {
    pub const USER: u8 = 1; // nome de usuário do SO
    pub const PASSWD: u8 = 2;
    pub const HOST: u8 = 4; // nome do host do cliente
    pub const GROUP: u8 = 5; // id efetivo do grupo Unix
    pub const USER_VERIFICATION: u8 = 6;
    pub const SPECIFIC_DATA: u8 = 7; // dados do plugin de autenticação, em chunks
    pub const PLUGIN_NAME: u8 = 8; // plugin que produziu specific_data
    pub const LOGIN: u8 = 9; // login moderno (igual a isc_dpb_user_name)
    pub const PLUGIN_LIST: u8 = 10; // plugins disponíveis no cliente
    pub const CLIENT_CRYPT: u8 = 11; // nível de wire-crypt desejado
}

/// Valores para `cnct::CLIENT_CRYPT` (e nível de wire-crypt do DPB).
pub mod wire_crypt {
    pub const DISABLED: i32 = 0;
    pub const ENABLED: i32 = 1;
    pub const REQUIRED: i32 = 2;
}

// ---------------------------------------------------------------------------
// DPB — Buffer de Parâmetros de Banco de Dados (consts_pub.h `isc_dpb_*`)
// ---------------------------------------------------------------------------

/// Byte de versão do DPB que prefixa o buffer.
pub const DPB_VERSION1: u8 = 1;
pub const DPB_VERSION2: u8 = 2; // strings em UTF-8, comprimentos em 4 bytes

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
    pub const LC_CTYPE: u8 = 48; // charset da conexão
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
// TPB — Buffer de Parâmetros de Transação (`isc_tpb_*`)
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
// Itens de informação SQL (`isc_info_sql_*`) usados após o prepare
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
    // Atenção: a ordem real do Firebird é owner=18, alias=19 (confirmado por
    // captura do describe-info: tag 0x12 carrega o owner, 0x13 carrega o alias).
    pub const OWNER: u8 = 18;
    pub const ALIAS: u8 = 19;
    pub const RELATION_ALIAS: u8 = 20;
    pub const STMT_TYPE: u8 = 21;
    pub const BATCH_FETCH: u8 = 22;
    pub const RECORDS: u8 = 23;
    pub const AFFECTED_RECORDS: u8 = 24;
    pub const EXPLAIN_PLAN: u8 = 25;
    pub const FLAGS: u8 = 26;
}

/// Contadores de registros retornados dentro de `isc_info_sql_records`
/// (`isc_info_req_*`): o número de linhas que cada tipo de operação afetou.
pub mod info_req {
    pub const SELECT_COUNT: u8 = 13;
    pub const INSERT_COUNT: u8 = 14;
    pub const UPDATE_COUNT: u8 = 15;
    pub const DELETE_COUNT: u8 = 16;
}

/// Tipos de instrução (statement) retornados por `isc_info_sql_stmt_type`.
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

/// Modos de `op_free_statement`.
pub mod free {
    pub const CLOSE: i32 = 1;
    pub const DROP: i32 = 2;
    pub const UNPREPARE: i32 = 4;
}

/// Direções de `op_fetch_scroll` (FB5).
pub mod scroll {
    pub const NEXT: i32 = 0;
    pub const PRIOR: i32 = 1;
    pub const FIRST: i32 = 2;
    pub const LAST: i32 = 3;
    pub const ABSOLUTE: i32 = 4;
    pub const RELATIVE: i32 = 5;
}

// ---------------------------------------------------------------------------
// Terminadores / status genéricos de info-buffer
// ---------------------------------------------------------------------------

pub const INFO_END: u8 = 1;
pub const INFO_TRUNCATED: u8 = 2;
pub const INFO_ERROR: u8 = 3;
pub const INFO_DATA_NOT_READY: u8 = 4;

// ---------------------------------------------------------------------------
// Tags do vetor de status (`isc_arg_*`)
// ---------------------------------------------------------------------------

pub mod arg {
    pub const END: i32 = 0;
    pub const GDS: i32 = 1; // código de erro do Firebird
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
    pub const SQL_STATE: i32 = 19; // string SQLSTATE (FB2.5+)
}

// ---------------------------------------------------------------------------
// Tipos de dados SQL (`SQL_*`, sqlda_pub.h). Bit baixo = flag anulável.
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

    /// Remove o bit baixo de anulável para obter o tipo base.
    #[inline]
    pub const fn base(t: i32) -> i32 {
        t & !1
    }
    /// Verdadeiro quando o bit baixo do tipo o marca como anulável.
    #[inline]
    pub const fn is_nullable(t: i32) -> bool {
        t & 1 != 0
    }
}

// ---------------------------------------------------------------------------
// Códigos BLR (Binary Language Representation) para descrições de mensagens
// ---------------------------------------------------------------------------

pub mod blr {
    pub const VERSION5: u8 = 5;
    pub const BEGIN: u8 = 2;
    pub const MESSAGE: u8 = 4;
    pub const END: u8 = 255;
    pub const EOC: u8 = 76; // fim de comando

    pub const TEXT: u8 = 14; // + length(2)
    pub const TEXT2: u8 = 15; // + charset(2) + length(2)
    pub const SHORT: u8 = 7; // + scale(1)
    pub const LONG: u8 = 8; // + scale(1)
    pub const QUAD: u8 = 9; // + scale(1) — também id de blob
    pub const FLOAT: u8 = 10;
    pub const DOUBLE: u8 = 27;
    pub const D_FLOAT: u8 = 11;
    pub const TIMESTAMP: u8 = 35;
    pub const VARYING: u8 = 37; // + length(2)
    pub const VARYING2: u8 = 38; // + charset(2) + length(2)
    pub const SQL_DATE: u8 = 12;
    pub const SQL_TIME: u8 = 13;
    pub const INT64: u8 = 16; // + scale(1)
    pub const BOOL: u8 = 23;
    pub const DEC64: u8 = 24;
    pub const DEC128: u8 = 25;
    pub const INT128: u8 = 26; // + scale(1)
    pub const SQL_TIME_TZ: u8 = 28;
    pub const TIMESTAMP_TZ: u8 = 29;
}

// ---------------------------------------------------------------------------
// Buffer de parâmetros de blob (`isc_bpb_*`) e info de blob
// ---------------------------------------------------------------------------

pub const BPB_VERSION1: u8 = 1;

pub mod bpb {
    pub const SOURCE_TYPE: u8 = 1;
    pub const TARGET_TYPE: u8 = 2;
    pub const TYPE: u8 = 3;
    pub const STORAGE: u8 = 7;
}

/// Subtipos de blob.
pub mod blob_type {
    pub const SEGMENTED: i32 = 0;
    pub const STREAM: i32 = 1;
}

// ---------------------------------------------------------------------------
// Buffer de parâmetros de batch (tags de `IBatch`) e itens de info (FB4+)
// ---------------------------------------------------------------------------

/// Tags para o buffer de parâmetros de criação de batch (`Firebird::IBatch::TAG_*`).
pub mod batch_tag {
    pub const MULTIERROR: u8 = 1; // continua após erros por linha
    pub const RECORD_COUNTS: u8 = 2; // reporta contagens afetadas por mensagem
    pub const BUFFER_BYTES_SIZE: u8 = 3; // limite do buffer do lado do servidor
    pub const BLOB_POLICY: u8 = 4;
    pub const DETAILED_ERRORS: u8 = 5;
}

/// Valores para `batch_tag::BLOB_POLICY`.
pub mod blob_policy {
    pub const NONE: u8 = 0;
    pub const ID_ENGINE: u8 = 1; // o engine atribui ids
    pub const ID_USER: u8 = 2; // o chamador atribui ids
    pub const STREAM: u8 = 3;
}

/// Itens de info de batch (info de `IBatch`, FB4+) retornados por `op_info_batch`.
pub mod batch_info {
    pub const VERSION: u8 = 1;
    pub const BLOB_ALIGNMENT: u8 = 2;
    pub const BLOB_HEADER: u8 = 3;
    pub const ROW_SIZE: u8 = 4;
    pub const BUFFER_BYTES_SIZE: u8 = 5;
}

/// Códigos de estado de conclusão de `op_batch_cs` (`IBatchCompletionState`).
pub mod batch_cs {
    /// Código de retorno por mensagem que significa "nenhuma info de registros afetados disponível".
    pub const NO_MORE_ERRORS: i32 = -1;
    pub const EXECUTE_FAILED: i32 = -2;
    pub const SUCCESS_NO_INFO: i32 = -3;
}
