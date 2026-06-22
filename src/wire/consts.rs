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

    // Eventos assíncronos (canal auxiliar).
    pub const QUE_EVENTS: i32 = 48;
    pub const CANCEL_EVENTS: i32 = 49;
    pub const COMMIT_RETAINING: i32 = 50;
    pub const EVENT: i32 = 52;
    pub const CONNECT_REQUEST: i32 = 53;

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
    pub const GET_SLICE: i32 = 58;
    pub const PUT_SLICE: i32 = 59;
    pub const SLICE: i32 = 60;
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
// SPB — Buffer de Parâmetros de Serviço (`isc_spb_*`, gerenciador de serviços)
// ---------------------------------------------------------------------------

/// O cabeçalho do SPB de attach é DOIS bytes: `isc_spb_version` seguido de
/// `isc_spb_current_version`, ambos `2` (confirmado por strace do `fbsvcmgr`).
pub const SPB_VERSION: u8 = 2;
pub const SPB_CURRENT_VERSION: u8 = 2;

pub mod spb {
    // Itens de autenticação / identificação no attach (espelham os do DPB).
    pub const USER_NAME: u8 = 28; // = isc_dpb_user_name
    pub const PASSWORD: u8 = 29; // = isc_dpb_password
    pub const SQL_ROLE_NAME: u8 = 60;
    pub const CONNECT_TIMEOUT: u8 = 57;
    pub const COMMAND_LINE: u8 = 105;
    pub const DBNAME: u8 = 106;
    pub const VERBOSE: u8 = 107;
    pub const OPTIONS: u8 = 108;
    pub const PROCESS_ID: u8 = 110;
    pub const PROCESS_NAME: u8 = 112;
    pub const TRUSTED_AUTH: u8 = 111;
    /// O `isc_spb_specific_auth_data` (a prova SRP) divide o tag com `trusted_auth`.
    pub const SPECIFIC_AUTH_DATA: u8 = 111;
    pub const AUTH_BLOCK: u8 = 115;
    pub const AUTH_PLUGIN_NAME: u8 = 116;
    pub const AUTH_PLUGIN_LIST: u8 = 117;
    pub const UTF8_FILENAME: u8 = 118;
    pub const CLIENT_VERSION: u8 = 119;
    pub const EXPECTED_DB: u8 = 124;
}

/// Códigos de ação para `op_service_start` (`isc_action_svc_*`); o primeiro byte
/// do SPB de start é o código da ação.
pub mod svc_action {
    pub const BACKUP: u8 = 1;
    pub const RESTORE: u8 = 2;
    pub const REPAIR: u8 = 3;
    pub const ADD_USER: u8 = 4;
    pub const DELETE_USER: u8 = 5;
    pub const MODIFY_USER: u8 = 6;
    pub const DISPLAY_USER: u8 = 7;
    pub const PROPERTIES: u8 = 8;
    pub const DB_STATS: u8 = 11;
    pub const GET_FB_LOG: u8 = 12;
    pub const NBAK: u8 = 20;
    pub const NREST: u8 = 21;
    pub const TRACE_START: u8 = 22;
    pub const TRACE_STOP: u8 = 23;
    pub const TRACE_SUSPEND: u8 = 24;
    pub const TRACE_RESUME: u8 = 25;
    pub const TRACE_LIST: u8 = 26;
    pub const VALIDATE: u8 = 30;
}

/// Argumentos de SPB para `isc_action_svc_nbak`/`nrest` (`isc_spb_nbk_*`).
pub mod svc_nbk {
    pub const LEVEL: u8 = 5; // inteiro: nível do backup incremental
    pub const FILE: u8 = 6; // string: arquivo de backup
    pub const DIRECT: u8 = 7; // string: "ON"/"OFF" (I/O direto)
    pub const GUID: u8 = 8; // string: GUID em vez de nível
    pub const CLEAN_HISTORY: u8 = 9;
    pub const KEEP_DAYS: u8 = 10;
    pub const KEEP_ROWS: u8 = 11;

    // Bits de opção em `isc_spb_options` (108).
    pub const NO_TRIGGERS: u32 = 0x01;
    pub const IN_PLACE: u32 = 0x02;
    pub const SEQUENCE: u32 = 0x04;
}

/// Argumentos de SPB para as ações de trace (`isc_spb_trc_*`).
pub mod svc_trc {
    pub const ID: u8 = 1; // inteiro: id da sessão (stop/suspend/resume)
    pub const NAME: u8 = 2; // string: nome da sessão
    pub const CFG: u8 = 3; // string: texto de configuração do trace
}

/// Argumentos de SPB para `isc_action_svc_validate` (`isc_spb_val_*`).
pub mod svc_val {
    pub const TAB_INCL: u8 = 1; // string: regex de tabelas a validar
    pub const TAB_EXCL: u8 = 2; // string: regex de tabelas a excluir
    pub const IDX_INCL: u8 = 3; // string: regex de índices a validar
    pub const IDX_EXCL: u8 = 4; // string: regex de índices a excluir
    pub const LOCK_TIMEOUT: u8 = 5; // inteiro: espera pelo lock da tabela (s)
}

/// Bits de opção (em `isc_spb_options`) para `isc_action_svc_repair`
/// (`isc_spb_rpr_*`), combináveis com `|`.
pub mod svc_rpr {
    pub const VALIDATE_DB: u32 = 0x01;
    pub const SWEEP_DB: u32 = 0x02;
    pub const MEND_DB: u32 = 0x04;
    pub const LIST_LIMBO_TRANS: u32 = 0x08;
    pub const CHECK_DB: u32 = 0x10;
    pub const IGNORE_CHECKSUM: u32 = 0x20;
    pub const KILL_SHADOWS: u32 = 0x40;
    pub const FULL: u32 = 0x80;
    pub const ICU: u32 = 0x0800;
    pub const UPGRADE_DB: u32 = 0x1000;
}

/// Argumentos e valores de SPB para `isc_action_svc_properties` (`isc_spb_prp_*`).
pub mod svc_prp {
    pub const PAGE_BUFFERS: u8 = 5; // inteiro
    pub const SWEEP_INTERVAL: u8 = 6; // inteiro
    pub const SHUTDOWN_DB: u8 = 7; // inteiro: timeout (legado)
    pub const DENY_NEW_ATTACHMENTS: u8 = 9; // inteiro: timeout (legado)
    pub const DENY_NEW_TRANSACTIONS: u8 = 10; // inteiro: timeout (legado)
    pub const RESERVE_SPACE: u8 = 11; // byte: RES_USE_FULL / RES
    pub const WRITE_MODE: u8 = 12; // byte: WM_ASYNC / WM_SYNC
    pub const ACCESS_MODE: u8 = 13; // byte: AM_READONLY / AM_READWRITE
    pub const SET_SQL_DIALECT: u8 = 14; // inteiro
    pub const FORCE_SHUTDOWN: u8 = 41; // inteiro: timeout
    pub const ATTACHMENTS_SHUTDOWN: u8 = 42; // inteiro: timeout
    pub const TRANSACTIONS_SHUTDOWN: u8 = 43; // inteiro: timeout
    pub const SHUTDOWN_MODE: u8 = 44; // byte: SM_*
    pub const ONLINE_MODE: u8 = 45; // byte: SM_*

    // Bits de opção em `isc_spb_options` (108).
    pub const ACTIVATE: u32 = 0x0100;
    pub const DB_ONLINE: u32 = 0x0200;
    pub const NOLINGER: u32 = 0x0400;

    // Valores para SHUTDOWN_MODE / ONLINE_MODE.
    pub const SM_NORMAL: u8 = 0;
    pub const SM_MULTI: u8 = 1;
    pub const SM_SINGLE: u8 = 2;
    pub const SM_FULL: u8 = 3;

    // Valores para RESERVE_SPACE.
    pub const RES_USE_FULL: u8 = 35;
    pub const RES: u8 = 36;

    // Valores para WRITE_MODE.
    pub const WM_ASYNC: u8 = 37;
    pub const WM_SYNC: u8 = 38;

    // Valores para ACCESS_MODE.
    pub const AM_READONLY: u8 = 39;
    pub const AM_READWRITE: u8 = 40;
}

/// Itens de info de serviço para `op_service_info` (`isc_info_svc_*`).
pub mod svc_info {
    pub const SVR_DB_INFO: u8 = 50;
    pub const VERSION: u8 = 54;
    pub const SERVER_VERSION: u8 = 55;
    pub const IMPLEMENTATION: u8 = 56;
    pub const CAPABILITIES: u8 = 57;
    pub const USER_DBPATH: u8 = 58;
    pub const GET_ENV: u8 = 59;
    pub const GET_ENV_LOCK: u8 = 60;
    pub const GET_ENV_MSG: u8 = 61;
    /// Uma linha de saída do serviço por chamada.
    pub const LINE: u8 = 62;
    /// Tanta saída do serviço quanto couber no buffer.
    pub const TO_EOF: u8 = 63;
    pub const TIMEOUT: u8 = 64;
    pub const LIMBO_TRANS: u8 = 66;
    /// Indica se uma ação ainda está em execução nesta conexão (0/1).
    pub const RUNNING: u8 = 67;
    pub const GET_USERS: u8 = 68;
    pub const STDIN: u8 = 78;
}

/// Argumentos de SPB para `isc_action_svc_backup`/`restore` (`isc_spb_bkp_*`).
pub mod svc_bkp {
    pub const FILE: u8 = 5;
    pub const FACTOR: u8 = 6;
    pub const LENGTH: u8 = 7;
    pub const STAT: u8 = 15;

    // Bits de opção carregados em `isc_spb_options` (108), combináveis com `|`.
    pub const IGNORE_CHECKSUMS: u32 = 0x01;
    pub const IGNORE_LIMBO: u32 = 0x02;
    pub const METADATA_ONLY: u32 = 0x04;
    pub const NO_GARBAGE_COLLECT: u32 = 0x08;
    pub const OLD_DESCRIPTIONS: u32 = 0x10;
    pub const NON_TRANSPORTABLE: u32 = 0x20;
    pub const CONVERT: u32 = 0x40;
    pub const EXPAND: u32 = 0x80;
    pub const NO_TRIGGERS: u32 = 0x8000;
    pub const ZIP: u32 = 0x0001_0000;
}

/// Argumentos de SPB para `isc_action_svc_restore` (`isc_spb_res_*`).
pub mod svc_res {
    pub const BUFFERS: u8 = 9;
    pub const PAGE_SIZE: u8 = 10;
    pub const LENGTH: u8 = 11;
    pub const ACCESS_MODE: u8 = 12;

    // Bits de opção carregados em `isc_spb_options` (108), combináveis com `|`.
    pub const METADATA_ONLY: u32 = 0x04;
    pub const DEACTIVATE_IDX: u32 = 0x0100;
    pub const NO_SHADOW: u32 = 0x0200;
    pub const NO_VALIDITY: u32 = 0x0400;
    pub const ONE_AT_A_TIME: u32 = 0x0800;
    /// Sobrescreve um banco existente (em vez de criar do zero).
    pub const REPLACE: u32 = 0x1000;
    /// Cria um banco novo (falha se já existir). É o padrão do gbak.
    pub const CREATE: u32 = 0x2000;
    pub const USE_ALL_SPACE: u32 = 0x4000;
    pub const NO_TRIGGERS: u32 = 0x8000;
}

/// Bits de opção (em `isc_spb_options`) para `isc_action_svc_db_stats`
/// (`isc_spb_sts_*`), combináveis com `|`.
pub mod svc_sts {
    pub const DATA_PAGES: u32 = 0x01;
    pub const HDR_PAGES: u32 = 0x04;
    pub const IDX_PAGES: u32 = 0x08;
    pub const SYS_RELATIONS: u32 = 0x10;
    pub const RECORD_VERSIONS: u32 = 0x20;
    pub const TABLE: u32 = 0x40;
    pub const NOCREATION: u32 = 0x80;
    pub const ENCRYPTION: u32 = 0x0100;
}

/// Argumentos de SPB para gestão de usuários (`isc_spb_sec_*`).
pub mod svc_sec {
    pub const USERID: u8 = 5;
    pub const GROUPID: u8 = 6;
    pub const USERNAME: u8 = 7;
    pub const PASSWORD: u8 = 8;
    pub const GROUPNAME: u8 = 9;
    pub const FIRSTNAME: u8 = 10;
    pub const MIDDLENAME: u8 = 11;
    pub const LASTNAME: u8 = 12;
    pub const ADMIN: u8 = 13;
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

/// Flags de cursor enviados em `op_execute` (campo `cursor_flags`).
pub mod cursor_type {
    /// Abre um cursor rolável (equivale a `IStatement::CURSOR_TYPE_SCROLLABLE`).
    pub const SCROLLABLE: i32 = 0x1;
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
    pub const BLOB2: u8 = 17; // + sub_type(2 LE) + charset(2 LE) — campo BLOB na mensagem
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
    pub const EX_TIME_TZ: u8 = 30; // formato estendido: inclui o offset resolvido
    pub const EX_TIMESTAMP_TZ: u8 = 31;
}

// ---------------------------------------------------------------------------
// SDL (Slice Description Language): o bytecode que descreve a fatia de um ARRAY
// pedida em op_get_slice/op_put_slice. Verbos de `isc_sdl_*` (consts_pub.h).
// O descritor do elemento dentro de `struct` usa códigos BLR (módulo `blr`).
// ---------------------------------------------------------------------------

pub mod sdl {
    pub const VERSION1: u8 = 1;
    pub const EOC: u8 = 255; // fim da cláusula
    pub const RELATION: u8 = 2; // + len(1) + nome
    pub const FIELD: u8 = 4; // + len(1) + nome
    pub const STRUCT: u8 = 6; // + count(1) + (descritor BLR do elemento)×count
    pub const VARIABLE: u8 = 7; // + n(1): referência à variável de laço n
    pub const SCALAR: u8 = 8; // + elem(1) + ndims(1) + (subscrito)×ndims
    pub const TINY_INTEGER: u8 = 9; // + valor(1)
    pub const SHORT_INTEGER: u8 = 10; // + valor(2 LE)
    pub const LONG_INTEGER: u8 = 11; // + valor(4 LE)
    pub const DO2: u8 = 34; // + var(1) + limite_inf(literal) + limite_sup(literal)
    pub const DO1: u8 = 35; // + var(1) + limite_sup(literal); limite_inf implícito = 1
    pub const ELEMENT: u8 = 36; // + n(1): nº de elementos do struct atribuídos
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

    /// Valores do clumplet [`TYPE`] (`isc_bpb_type_*`).
    pub const TYPE_SEGMENTED: u8 = 0;
    pub const TYPE_STREAM: u8 = 1;
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
/// Valores confirmados via wire: numa entrada do vetor de contagens, `>= 0` é o
/// número de linhas afetadas; `EXECUTE_FAILED` marca a mensagem que falhou.
pub mod batch_cs {
    /// Aquela mensagem falhou ao executar (o detalhe vem no vetor de erros).
    pub const EXECUTE_FAILED: i32 = -1;
    /// Sucesso, mas o servidor não reportou a contagem de linhas afetadas.
    pub const SUCCESS_NO_INFO: i32 = -2;
    /// Sentinela de `findError`: não há mais posições com erro (posição `u32`).
    pub const NO_MORE_ERRORS: u32 = u32::MAX;
}
