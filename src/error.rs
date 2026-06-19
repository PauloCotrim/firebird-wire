//! Tipos de erro do driver.
//!
//! Falhas do lado do servidor chegam como um *status vector* do Firebird: uma
//! sequência de argumentos marcados (códigos de erro, números e strings). Nós o
//! parseamos em um [`StatusVector`] estruturado e expomos o código GDS primário
//! e o SQLSTATE para que os chamadores possam fazer match em condições
//! específicas sem ter que vasculhar strings.

use std::fmt;

use crate::wire::consts::arg;
use crate::wire::xdr::XdrReader;

/// Alias de conveniência usado em toda a crate.
pub type Result<T> = std::result::Result<T, Error>;

/// O tipo de erro de nível mais alto.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Falha de I/O no nível de transporte.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// O par enviou algo que viola o protocolo de comunicação (wire protocol).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Falha de autenticação/handshake (SRP, wire crypt, incompatibilidade de plugin).
    #[error("authentication error: {0}")]
    Auth(String),

    /// Um erro reportado pelo servidor com um status vector completo.
    #[error(transparent)]
    Database(#[from] DatabaseError),

    /// Um valor não pôde ser convertido de/para o tipo Rust solicitado.
    #[error("conversion error: {0}")]
    Conversion(String),

    /// Falha no pool de conexões (esgotado, fechado, ...).
    #[error("pool error: {0}")]
    Pool(String),

    /// Uma operação excedeu seu prazo.
    #[error("operation timed out")]
    Timeout,

    /// A conexão foi fechada e não pode mais ser usada.
    #[error("connection is closed")]
    Closed,

    /// Um recurso ainda não é suportado pelo protocolo negociado ou por este driver.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl Error {
    pub fn protocol(msg: impl Into<String>) -> Self {
        Error::Protocol(msg.into())
    }
    pub fn auth(msg: impl Into<String>) -> Self {
        Error::Auth(msg.into())
    }
    pub fn conversion(msg: impl Into<String>) -> Self {
        Error::Conversion(msg.into())
    }
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Error::Unsupported(msg.into())
    }

    /// Se este for um erro de banco de dados, o código de erro primário do Firebird (GDS).
    pub fn gds_code(&self) -> Option<i32> {
        match self {
            Error::Database(db) => db.gds_code(),
            _ => None,
        }
    }

    /// Se este for um erro de banco de dados, seu SQLSTATE (5 caracteres), quando fornecido.
    pub fn sql_state(&self) -> Option<&str> {
        match self {
            Error::Database(db) => db.sql_state.as_deref(),
            _ => None,
        }
    }
}

/// Um elemento de um status vector do Firebird.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusArg {
    /// Um código de erro Firebird/GDS (`isc_arg_gds`).
    Gds(i32),
    /// Um código de aviso (`isc_arg_warning`).
    Warning(i32),
    /// Um argumento numérico usado para preencher um placeholder da mensagem.
    Number(i32),
    /// Um argumento de string usado para preencher um placeholder da mensagem.
    Str(String),
    /// Texto que o servidor já interpretou para nós.
    Interpreted(String),
}

/// Um status vector parseado mais uma mensagem legível por humanos com melhor esforço.
#[derive(Debug, Clone)]
pub struct StatusVector {
    pub args: Vec<StatusArg>,
    pub sql_state: Option<String>,
}

impl StatusVector {
    /// Parseia um status vector a partir de um stream XDR (como o transportado por `op_response`).
    ///
    /// Argumentos que carregam strings (`isc_arg_string`, `isc_arg_interpreted`,
    /// `isc_arg_sql_state`) são transmitidos como buffers prefixados por
    /// comprimento e alinhados em 4 bytes. Argumentos numéricos são palavras XDR
    /// únicas.
    pub fn read(r: &mut XdrReader) -> Result<Self> {
        let mut args = Vec::new();
        let mut sql_state = None;

        loop {
            let tag = r.get_i32()?;
            match tag {
                t if t == arg::END => break,
                t if t == arg::GDS => args.push(StatusArg::Gds(r.get_i32()?)),
                t if t == arg::WARNING => args.push(StatusArg::Warning(r.get_i32()?)),
                t if t == arg::NUMBER => args.push(StatusArg::Number(r.get_i32()?)),
                t if t == arg::STRING || t == arg::CSTRING => {
                    let s = String::from_utf8_lossy(r.get_bytes()?).into_owned();
                    args.push(StatusArg::Str(s));
                }
                t if t == arg::INTERPRETED => {
                    let s = String::from_utf8_lossy(r.get_bytes()?).into_owned();
                    args.push(StatusArg::Interpreted(s));
                }
                t if t == arg::SQL_STATE => {
                    sql_state = Some(String::from_utf8_lossy(r.get_bytes()?).into_owned());
                }
                other => {
                    // Tags desconhecidas carregam uma única palavra numérica na
                    // codificação legada; consumimos para nos mantermos em sincronia.
                    let _ = r.get_i32()?;
                    args.push(StatusArg::Number(other));
                }
            }
        }

        Ok(StatusVector { args, sql_state })
    }

    /// Verdadeiro quando o vetor não carrega nenhum código de erro.
    pub fn is_empty(&self) -> bool {
        !self
            .args
            .iter()
            .any(|a| matches!(a, StatusArg::Gds(_) | StatusArg::Warning(_)))
    }

    /// Verdadeiro quando o vetor representa uma falha real. Um `isc_arg_gds` com
    /// código `0` é o sentinela de "success" do Firebird e *não* é um erro.
    pub fn is_error(&self) -> bool {
        self.args.iter().any(|a| matches!(a, StatusArg::Gds(c) if *c != 0))
    }

    /// O primeiro código de erro GDS diferente de zero, se houver.
    pub fn gds_code(&self) -> Option<i32> {
        self.args.iter().find_map(|a| match a {
            StatusArg::Gds(c) if *c != 0 => Some(*c),
            _ => None,
        })
    }

    /// Constrói uma mensagem com melhor esforço. Nós não incluímos o catálogo
    /// `firebird.msg`, então juntamos qualquer texto interpretado pelo servidor e
    /// argumentos de string, recorrendo ao código GDS bruto.
    fn message(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for a in &self.args {
            match a {
                StatusArg::Interpreted(s) | StatusArg::Str(s) if !s.is_empty() => {
                    parts.push(s.clone())
                }
                _ => {}
            }
        }
        if parts.is_empty() {
            match self.gds_code() {
                Some(c) => format!("Firebird error (gds code {c})"),
                None => "unknown Firebird error".to_string(),
            }
        } else {
            parts.join("; ")
        }
    }
}

impl fmt::Display for StatusVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

/// Um erro do servidor: o status vector e sua mensagem renderizada.
#[derive(Debug, Clone)]
pub struct DatabaseError {
    pub status: StatusVector,
    pub sql_state: Option<String>,
    message: String,
}

impl DatabaseError {
    pub fn new(status: StatusVector) -> Self {
        let message = status.message();
        let sql_state = status.sql_state.clone();
        DatabaseError { status, sql_state, message }
    }

    pub fn gds_code(&self) -> Option<i32> {
        self.status.gds_code()
    }
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.sql_state, self.gds_code()) {
            (Some(state), Some(code)) => {
                write!(f, "{} (SQLSTATE {state}, gds {code})", self.message)
            }
            (None, Some(code)) => write!(f, "{} (gds {code})", self.message),
            _ => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for DatabaseError {}

impl From<StatusVector> for Error {
    fn from(status: StatusVector) -> Self {
        Error::Database(DatabaseError::new(status))
    }
}
