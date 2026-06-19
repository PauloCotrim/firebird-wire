//! Error types for the driver.
//!
//! Server-side failures arrive as a Firebird *status vector*: a sequence of
//! tagged arguments (error codes, numbers and strings). We parse it into a
//! structured [`StatusVector`] and expose the primary GDS code and SQLSTATE
//! so callers can match on specific conditions without string-scraping.

use std::fmt;

use crate::wire::consts::arg;
use crate::wire::xdr::XdrReader;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The top-level error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Transport-level I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The peer sent something that violates the wire protocol.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Authentication/handshake failure (SRP, wire crypt, plugin mismatch).
    #[error("authentication error: {0}")]
    Auth(String),

    /// An error reported by the server with a full status vector.
    #[error(transparent)]
    Database(#[from] DatabaseError),

    /// A value could not be converted to/from the requested Rust type.
    #[error("conversion error: {0}")]
    Conversion(String),

    /// Connection-pool failure (exhausted, closed, ...).
    #[error("pool error: {0}")]
    Pool(String),

    /// An operation exceeded its deadline.
    #[error("operation timed out")]
    Timeout,

    /// The connection has been closed and can no longer be used.
    #[error("connection is closed")]
    Closed,

    /// A feature is not supported by the negotiated protocol or this driver yet.
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

    /// If this is a database error, the primary Firebird (GDS) error code.
    pub fn gds_code(&self) -> Option<i32> {
        match self {
            Error::Database(db) => db.gds_code(),
            _ => None,
        }
    }

    /// If this is a database error, its SQLSTATE (5 chars), when provided.
    pub fn sql_state(&self) -> Option<&str> {
        match self {
            Error::Database(db) => db.sql_state.as_deref(),
            _ => None,
        }
    }
}

/// One element of a Firebird status vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusArg {
    /// A Firebird/GDS error code (`isc_arg_gds`).
    Gds(i32),
    /// A warning code (`isc_arg_warning`).
    Warning(i32),
    /// A numeric argument used to fill a message placeholder.
    Number(i32),
    /// A string argument used to fill a message placeholder.
    Str(String),
    /// Text the server already interpreted for us.
    Interpreted(String),
}

/// A parsed status vector plus a best-effort human-readable message.
#[derive(Debug, Clone)]
pub struct StatusVector {
    pub args: Vec<StatusArg>,
    pub sql_state: Option<String>,
}

impl StatusVector {
    /// Parse a status vector out of an XDR stream (as carried by `op_response`).
    ///
    /// String-bearing arguments (`isc_arg_string`, `isc_arg_interpreted`,
    /// `isc_arg_sql_state`) are transmitted as length-prefixed, 4-byte-aligned
    /// buffers. Numeric arguments are single XDR words.
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
                    // Unknown tags carry a single numeric word in the legacy
                    // encoding; consume it so we stay in sync.
                    let _ = r.get_i32()?;
                    args.push(StatusArg::Number(other));
                }
            }
        }

        Ok(StatusVector { args, sql_state })
    }

    /// True when the vector carries no error codes.
    pub fn is_empty(&self) -> bool {
        !self
            .args
            .iter()
            .any(|a| matches!(a, StatusArg::Gds(_) | StatusArg::Warning(_)))
    }

    /// True when the vector represents a real failure. A `isc_arg_gds` with
    /// code `0` is Firebird's "success" sentinel and is *not* an error.
    pub fn is_error(&self) -> bool {
        self.args.iter().any(|a| matches!(a, StatusArg::Gds(c) if *c != 0))
    }

    /// The first non-zero GDS error code, if any.
    pub fn gds_code(&self) -> Option<i32> {
        self.args.iter().find_map(|a| match a {
            StatusArg::Gds(c) if *c != 0 => Some(*c),
            _ => None,
        })
    }

    /// Build a best-effort message. We do not bundle the `firebird.msg`
    /// catalogue, so we join any server-interpreted text and string arguments,
    /// falling back to the raw GDS code.
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

/// A server error: the status vector and its rendered message.
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
