//! Tipos de erro do driver.
//!
//! Falhas do lado do servidor chegam como um *status vector* do Firebird: uma
//! sequência de argumentos marcados (códigos de erro, números e strings). Nós o
//! parseamos em um [`StatusVector`] estruturado e expomos o código GDS primário
//! e o SQLSTATE para que os chamadores possam fazer match em condições
//! específicas sem ter que vasculhar strings.

use std::fmt;

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

    /// Constrói uma mensagem com melhor esforço. Não embutimos o catálogo
    /// `firebird.msg` completo, mas temos um mapa dos códigos GDS mais comuns
    /// ([`gds_template`]) cujos placeholders `@N` preenchemos com os argumentos do
    /// status vector. A ordem de preferência é: (1) texto já interpretado pelo
    /// servidor; (2) templates conhecidos formatados; (3) argumentos crus; (4) o
    /// código GDS bruto.
    fn message(&self) -> String {
        // (1) O servidor às vezes já manda o texto pronto.
        let interpreted: Vec<String> = self
            .args
            .iter()
            .filter_map(|a| match a {
                StatusArg::Interpreted(s) if !s.is_empty() => Some(s.clone()),
                _ => None,
            })
            .collect();
        if !interpreted.is_empty() {
            return interpreted.join("; ");
        }

        // Valores que preenchem @1, @2, … na ordem em que aparecem.
        let fill: Vec<String> = self
            .args
            .iter()
            .filter_map(|a| match a {
                StatusArg::Number(n) => Some(n.to_string()),
                StatusArg::Str(s) => Some(s.clone()),
                _ => None,
            })
            .collect();

        // (2) Formata cada código GDS com template conhecido.
        let templated: Vec<String> = self
            .args
            .iter()
            .filter_map(|a| match a {
                StatusArg::Gds(c) if *c != 0 => gds_template(*c).map(|t| fill_template(t, &fill)),
                _ => None,
            })
            .collect();
        if !templated.is_empty() {
            return templated.join("; ");
        }

        // (3)/(4) Argumentos crus, senão o código.
        if !fill.is_empty() {
            return fill.join("; ");
        }
        match self.gds_code() {
            Some(c) => format!("Firebird error (gds code {c})"),
            None => "unknown Firebird error".to_string(),
        }
    }
}

/// Substitui os marcadores `@1`..`@9` de um template do Firebird pelos valores em
/// `fill` (na ordem). Marcadores sem valor correspondente ficam como estão.
fn fill_template(template: &str, fill: &[String]) -> String {
    let mut out = template.to_string();
    // Em ordem decrescente para que `@1` não case dentro de um `@10` (inexistente
    // nos templates atuais, mas a ordem é barata e à prova de futuro).
    for i in (1..=fill.len().min(9)).rev() {
        out = out.replace(&format!("@{i}"), &fill[i - 1]);
    }
    out
}

/// Texto dos códigos de erro GDS mais comuns (extraído do `firebird.msg` do FB5
/// via `fb_interpret`). Os `@N` são preenchidos por [`fill_template`]. Cobre os
/// erros que aplicações realmente encontram; o resto recai no código bruto.
fn gds_template(code: i32) -> Option<&'static str> {
    Some(match code {
        335544321 => "arithmetic exception, numeric overflow, or string truncation",
        335544324 => "invalid database handle (no active connection)",
        335544328 => "invalid BLOB handle",
        335544329 => "invalid BLOB ID",
        335544333 => "internal Firebird consistency check (@1)",
        335544334 => "conversion error from string \"@1\"",
        335544336 => "deadlock",
        335544344 => "I/O error during \"@1\" operation for file \"@2\"",
        335544345 => "lock conflict on no wait transaction",
        335544347 => "validation error for column @1, value \"@2\"",
        335544348 => "no current record for fetch operation",
        335544349 => {
            "attempt to store duplicate value (visible to active transactions) in unique index \"@1\""
        }
        335544351 => "unsuccessful metadata update",
        335544352 => "no permission for @1 access to @2 @3",
        335544359 => "attempted update of read-only column @1",
        335544361 => "attempted update during read-only transaction",
        335544380 => "wrong number of arguments on call",
        335544395 => "table @1 is not defined",
        335544396 => "column @1 is not defined in table @2",
        335544421 => "connection rejected by remote interface",
        335544451 => "update conflicts with concurrent update",
        335544466 => "violation of FOREIGN KEY constraint \"@1\" on table \"@2\"",
        335544472 => {
            "Your user name and password are not defined. Ask your database administrator to set up a Firebird login."
        }
        335544510 => "lock time-out on wait transaction",
        335544558 => "Operation violates CHECK constraint @1 on view or table @2",
        335544569 => "Dynamic SQL Error",
        335544578 => "Column unknown",
        335544580 => "Table unknown",
        335544606 => "expression evaluation not supported",
        335544634 => "Token unknown - line @1, column @2",
        335544665 => "violation of PRIMARY or UNIQUE KEY constraint \"@1\" on table \"@2\"",
        _ => return None,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(args: Vec<StatusArg>) -> StatusVector {
        StatusVector { args, sql_state: None }
    }

    #[test]
    fn templated_message_fills_placeholders() {
        // FK: violation of FOREIGN KEY constraint "@1" on table "@2".
        let v = sv(vec![
            StatusArg::Gds(335544466),
            StatusArg::Str("FK_PEDIDO_CLIENTE".into()),
            StatusArg::Str("PEDIDO".into()),
        ]);
        assert_eq!(
            v.message(),
            "violation of FOREIGN KEY constraint \"FK_PEDIDO_CLIENTE\" on table \"PEDIDO\""
        );
    }

    #[test]
    fn chained_gds_codes_are_joined() {
        // Dynamic SQL Error (sem args) + Token unknown - line @1, column @2.
        let v = sv(vec![
            StatusArg::Gds(335544569),
            StatusArg::Gds(335544634),
            StatusArg::Number(1),
            StatusArg::Number(42),
        ]);
        assert_eq!(v.message(), "Dynamic SQL Error; Token unknown - line 1, column 42");
    }

    #[test]
    fn interpreted_text_wins() {
        let v = sv(vec![
            StatusArg::Gds(335544321),
            StatusArg::Interpreted("texto do servidor".into()),
        ]);
        assert_eq!(v.message(), "texto do servidor");
    }

    #[test]
    fn unknown_code_falls_back_to_number() {
        let v = sv(vec![StatusArg::Gds(999999)]);
        assert_eq!(v.message(), "Firebird error (gds code 999999)");
        assert!(v.is_error());
    }

    #[test]
    fn deadlock_has_no_placeholders() {
        assert_eq!(sv(vec![StatusArg::Gds(335544336)]).message(), "deadlock");
    }
}
