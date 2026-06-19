//! Connection configuration.

use std::time::Duration;

/// Desired wire-encryption posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WireCrypt {
    /// Never encrypt. Fails against a server configured `WireCrypt = Required`.
    Disabled,
    /// Encrypt when the server offers a supported cipher; otherwise continue
    /// in clear text.
    #[default]
    Enabled,
    /// Require encryption; fail the handshake if it cannot be negotiated.
    Required,
}

/// Everything needed to open a connection to a Firebird server.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    pub host: String,
    pub port: u16,
    /// Database path or alias on the server (e.g. `employee` or `/data/db.fdb`).
    pub database: String,
    pub user: String,
    pub password: String,
    pub role: Option<String>,
    /// Connection character set (default `UTF8`).
    pub charset: String,
    /// SQL dialect (default `3`).
    pub dialect: i32,
    pub wire_crypt: WireCrypt,
    /// TCP + handshake timeout.
    pub connect_timeout: Option<Duration>,
    /// Page size for [`crate::Connection::create_database`].
    pub page_size: Option<i32>,
    /// Session time zone (FB4+), e.g. `America/Sao_Paulo`.
    pub timezone: Option<String>,
    /// Number of parallel workers for the attachment (FB5).
    pub parallel_workers: Option<i32>,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        ConnectConfig {
            host: "localhost".to_string(),
            port: 3050,
            database: String::new(),
            user: "SYSDBA".to_string(),
            password: String::new(),
            role: None,
            charset: "UTF8".to_string(),
            dialect: 3,
            wire_crypt: WireCrypt::default(),
            connect_timeout: Some(Duration::from_secs(15)),
            page_size: None,
            timezone: None,
            parallel_workers: None,
        }
    }
}

impl ConnectConfig {
    /// Start from defaults (`localhost:3050`, user `SYSDBA`, UTF8, dialect 3).
    pub fn new() -> Self {
        Self::default()
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
    pub fn database(mut self, db: impl Into<String>) -> Self {
        self.database = db.into();
        self
    }
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = password.into();
        self
    }
    pub fn role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }
    pub fn charset(mut self, charset: impl Into<String>) -> Self {
        self.charset = charset.into();
        self
    }
    pub fn dialect(mut self, dialect: i32) -> Self {
        self.dialect = dialect;
        self
    }
    pub fn wire_crypt(mut self, wc: WireCrypt) -> Self {
        self.wire_crypt = wc;
        self
    }
    pub fn connect_timeout(mut self, t: Duration) -> Self {
        self.connect_timeout = Some(t);
        self
    }
    pub fn page_size(mut self, size: i32) -> Self {
        self.page_size = Some(size);
        self
    }
    pub fn timezone(mut self, tz: impl Into<String>) -> Self {
        self.timezone = Some(tz.into());
        self
    }
    pub fn parallel_workers(mut self, n: i32) -> Self {
        self.parallel_workers = Some(n);
        self
    }

    /// The username normalized the way the Srp plugin expects it (unquoted
    /// identifiers are folded to upper case).
    pub(crate) fn normalized_user(&self) -> String {
        self.user.to_uppercase()
    }
}
