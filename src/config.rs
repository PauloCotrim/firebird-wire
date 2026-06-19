//! Configuração da conexão.

use std::time::Duration;

/// Postura desejada de criptografia da conexão (wire-encryption).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WireCrypt {
    /// Nunca criptografa. Falha contra um servidor configurado com `WireCrypt = Required`.
    Disabled,
    /// Criptografa quando o servidor oferece uma cifra suportada; caso contrário
    /// continua em texto claro.
    #[default]
    Enabled,
    /// Exige criptografia; falha o handshake se ela não puder ser negociada.
    Required,
}

/// Tudo o que é necessário para abrir uma conexão com um servidor Firebird.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    pub host: String,
    pub port: u16,
    /// Caminho ou alias do banco de dados no servidor (ex.: `employee` ou `/data/db.fdb`).
    pub database: String,
    pub user: String,
    pub password: String,
    pub role: Option<String>,
    /// Charset da conexão (padrão `UTF8`).
    pub charset: String,
    /// Dialeto SQL (padrão `3`).
    pub dialect: i32,
    pub wire_crypt: WireCrypt,
    /// Timeout de TCP + handshake.
    pub connect_timeout: Option<Duration>,
    /// Tamanho da página para [`crate::Connection::create_database`].
    pub page_size: Option<i32>,
    /// Fuso horário da sessão (FB4+), ex.: `America/Sao_Paulo`.
    pub timezone: Option<String>,
    /// Número de workers paralelos para a conexão (FB5).
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
    /// Começa a partir dos padrões (`localhost:3050`, usuário `SYSDBA`, UTF8, dialeto 3).
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

    /// O nome de usuário normalizado da forma que o plugin SRP espera
    /// (identificadores sem aspas são convertidos para maiúsculas).
    pub(crate) fn normalized_user(&self) -> String {
        self.user.to_uppercase()
    }
}
