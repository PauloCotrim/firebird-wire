//! Configuração da conexão.

use std::time::Duration;

use crate::error::{Error, Result};

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
    /// Nome ou IP do servidor Firebird.
    pub host: String,
    /// Porta TCP do servidor Firebird. O padrão do Firebird é `3050`.
    pub port: u16,
    /// Caminho ou alias do banco de dados no servidor (ex.: `employee` ou `/data/db.fdb`).
    pub database: String,
    /// Nome do usuário Firebird.
    pub user: String,
    /// Senha do usuário Firebird.
    pub password: String,
    /// Papel SQL opcional usado na conexão (`ROLE`).
    pub role: Option<String>,
    /// Charset da conexão (padrão `UTF8`).
    pub charset: String,
    /// Dialeto SQL (padrão `3`).
    pub dialect: i32,
    /// Política de criptografia da comunicação.
    pub wire_crypt: WireCrypt,
    /// Timeout de TCP + handshake.
    pub connect_timeout: Option<Duration>,
    /// Tamanho da página para [`crate::Connection::create_database`].
    pub page_size: Option<i32>,
    /// Fuso horário da sessão (FB4+), ex.: `America/Sao_Paulo`.
    pub timezone: Option<String>,
    /// Número de workers paralelos para a conexão (FB5).
    pub parallel_workers: Option<i32>,
    /// Quando `true`, emite `SET BIND OF INT128/DECFLOAT/TIME ZONE TO NATIVE`
    /// logo após o attach (FB4+). Útil quando o servidor está com
    /// `DataTypeCompatibility` ligado e coage esses tipos para os legados —
    /// assim eles voltam como `Int128`/`DecFloat`/`TimeTz` em vez de aproximações.
    pub native_data_types: bool,
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
            native_data_types: false,
        }
    }
}

impl ConnectConfig {
    /// Começa a partir dos padrões (`localhost:3050`, usuário `SYSDBA`, UTF8, dialeto 3).
    pub fn new() -> Self {
        Self::default()
    }

    /// Define o host ou IP do servidor Firebird.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }
    /// Define a porta TCP do servidor Firebird.
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
    /// Define o banco por alias ou caminho no servidor.
    pub fn database(mut self, db: impl Into<String>) -> Self {
        self.database = db.into();
        self
    }
    /// Define o usuário Firebird.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }
    /// Define a senha do usuário Firebird.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = password.into();
        self
    }
    /// Define o papel SQL (`ROLE`) usado após o login.
    pub fn role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }
    /// Define o charset da conexão, como `UTF8`, `WIN1252` ou `ISO8859_1`.
    pub fn charset(mut self, charset: impl Into<String>) -> Self {
        self.charset = charset.into();
        self
    }
    /// Define o dialeto SQL. Use `3` para bancos modernos.
    pub fn dialect(mut self, dialect: i32) -> Self {
        self.dialect = dialect;
        self
    }
    /// Define se a comunicação deve ser criptografada, quando disponível ou obrigatoriamente.
    pub fn wire_crypt(mut self, wc: WireCrypt) -> Self {
        self.wire_crypt = wc;
        self
    }
    /// Define o tempo máximo para abrir o socket TCP e completar o handshake.
    pub fn connect_timeout(mut self, t: Duration) -> Self {
        self.connect_timeout = Some(t);
        self
    }
    /// Define o tamanho de página ao criar um banco novo com [`crate::Connection::create_database`].
    pub fn page_size(mut self, size: i32) -> Self {
        self.page_size = Some(size);
        self
    }
    /// Define o fuso horário da sessão, por exemplo `America/Sao_Paulo`.
    pub fn timezone(mut self, tz: impl Into<String>) -> Self {
        self.timezone = Some(tz.into());
        self
    }
    /// Define o número de workers paralelos solicitado ao servidor Firebird 5.
    pub fn parallel_workers(mut self, n: i32) -> Self {
        self.parallel_workers = Some(n);
        self
    }
    /// Pede os tipos nativos (INT128/DECFLOAT/WITH TIME ZONE) após o attach.
    /// Veja [`ConnectConfig::native_data_types`].
    pub fn native_data_types(mut self, on: bool) -> Self {
        self.native_data_types = on;
        self
    }

    /// O nome de usuário normalizado da forma que o plugin SRP espera
    /// (identificadores sem aspas são convertidos para maiúsculas).
    pub(crate) fn normalized_user(&self) -> String {
        self.user.to_uppercase()
    }

    /// Valida campos que vão para clumplets de 1 byte de comprimento (DPB/cnct),
    /// onde um valor acima de 255 bytes corromperia silenciosamente o buffer.
    /// Chamado no início do handshake. O `database` não entra aqui: vai num campo
    /// XDR de comprimento de 4 bytes, sem esse limite.
    pub(crate) fn validate(&self) -> Result<()> {
        // O usuário é enviado em maiúsculas (pode mudar o nº de bytes em multibyte).
        check_clumplet_len("user", &self.normalized_user())?;
        check_clumplet_len("password", &self.password)?;
        check_clumplet_len("charset", &self.charset)?;
        if let Some(role) = &self.role {
            check_clumplet_len("role", role)?;
        }
        if let Some(tz) = &self.timezone {
            check_clumplet_len("timezone", tz)?;
        }
        Ok(())
    }
}

/// Garante que um valor cabe num clumplet de comprimento de 1 byte (≤ 255 bytes).
fn check_clumplet_len(field: &str, value: &str) -> Result<()> {
    if value.len() > u8::MAX as usize {
        return Err(Error::conversion(format!(
            "{field} excede 255 bytes ({}); não cabe num parâmetro de conexão",
            value.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(ConnectConfig::new().user("SYSDBA").validate().is_ok());
    }

    #[test]
    fn over_long_password_is_rejected() {
        let cfg = ConnectConfig::new().password("x".repeat(256));
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(err, Error::Conversion(_)),
            "esperava erro de conversão, veio {err:?}"
        );
    }

    #[test]
    fn max_length_fields_pass() {
        let cfg = ConnectConfig::new()
            .role("r".repeat(255))
            .charset("c".repeat(255));
        assert!(cfg.validate().is_ok());
    }
}
