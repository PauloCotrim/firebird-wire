//! O **gerenciador de serviços** do Firebird (Service Manager): backup/restore
//! (gbak), estatísticas (gstat), reparos (gfix), gestão de usuários, leitura do
//! log do servidor, etc.
//!
//! Um anexo de serviço usa o MESMO handshake de uma conexão de banco (connect +
//! SRP + wire-crypt), mas com a operação `op_service_attach` (82) e o "arquivo"
//! especial `service_mgr`. Em vez de um DPB, o attach carrega um **SPB** (Service
//! Parameter Buffer). O fluxo de wire (decodificado de um strace do `fbsvcmgr`):
//!
//! 1. `op_service_attach` (82): `op | obj(0) | "service_mgr"(cstring) | spb(cstring)`.
//!    O SPB começa com dois bytes `isc_spb_version, isc_spb_current_version`
//!    (ambos `2`) e então clumplets: `user_name(28)`, e a autenticação igual ao
//!    DPB — `auth_plugin_name(116)`, `auth_plugin_list(117)`,
//!    `specific_auth_data(111)` (a prova SRP). A resposta traz o handle do serviço.
//! 2. `op_service_info` (84): `op | handle | incarnation(0) | send_items(cstring)
//!    | recv_items(cstring) | buffer_length(i32)`. A resposta é um `op_response`
//!    cujo `p_resp_data` é um buffer de info clássico (`tag | len(2 LE) | valor …`
//!    terminado por `isc_info_end`). É usada tanto para consultas (versão do
//!    servidor, ambiente) quanto para drenar a saída textual de uma ação.
//! 3. `op_service_start` (85): `op | handle | incarnation(0) | spb(cstring)`. O
//!    primeiro byte do SPB é o código da ação (`isc_action_svc_*`), seguido de
//!    seus argumentos. Dispara a ação; a saída é lida depois via `op_service_info`.
//! 4. `op_service_detach` (83): `op | handle`.
//!
//! **Codificação do SPB de uma ação** (decodificada de straces de
//! `fbsvcmgr action_backup/action_db_stats`): difere tanto do SPB de attach
//! quanto dos DPBs de banco. O primeiro byte é o código da ação; em seguida os
//! argumentos, onde:
//! - argumento **string** (ex.: `isc_spb_dbname` 106, `isc_spb_bkp_file` 5):
//!   `tag(1) | comprimento(2, little-endian) | bytes` — note o prefixo de
//!   **2 bytes**, não o de 1 byte dos clumplets de attach;
//! - argumento **inteiro** (ex.: `isc_spb_bkp_factor` 6, `isc_spb_options` 108):
//!   `tag(1) | valor(4, little-endian)`, **sem** prefixo de comprimento;
//! - **flag** isolada (ex.: `isc_spb_verbose` 107): apenas `tag(1)`.
//!
//! As opções de backup/restore/estatísticas são um bitmask carregado em um único
//! `isc_spb_options` (o servidor o lê como máscara de bits).

use crate::config::ConnectConfig;
use crate::connection::{handshake, AuthState, Handshake};
use crate::error::{Error, Result};
use crate::wire::consts::*;
use crate::wire::response::read_response;
use crate::wire::stream::{info_payload, op_packet, FbStream};
use crate::wire::xdr::ParameterBuffer;

/// Tamanho padrão do buffer de resposta para consultas/saída de serviço.
const DEFAULT_INFO_BUF: i32 = 32768;

/// Um anexo autenticado ao gerenciador de serviços de um servidor Firebird.
pub struct ServiceManager {
    stream: FbStream,
    handle: i32,
}

impl ServiceManager {
    /// Anexa ao gerenciador de serviços usando host/porta/credenciais de `config`
    /// (o campo `database` é ignorado; o alvo é sempre `service_mgr`).
    pub async fn attach(config: &ConnectConfig) -> Result<ServiceManager> {
        let fut = Self::attach_inner(config);
        match config.connect_timeout {
            Some(t) => tokio::time::timeout(t, fut).await.map_err(|_| Error::Timeout)?,
            None => fut.await,
        }
    }

    async fn attach_inner(config: &ConnectConfig) -> Result<ServiceManager> {
        let Handshake { mut stream, protocol_version: _, auth } =
            handshake(config, op::SERVICE_ATTACH, "service_mgr").await?;

        let spb = build_attach_spb(config, &auth);
        let mut w = op_packet(op::SERVICE_ATTACH);
        w.put_i32(0); // id do objeto
        w.put_str("service_mgr");
        w.put_bytes(&spb);
        stream.send(&w).await?;
        let resp = crate::connection::attach_response(&mut stream).await?;

        Ok(ServiceManager { stream, handle: resp.handle })
    }

    /// Se a comunicação (wire) com o serviço está criptografada.
    pub fn is_encrypted(&self) -> bool {
        self.stream.is_encrypted()
    }

    /// Desanexa do gerenciador de serviços (`op_service_detach`) e fecha o socket.
    pub async fn close(mut self) -> Result<()> {
        let mut w = op_packet(op::SERVICE_DETACH);
        w.put_i32(self.handle);
        self.stream.send(&w).await?;
        let _ = read_response(&mut self.stream).await?;
        Ok(())
    }

    // -- API de baixo nível -------------------------------------------------

    /// Envia `op_service_info` com os itens de requisição (`recv`) e devolve o
    /// `p_resp_data` bruto (um buffer de info terminado por `isc_info_end`).
    ///
    /// `send` são itens de configuração para esta chamada (ex.:
    /// `isc_info_svc_timeout`); normalmente vazio.
    pub async fn info(&mut self, send: &[u8], recv: &[u8], buf_len: i32) -> Result<Vec<u8>> {
        let mut w = op_packet(op::SERVICE_INFO);
        w.put_i32(self.handle);
        w.put_i32(0); // incarnation
        w.put_bytes(send); // itens de "envio"
        w.put_bytes(recv); // itens de "recepção" (o que queremos)
        w.put_i32(buf_len);
        self.stream.send(&w).await?;
        let resp = read_response(&mut self.stream).await?;
        Ok(resp.data)
    }

    /// Dispara uma ação (`op_service_start`). O `spb` deve começar pelo código da
    /// ação (`svc_action::*`). Use [`ServiceManager::run`] para também coletar a
    /// saída textual da ação.
    pub async fn start(&mut self, spb: &[u8]) -> Result<()> {
        let mut w = op_packet(op::SERVICE_START);
        w.put_i32(self.handle);
        w.put_i32(0); // incarnation
        w.put_bytes(spb);
        self.stream.send(&w).await?;
        read_response(&mut self.stream).await?;
        Ok(())
    }

    /// Dispara uma ação e coleta toda a sua saída textual, drenando o serviço com
    /// chamadas sucessivas de `op_service_info`/`isc_info_svc_to_eof` até o fim.
    pub async fn run(&mut self, spb: &[u8]) -> Result<String> {
        self.start(spb).await?;
        self.collect_output().await
    }

    /// Lê a saída acumulada do serviço (após um [`start`](Self::start)) até o EOF.
    pub async fn collect_output(&mut self) -> Result<String> {
        let mut out = String::new();
        loop {
            let data = self.info(&[], &[svc_info::TO_EOF], DEFAULT_INFO_BUF).await?;
            let chunk = parse_svc_string(&data, svc_info::TO_EOF)?;
            if chunk.is_empty() {
                break;
            }
            out.push_str(&String::from_utf8_lossy(&chunk));
        }
        Ok(out)
    }

    // -- consultas de info comuns -------------------------------------------

    /// A versão do servidor Firebird (`isc_info_svc_server_version`).
    pub async fn server_version(&mut self) -> Result<String> {
        self.query_string(svc_info::SERVER_VERSION).await
    }

    /// A implementação do servidor (`isc_info_svc_implementation`).
    pub async fn implementation(&mut self) -> Result<String> {
        self.query_string(svc_info::IMPLEMENTATION).await
    }

    /// O caminho do banco de segurança em uso (`isc_info_svc_user_dbpath`).
    pub async fn security_database(&mut self) -> Result<String> {
        self.query_string(svc_info::USER_DBPATH).await
    }

    /// O valor de `$FIREBIRD` no servidor (`isc_info_svc_get_env`).
    pub async fn home_directory(&mut self) -> Result<String> {
        self.query_string(svc_info::GET_ENV).await
    }

    /// A versão do protocolo do Service Manager (`isc_info_svc_version`; um
    /// inteiro, p.ex. `2` no Firebird 5).
    pub async fn manager_version(&mut self) -> Result<i32> {
        self.query_int(svc_info::VERSION).await
    }

    /// Indica se uma ação ainda está em execução nesta conexão de serviço
    /// (`isc_info_svc_running`). Útil para sondar o andamento entre leituras de
    /// saída de uma ação longa (backup, restore, etc.).
    pub async fn is_running(&mut self) -> Result<bool> {
        Ok(self.query_int(svc_info::RUNNING).await? != 0)
    }

    // -- ações de alto nível ------------------------------------------------

    /// Lê o log do servidor (`firebird.log`) via `isc_action_svc_get_fb_log`.
    /// (A ação não tem argumentos: o SPB é apenas o código da ação.)
    pub async fn get_fb_log(&mut self) -> Result<String> {
        let mut spb = ParameterBuffer::raw();
        spb.tag(svc_action::GET_FB_LOG);
        self.run(&spb.into_vec()).await
    }

    /// Faz backup de `database` (alias ou caminho no servidor) para `backup_file`
    /// (caminho **no servidor**) via `gbak`. `options` é um bitmask de `svc_bkp::*`
    /// (use `0` para o padrão). Devolve a saída textual do gbak (modo verbose).
    pub async fn backup(
        &mut self,
        database: &str,
        backup_file: &str,
        options: u32,
    ) -> Result<String> {
        let mut spb = ActionSpb::new(svc_action::BACKUP);
        spb.string(spb::DBNAME, database);
        spb.string(svc_bkp::FILE, backup_file);
        if options != 0 {
            spb.int(spb::OPTIONS, options);
        }
        spb.flag(spb::VERBOSE);
        self.run(&spb.into_vec()).await
    }

    /// Restaura `backup_file` (caminho **no servidor**) para `database` via `gbak`.
    /// `options` é um bitmask de `svc_res::*`; se nem `REPLACE` nem `CREATE`
    /// estiverem presentes, assume `CREATE` (o padrão do gbak). Devolve a saída
    /// textual do gbak (modo verbose).
    pub async fn restore(
        &mut self,
        backup_file: &str,
        database: &str,
        options: u32,
    ) -> Result<String> {
        let mut options = options;
        if options & (svc_res::REPLACE | svc_res::CREATE) == 0 {
            options |= svc_res::CREATE;
        }
        let mut spb = ActionSpb::new(svc_action::RESTORE);
        // Na restauração os papéis se invertem: bkp_file é a ORIGEM, dbname o DESTINO.
        spb.string(svc_bkp::FILE, backup_file);
        spb.string(spb::DBNAME, database);
        spb.int(spb::OPTIONS, options);
        spb.flag(spb::VERBOSE);
        self.run(&spb.into_vec()).await
    }

    /// Coleta estatísticas de `database` via `gstat` (`isc_action_svc_db_stats`).
    /// `options` é um bitmask de `svc_sts::*` (use `0` para o cabeçalho do banco).
    pub async fn statistics(&mut self, database: &str, options: u32) -> Result<String> {
        let mut spb = ActionSpb::new(svc_action::DB_STATS);
        spb.string(spb::DBNAME, database);
        if options != 0 {
            spb.int(spb::OPTIONS, options);
        }
        self.run(&spb.into_vec()).await
    }

    // -- gestão de usuários (banco de segurança) ----------------------------

    /// Cria um usuário no banco de segurança (`isc_action_svc_add_user`).
    pub async fn add_user(&mut self, user: &UserParams) -> Result<()> {
        self.run(&build_user_spb(svc_action::ADD_USER, user)).await?;
        Ok(())
    }

    /// Altera um usuário existente (`isc_action_svc_modify_user`). Só os campos
    /// presentes em `user` são modificados.
    pub async fn modify_user(&mut self, user: &UserParams) -> Result<()> {
        self.run(&build_user_spb(svc_action::MODIFY_USER, user)).await?;
        Ok(())
    }

    /// Remove um usuário (`isc_action_svc_delete_user`).
    pub async fn delete_user(&mut self, username: &str) -> Result<()> {
        let mut spb = ActionSpb::new(svc_action::DELETE_USER);
        spb.string(svc_sec::USERNAME, username);
        self.run(&spb.into_vec()).await?;
        Ok(())
    }

    /// Lista todos os usuários do banco de segurança
    /// (`isc_action_svc_display_user` + `isc_info_svc_get_users`).
    pub async fn display_users(&mut self) -> Result<Vec<UserInfo>> {
        let spb = ActionSpb::new(svc_action::DISPLAY_USER);
        self.fetch_users(spb.into_vec()).await
    }

    /// Consulta um único usuário pelo nome; devolve `None` se não existir.
    pub async fn display_user(&mut self, username: &str) -> Result<Option<UserInfo>> {
        let mut spb = ActionSpb::new(svc_action::DISPLAY_USER);
        spb.string(svc_sec::USERNAME, username);
        Ok(self.fetch_users(spb.into_vec()).await?.into_iter().next())
    }

    /// Dispara um `display_user` e decodifica o buffer `isc_info_svc_get_users`.
    async fn fetch_users(&mut self, spb: Vec<u8>) -> Result<Vec<UserInfo>> {
        self.start(&spb).await?;
        let data = self.info(&[], &[svc_info::GET_USERS], DEFAULT_INFO_BUF).await?;
        let payload = parse_svc_string(&data, svc_info::GET_USERS)?;
        parse_users(&payload)
    }

    // -- auxiliares ---------------------------------------------------------

    /// Consulta um único item de info que devolve uma string.
    async fn query_string(&mut self, item: u8) -> Result<String> {
        let data = self.info(&[], &[item], DEFAULT_INFO_BUF).await?;
        let value = parse_svc_string(&data, item)?;
        Ok(String::from_utf8_lossy(&value).into_owned())
    }

    /// Consulta um único item de info que devolve um inteiro.
    async fn query_int(&mut self, item: u8) -> Result<i32> {
        let data = self.info(&[], &[item], DEFAULT_INFO_BUF).await?;
        parse_svc_int(&data, item)
    }
}

/// Constrói o SPB de `op_service_attach`. Cabeçalho `[version, current_version]`
/// (ambos `2`) seguido do usuário e da autenticação, espelhando o DPB de banco.
fn build_attach_spb(config: &ConnectConfig, auth: &AuthState) -> Vec<u8> {
    let mut spb = ParameterBuffer::raw();
    spb.tag(SPB_VERSION);
    spb.tag(SPB_CURRENT_VERSION);

    spb.string(spb::USER_NAME, &config.normalized_user());

    match auth {
        AuthState::Proof(a) => {
            spb.string(spb::AUTH_PLUGIN_NAME, &a.plugin);
            spb.string(spb::AUTH_PLUGIN_LIST, "Srp256,Srp");
            spb.string(spb::SPECIFIC_AUTH_DATA, &a.proof_hex);
        }
        AuthState::Legacy => {
            spb.string(spb::PASSWORD, &config.password);
        }
        AuthState::Done => {}
    }

    if let Some(role) = &config.role {
        spb.string(spb::SQL_ROLE_NAME, role);
    }
    spb.into_vec()
}

/// Construtor do SPB de uma ação `op_service_start`. O primeiro byte é o código
/// da ação; argumentos string usam prefixo de comprimento de **2 bytes (LE)**,
/// argumentos inteiros são **4 bytes LE sem prefixo**, e flags são só o tag.
/// (Distinto do [`ParameterBuffer`], que usa clumplets de 1 byte.)
struct ActionSpb {
    buf: Vec<u8>,
}

impl ActionSpb {
    fn new(action: u8) -> Self {
        Self { buf: vec![action] }
    }

    /// Argumento string: `tag | comprimento(2 LE) | bytes`.
    fn string(&mut self, tag: u8, value: &str) -> &mut Self {
        let bytes = value.as_bytes();
        self.buf.push(tag);
        self.buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Argumento inteiro: `tag | valor(4 LE)`, sem prefixo de comprimento.
    fn int(&mut self, tag: u8, value: u32) -> &mut Self {
        self.buf.push(tag);
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Flag isolada: apenas o tag.
    fn flag(&mut self, tag: u8) -> &mut Self {
        self.buf.push(tag);
        self
    }

    fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Parâmetros para criar (`add_user`) ou alterar (`modify_user`) um usuário.
/// Construa com [`UserParams::new`] e os métodos encadeáveis; só os campos
/// definidos entram no SPB (em `modify_user`, os ausentes ficam intactos).
#[derive(Debug, Clone, Default)]
pub struct UserParams {
    username: String,
    password: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    user_id: Option<u32>,
    group_id: Option<u32>,
    admin: Option<bool>,
}

impl UserParams {
    /// Inicia os parâmetros para o usuário de nome `username`.
    pub fn new(username: impl Into<String>) -> Self {
        Self { username: username.into(), ..Default::default() }
    }

    /// Define a senha (`isc_spb_sec_password`).
    pub fn password(mut self, v: impl Into<String>) -> Self {
        self.password = Some(v.into());
        self
    }

    /// Define o primeiro nome (`isc_spb_sec_firstname`).
    pub fn first_name(mut self, v: impl Into<String>) -> Self {
        self.first_name = Some(v.into());
        self
    }

    /// Define o nome do meio (`isc_spb_sec_middlename`).
    pub fn middle_name(mut self, v: impl Into<String>) -> Self {
        self.middle_name = Some(v.into());
        self
    }

    /// Define o sobrenome (`isc_spb_sec_lastname`).
    pub fn last_name(mut self, v: impl Into<String>) -> Self {
        self.last_name = Some(v.into());
        self
    }

    /// Define o UID Unix (`isc_spb_sec_userid`).
    pub fn user_id(mut self, v: u32) -> Self {
        self.user_id = Some(v);
        self
    }

    /// Define o GID Unix (`isc_spb_sec_groupid`).
    pub fn group_id(mut self, v: u32) -> Self {
        self.group_id = Some(v);
        self
    }

    /// Concede ou revoga o papel de administrador (`isc_spb_sec_admin`).
    pub fn admin(mut self, v: bool) -> Self {
        self.admin = Some(v);
        self
    }
}

/// Um usuário do banco de segurança, devolvido por
/// [`ServiceManager::display_users`]/[`display_user`](ServiceManager::display_user).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserInfo {
    pub username: String,
    pub first_name: String,
    pub middle_name: String,
    pub last_name: String,
    pub user_id: u32,
    pub group_id: u32,
}

/// Monta o SPB de `add_user`/`modify_user` a partir de [`UserParams`]. Campos
/// string usam `tag | len(2 LE) | bytes`; UID/GID/admin são inteiros de 4 bytes.
fn build_user_spb(action: u8, p: &UserParams) -> Vec<u8> {
    let mut spb = ActionSpb::new(action);
    spb.string(svc_sec::USERNAME, &p.username);
    if let Some(v) = &p.password {
        spb.string(svc_sec::PASSWORD, v);
    }
    if let Some(v) = &p.first_name {
        spb.string(svc_sec::FIRSTNAME, v);
    }
    if let Some(v) = &p.middle_name {
        spb.string(svc_sec::MIDDLENAME, v);
    }
    if let Some(v) = &p.last_name {
        spb.string(svc_sec::LASTNAME, v);
    }
    if let Some(v) = p.user_id {
        spb.int(svc_sec::USERID, v);
    }
    if let Some(v) = p.group_id {
        spb.int(svc_sec::GROUPID, v);
    }
    if let Some(v) = p.admin {
        spb.int(svc_sec::ADMIN, v as u32);
    }
    spb.into_vec()
}

/// Decodifica o buffer interno de `isc_info_svc_get_users`: uma sequência plana
/// de sub-itens, um registro de usuário começando a cada `isc_spb_sec_username`.
/// Strings (username/firstname/middlename/lastname/groupname) usam `tag|len(2
/// LE)|bytes`; UID/GID (`isc_spb_sec_userid`/`groupid`) são inteiros de 4 bytes
/// LE sem prefixo de comprimento.
fn parse_users(payload: &[u8]) -> Result<Vec<UserInfo>> {
    let mut users = Vec::new();
    let mut cur: Option<UserInfo> = None;
    let mut p = 0usize;
    while p < payload.len() {
        let tag = payload[p];
        p += 1;
        match tag {
            svc_sec::USERNAME | svc_sec::GROUPNAME | svc_sec::FIRSTNAME
            | svc_sec::MIDDLENAME | svc_sec::LASTNAME => {
                let len = payload
                    .get(p..p + 2)
                    .ok_or_else(|| Error::protocol("get_users: comprimento truncado"))?;
                let len = u16::from_le_bytes([len[0], len[1]]) as usize;
                let value = payload
                    .get(p + 2..p + 2 + len)
                    .ok_or_else(|| Error::protocol("get_users: valor truncado"))?;
                let s = String::from_utf8_lossy(value).into_owned();
                p += 2 + len;
                if tag == svc_sec::USERNAME {
                    if let Some(u) = cur.take() {
                        users.push(u);
                    }
                    cur = Some(UserInfo { username: s, ..Default::default() });
                } else if let Some(u) = cur.as_mut() {
                    match tag {
                        svc_sec::FIRSTNAME => u.first_name = s,
                        svc_sec::MIDDLENAME => u.middle_name = s,
                        svc_sec::LASTNAME => u.last_name = s,
                        _ => {} // groupname: ignorado
                    }
                }
            }
            svc_sec::USERID | svc_sec::GROUPID => {
                let v = payload
                    .get(p..p + 4)
                    .ok_or_else(|| Error::protocol("get_users: inteiro truncado"))?;
                let v = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
                p += 4;
                if let Some(u) = cur.as_mut() {
                    if tag == svc_sec::USERID {
                        u.user_id = v;
                    } else {
                        u.group_id = v;
                    }
                }
            }
            _ => break, // tag desconhecida (ou fim): encerra
        }
    }
    if let Some(u) = cur.take() {
        users.push(u);
    }
    Ok(users)
}

/// Lê o primeiro item `tag | len(2 LE) | valor` de um buffer de info de serviço.
fn read_svc_item(payload: &[u8]) -> Result<(u8, &[u8])> {
    if payload.len() < 3 {
        return Err(Error::protocol("buffer de info de serviço curto demais"));
    }
    let tag = payload[0];
    let len = u16::from_le_bytes([payload[1], payload[2]]) as usize;
    let value = payload
        .get(3..3 + len)
        .ok_or_else(|| Error::protocol("item de info de serviço truncado"))?;
    Ok((tag, value))
}

/// Extrai o valor (bytes) de um item de info de serviço de string, verificando o
/// tag esperado. Trata o caso de buffer vazio (saída esgotada) devolvendo vazio.
fn parse_svc_string(data: &[u8], expected: u8) -> Result<Vec<u8>> {
    let payload = info_payload(data)?;
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    let (tag, value) = read_svc_item(payload)?;
    if tag != expected {
        return Err(Error::protocol(format!(
            "esperava item de serviço {expected}, veio {tag}"
        )));
    }
    Ok(value.to_vec())
}

/// Extrai um item de info de serviço INTEIRO (`tag(1) | valor(4 LE)`, sem prefixo
/// de comprimento — confirmado por strace de `fbsvcmgr info_version`: o item 54
/// chega como `36 02 00 00 00 01`, valor 2 seguido de `isc_info_end`).
fn parse_svc_int(data: &[u8], expected: u8) -> Result<i32> {
    let payload = info_payload(data)?;
    if payload.is_empty() {
        return Err(Error::protocol("buffer de info de serviço vazio"));
    }
    if payload[0] != expected {
        return Err(Error::protocol(format!(
            "esperava item de serviço {expected}, veio {}",
            payload[0]
        )));
    }
    let v = payload
        .get(1..5)
        .ok_or_else(|| Error::protocol("item inteiro de info de serviço truncado"))?;
    Ok(i32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_spb_header_and_user() {
        let cfg = ConnectConfig::new().user("sysdba");
        let spb = build_attach_spb(&cfg, &AuthState::Legacy);
        // Cabeçalho: version, current_version.
        assert_eq!(spb[0], SPB_VERSION);
        assert_eq!(spb[1], SPB_CURRENT_VERSION);
        // user_name normalizado em maiúsculas.
        assert!(spb.windows(6).any(|w| w == b"SYSDBA"));
        // sem sessão SRP -> senha legada presente como clumplet.
        assert!(spb.contains(&spb::PASSWORD));
    }

    #[test]
    fn parse_int_item_from_strace() {
        // isc_info_svc_version capturado ao vivo: tag 54, valor 2 (4 LE), isc_info_end.
        let buf = [svc_info::VERSION, 2, 0, 0, 0, INFO_END];
        assert_eq!(parse_svc_int(&buf, svc_info::VERSION).unwrap(), 2);
        // Tag inesperado é erro.
        assert!(parse_svc_int(&buf, svc_info::RUNNING).is_err());
    }

    #[test]
    fn parse_string_item() {
        // tag 55 (server_version), len 3 (LE), "abc", isc_info_end
        let buf = [55u8, 3, 0, b'a', b'b', b'c', INFO_END];
        let v = parse_svc_string(&buf, svc_info::SERVER_VERSION).unwrap();
        assert_eq!(v, b"abc");
    }

    #[test]
    fn parse_empty_output_is_empty() {
        let buf = [INFO_END];
        let v = parse_svc_string(&buf, svc_info::TO_EOF).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn action_spb_string_uses_2byte_le_length() {
        // Espelha o strace de `fbsvcmgr action_db_stats dbname employee`:
        // 0b (db_stats) | 6a (dbname) | 0800 (len 8 LE) | "employee".
        let mut spb = ActionSpb::new(svc_action::DB_STATS);
        spb.string(spb::DBNAME, "employee");
        assert_eq!(
            spb.into_vec(),
            b"\x0b\x6a\x08\x00employee".to_vec(),
        );
    }

    #[test]
    fn user_spb_add_matches_strace() {
        // strace de `action_add_user sec_username FDBTEST sec_password secret99
        // sec_firstname Test sec_lastname User`:
        // 04 | 07 0700 FDBTEST | 08 0800 secret99 | 0a 0400 Test | 0c 0400 User.
        let p = UserParams::new("FDBTEST")
            .password("secret99")
            .first_name("Test")
            .last_name("User");
        let spb = build_user_spb(svc_action::ADD_USER, &p);
        assert_eq!(
            spb,
            b"\x04\x07\x07\x00FDBTEST\x08\x08\x00secret99\x0a\x04\x00Test\x0c\x04\x00User".to_vec(),
        );
    }

    #[test]
    fn user_spb_delete_is_just_username() {
        let mut spb = ActionSpb::new(svc_action::DELETE_USER);
        spb.string(svc_sec::USERNAME, "FDBTEST");
        assert_eq!(spb.into_vec(), b"\x05\x07\x07\x00FDBTEST".to_vec());
    }

    /// Decodifica uma string hex em bytes (auxiliar de teste).
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn parse_users_from_strace_payload() {
        // Payload interno de isc_info_svc_get_users capturado ao vivo (3 usuários),
        // montado por campo para legibilidade.
        let payload = hex(concat!(
            "070600", "535953444241",       // username "SYSDBA"
            "0a0300", "53716c",             // first "Sql"
            "0b0600", "536572766572",       // middle "Server"
            "0c0d00", "41646d696e6973747261746f72", // last "Administrator"
            "05", "00000000",               // userid 0
            "06", "00000000",               // groupid 0
            "070800", "4653435343504938",   // username "FSCSCPI8"
            "0a0000", "0b0000", "0c0000",   // first/middle/last vazios
            "05", "00000000", "06", "00000000",
            "070600", "465343534950",       // username "FSCSIP"
            "0a0000", "0b0000", "0c0000",
            "05", "00000000", "06", "00000000",
        ));
        let users = parse_users(&payload).unwrap();
        assert_eq!(users.len(), 3);
        assert_eq!(users[0].username, "SYSDBA");
        assert_eq!(users[0].first_name, "Sql");
        assert_eq!(users[0].middle_name, "Server");
        assert_eq!(users[0].last_name, "Administrator");
        assert_eq!(users[1].username, "FSCSCPI8");
        assert_eq!(users[1].first_name, "");
        assert_eq!(users[2].username, "FSCSIP");
    }

    #[test]
    fn action_spb_backup_matches_strace() {
        // `action_backup dbname employee bkp_file /tmp/x bkp_factor não usado`,
        // com NO_GARBAGE_COLLECT|IGNORE_CHECKSUMS e verbose:
        // 01 | dbname | bkp_file | 6c (options) | bitmask(4 LE) | 6b (verbose).
        let mut spb = ActionSpb::new(svc_action::BACKUP);
        spb.string(spb::DBNAME, "db");
        spb.string(svc_bkp::FILE, "f");
        spb.int(spb::OPTIONS, svc_bkp::NO_GARBAGE_COLLECT | svc_bkp::IGNORE_CHECKSUMS);
        spb.flag(spb::VERBOSE);
        assert_eq!(
            spb.into_vec(),
            vec![
                svc_action::BACKUP,
                spb::DBNAME, 2, 0, b'd', b'b',
                svc_bkp::FILE, 1, 0, b'f',
                spb::OPTIONS, 0x09, 0, 0, 0, // 8 | 1 = 9, little-endian
                spb::VERBOSE,
            ],
        );
    }
}
