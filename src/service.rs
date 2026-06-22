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

    // -- ações de alto nível ------------------------------------------------

    /// Lê o log do servidor (`firebird.log`) via `isc_action_svc_get_fb_log`.
    /// (A ação não tem argumentos: o SPB é apenas o código da ação.)
    pub async fn get_fb_log(&mut self) -> Result<String> {
        let mut spb = ParameterBuffer::raw();
        spb.tag(svc_action::GET_FB_LOG);
        self.run(&spb.into_vec()).await
    }

    // -- auxiliares ---------------------------------------------------------

    /// Consulta um único item de info que devolve uma string.
    async fn query_string(&mut self, item: u8) -> Result<String> {
        let data = self.info(&[], &[item], DEFAULT_INFO_BUF).await?;
        let value = parse_svc_string(&data, item)?;
        Ok(String::from_utf8_lossy(&value).into_owned())
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
}
