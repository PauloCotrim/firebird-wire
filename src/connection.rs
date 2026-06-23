//! A conexão TCP: negociação de protocolo, autenticação SRP, criptografia de
//! comunicação (wire) opcional, e attach/create do banco de dados.

use std::net::{TcpStream, ToSocketAddrs};

use crate::auth::srp::{SrpClient, SrpHash, parse_server_data};
use crate::auth::wirecrypt::{WireCryptPlugin, make_ciphers};
use crate::config::{ConnectConfig, WireCrypt};
use crate::error::{Error, Result};
use crate::wire::consts::*;
use crate::wire::response::{read_op, read_response, read_response_body};
use crate::wire::stream::{FbStream, op_name, op_packet};
use crate::wire::xdr::{ParameterBuffer, XdrWriter};

/// Versões de protocolo que oferecemos, em preferência ascendente (`weight`).
const OFFERED_PROTOCOLS: &[i32] = &[
    PROTOCOL_VERSION13,
    PROTOCOL_VERSION15,
    PROTOCOL_VERSION16,
    PROTOCOL_VERSION17,
    PROTOCOL_VERSION18,
    PROTOCOL_VERSION19,
];

/// Um anexo (attachment) autenticado a um banco de dados.
pub struct Connection {
    stream: FbStream,
    db_handle: i32,
    protocol_version: i32,
    charset: crate::charset::Charset,
    /// Contador para atribuir ids únicos de registro de eventos nesta conexão.
    event_seq: i32,
}

impl Connection {
    /// Conecta ao servidor e anexa (attach) a um banco de dados existente.
    pub fn connect(config: &ConnectConfig) -> Result<Connection> {
        Self::open(config, false)
    }

    /// Conecta e cria um novo banco de dados, e então anexa (attach) a ele.
    pub fn create_database(config: &ConnectConfig) -> Result<Connection> {
        Self::open(config, true)
    }

    fn open(config: &ConnectConfig, create: bool) -> Result<Connection> {
        Self::open_inner(config, create)
    }

    fn open_inner(config: &ConnectConfig, create: bool) -> Result<Connection> {
        let connect_op = if create { op::CREATE } else { op::ATTACH };

        // O handshake (connect + accept + SRP + wire-crypt) é idêntico ao do
        // attach de serviço; está fatorado em [`handshake`].
        let Handshake {
            mut stream,
            protocol_version,
            auth,
        } = handshake(config, connect_op, &config.database)?;

        // --- attach / create ----------------------------------------------
        let dpb = build_dpb(config, create, &auth);
        let mut w = op_packet(connect_op);
        w.put_i32(0); // id do objeto de banco de dados
        w.put_str(&config.database);
        w.put_bytes(&dpb);
        stream.send(&w)?;
        let resp = attach_response(&mut stream)?;

        let mut conn = Connection {
            stream,
            db_handle: resp.handle,
            protocol_version,
            charset: crate::charset::Charset::from_name(&config.charset),
            event_seq: 0,
        };

        // Opcional: pede os tipos nativos (INT128/DECFLOAT/WITH TIME ZONE) caso o
        // servidor esteja coagindo-os via DataTypeCompatibility. São features de
        // FB4+ (protocolo >= 16); ignoradas em servidores mais antigos.
        if config.native_data_types && protocol_version >= 16 {
            for stmt in [
                "SET BIND OF INT128 TO NATIVE",
                "SET BIND OF DECFLOAT TO NATIVE",
                "SET BIND OF TIME ZONE TO NATIVE",
            ] {
                conn.exec_immediate(None, stmt)?;
            }
        }

        Ok(conn)
    }

    /// Devolve o próximo id de registro de eventos (único nesta conexão).
    pub(crate) fn next_event_id(&mut self) -> i32 {
        self.event_seq += 1;
        self.event_seq
    }

    /// O charset da conexão, usado para decodificar texto vindo do servidor.
    pub fn charset(&self) -> crate::charset::Charset {
        self.charset
    }

    /// Desanexa (detach) do banco de dados e fecha o socket.
    pub fn close(mut self) -> Result<()> {
        let mut w = op_packet(op::DETACH);
        w.put_i32(self.db_handle);
        self.stream.send(&w)?;
        let _ = read_response(&mut self.stream)?;
        Ok(())
    }

    /// Faz um round-trip de `op_ping` para verificar se a conexão está viva.
    pub fn ping(&mut self) -> Result<()> {
        let w = op_packet(op::PING);
        self.stream.send(&w)?;
        read_response(&mut self.stream)?;
        Ok(())
    }

    /// A versão de protocolo negociada (número base, ex.: `18` para FB5).
    pub fn protocol_version(&self) -> i32 {
        self.protocol_version
    }

    /// Se o protocolo negociado suporta as ops de batch (array-DML).
    pub fn supports_batch(&self) -> bool {
        self.protocol_version >= 16
    }

    /// Se o protocolo negociado suporta cursores roláveis (scrollable).
    pub fn supports_fetch_scroll(&self) -> bool {
        self.protocol_version >= 17
    }

    /// Executa um comando SQL sem prepare prévio (`op_exec_immediate`). Use para DDL
    /// (CREATE/ALTER/DROP TABLE, índices, procedures…) ou DML sem retorno de linhas.
    ///
    /// Passe `None` para deixar o driver criar e fazer commit de uma transação
    /// implícita (necessário para DDL autocommit). Passe `Some(&tx)` para executar
    /// dentro de uma transação existente.
    pub fn exec_immediate(
        &mut self,
        tx: Option<&crate::transaction::Transaction>,
        sql: &str,
    ) -> Result<()> {
        match tx {
            Some(t) => self.exec_immediate_inner(t.handle(), sql),
            None => {
                // DDL exige contexto de transação no wire; cria e faz commit implicitamente.
                let implicit_tx = self.begin()?;
                let tx_handle = implicit_tx.handle();
                match self.exec_immediate_inner(tx_handle, sql) {
                    Ok(()) => implicit_tx.commit(self),
                    Err(e) => {
                        let _ = implicit_tx.rollback(self);
                        Err(e)
                    }
                }
            }
        }
    }

    // Envia op_exec_immediate com os campos na ordem correta confirmada via strace:
    // tx_handle (campo 1) | db_handle (campo 2) | dialect | sql | items | buf_len.
    fn exec_immediate_inner(&mut self, tx_handle: i32, sql: &str) -> Result<()> {
        let mut w = op_packet(op::EXEC_IMMEDIATE);
        w.put_i32(tx_handle); // campo 1: transação
        w.put_i32(self.db_handle); // campo 2: banco de dados
        w.put_i32(3); // dialeto SQL (3 = padrão)
        w.put_str(sql);
        w.put_bytes(&[]); // itens de info vazios
        w.put_i32(0); // buffer_length = 0
        self.stream.send(&w)?;
        read_response(&mut self.stream)?;
        Ok(())
    }

    /// Se a comunicação (wire) está criptografada.
    pub fn is_encrypted(&self) -> bool {
        self.stream.is_encrypted()
    }

    /// Se a conexão ainda está sã (sem erro de I/O nem desync de protocolo). O
    /// [`crate::Pool`] usa isto para descartar conexões com falha em vez de
    /// devolvê-las ao conjunto de ociosas.
    pub fn is_healthy(&self) -> bool {
        !self.stream.is_broken()
    }

    // -- acessores internos para módulos irmãos ----------------------------

    pub(crate) fn io(&mut self) -> &mut FbStream {
        &mut self.stream
    }

    pub(crate) fn db_handle(&self) -> i32 {
        self.db_handle
    }
}

/// O que o servidor nos informou em seu pacote de accept.
struct Accept {
    version: i32,
    /// Dados SRP do servidor (salt + B); vazio para um `op_accept` simples.
    data: Vec<u8>,
    /// Nome do plugin de autenticação escolhido.
    plugin: String,
    /// Se o servidor nos considera já autenticados.
    authenticated: bool,
    /// Buffer de troca de chaves de cifra (lista os plugins de wire-crypt disponíveis).
    keys: Vec<u8>,
    /// Verdadeiro para `op_cond_accept` (98): o servidor pede que a autenticação
    /// continue via `op_cont_auth` (é o que servidores com `WireCrypt=Required`
    /// fazem, pois as chaves da cifra vêm na resposta do cont_auth).
    cond: bool,
}

fn read_accept(stream: &mut FbStream) -> Result<Accept> {
    let code = read_op(stream)?;
    match code {
        c if c == op::ACCEPT => {
            let version = stream.read_i32()?;
            let _arch = stream.read_i32()?;
            let _ptype = stream.read_i32()?;
            Ok(Accept {
                version,
                data: Vec::new(),
                plugin: String::new(),
                authenticated: true,
                keys: Vec::new(),
                cond: false,
            })
        }
        // op_accept_data e op_cond_accept compartilham um layout de comunicação
        // (wire) idêntico; a única diferença é se o cliente ainda precisa
        // concluir a autenticação, o que lemos da flag `authenticated`.
        c if c == op::ACCEPT_DATA || c == op::COND_ACCEPT => {
            let version = stream.read_i32()?;
            let _arch = stream.read_i32()?;
            let _ptype = stream.read_i32()?;
            let data = stream.read_bytes()?;
            let plugin = String::from_utf8_lossy(&stream.read_bytes()?)
                .trim()
                .to_string();
            let authenticated = stream.read_i32()? != 0;
            let keys = stream.read_bytes()?;
            Ok(Accept {
                version,
                data,
                plugin,
                authenticated,
                keys,
                cond: c == op::COND_ACCEPT,
            })
        }
        c if c == op::REJECT => Err(Error::auth("server rejected the connection")),
        c if c == op::RESPONSE => {
            // Uma resposta de erro durante o connect.
            crate::wire::response::read_response_body(stream)?.into_result()?;
            Err(Error::protocol("unexpected op_response during connect"))
        }
        other => Err(Error::protocol(format!(
            "unexpected handshake packet {} ({other})",
            op_name(other)
        ))),
    }
}

/// A prova SRP a embutir no DPB/SPB de attach, mais a chave de sessão derivada.
pub(crate) struct AuthData {
    pub(crate) plugin: String,
    pub(crate) proof_hex: String,
    pub(crate) session_key: Vec<u8>,
}

/// Como a autenticação foi concluída no handshake, e portanto como ela deve ser
/// apresentada no buffer de parâmetros (DPB de banco ou SPB de serviço).
pub(crate) enum AuthState {
    /// Embute a prova SRP no PB (`isc_dpb_specific_auth_data` / `isc_spb_specific_auth_data`).
    Proof(AuthData),
    /// Sem sessão SRP: recorre a senha legada.
    Legacy,
    /// Já autenticado por `op_cont_auth` (a prova não vai no PB).
    Done,
}

/// O resultado do handshake: o socket (já criptografado, se negociado), a versão
/// de protocolo negociada e como apresentar a autenticação no PB de attach.
pub(crate) struct Handshake {
    pub(crate) stream: FbStream,
    pub(crate) protocol_version: i32,
    pub(crate) auth: AuthState,
}

/// Executa o handshake comum a attach de banco e de serviço: `op_connect`, lê o
/// accept do servidor, calcula a prova SRP e negocia a criptografia de
/// comunicação (wire). `connect_op` é a operação anunciada no bloco connect
/// (`op_attach`/`op_create`/`op_service_attach`); `target` é o arquivo/serviço.
pub(crate) fn handshake(
    config: &ConnectConfig,
    connect_op: i32,
    target: &str,
) -> Result<Handshake> {
    config.validate()?;
    let sock = connect_socket(config)?;
    let mut stream = FbStream::new(sock);

    let mut srp = SrpClient::new(SrpHash::Sha256);

    // --- op_connect --------------------------------------------------------
    let pubkey = srp.public_key_hex();
    let cnct = build_cnct_block(config, &pubkey);
    dbg_log(&format!("pubkey hex ({} chars)", pubkey.len()));
    dbg_log(&format!("cnct ({} bytes): {}", cnct.len(), hexdump(&cnct)));
    let mut w = op_packet(op::CONNECT);
    w.put_i32(connect_op); // p_cnct_operation (operação)
    w.put_i32(CONNECT_VERSION3);
    w.put_i32(ARCH_GENERIC);
    w.put_str(target); // p_cnct_file
    w.put_i32(OFFERED_PROTOCOLS.len() as i32);
    w.put_bytes(&cnct); // p_cnct_user_id
    for (i, &version) in OFFERED_PROTOCOLS.iter().enumerate() {
        w.put_i32(version);
        w.put_i32(ARCH_GENERIC);
        w.put_i32(PTYPE_RPC); // tipo mínimo aceitável
        w.put_i32(PTYPE_BATCH_SEND); // tipo máximo aceitável (sem lazy-send)
        w.put_i32((i + 1) as i32); // weight (peso)
    }
    stream.send(&w)?;
    dbg_log("sent op_connect");

    // --- accept / autenticação ---------------------------------------------
    let accept = read_accept(&mut stream)?;
    // A versão chega como um USHORT com sinal estendido (ex.: 0xffff8013);
    // mantemos os 15 bits baixos para recuperar a versão base (flag removida).
    let protocol_version = accept.version & 0x7fff;
    dbg_log(&format!(
        "accept: proto={protocol_version} plugin={:?} authenticated={} data_len={} keys_len={}",
        accept.plugin,
        accept.authenticated,
        accept.data.len(),
        accept.keys.len()
    ));

    // Calcula a prova SRP; no caminho comum ela viaja dentro do PB de attach
    // (isc_*_specific_auth_data), o caminho que fbclient/isql usam.
    let auth = compute_auth(config, &mut srp, &accept)?;
    let session_key = auth.as_ref().map(|a| a.session_key.clone());
    dbg_log(&format!("auth computed; have_proof={}", auth.is_some()));

    // --- criptografia de comunicação (wire) --------------------------------
    // Quando o servidor pede continuação (`op_cond_accept`, típico de
    // `WireCrypt=Required`), concluímos a autenticação por `op_cont_auth`: a
    // resposta traz as chaves da cifra (incl. o nonce do ChaCha). Caso
    // contrário, usamos a prova embutida no PB e as chaves do accept.
    let auth = match (auth, accept.cond, config.wire_crypt != WireCrypt::Disabled) {
        (Some(a), true, true) => {
            let keys = continue_auth(&mut stream, &a)?;
            negotiate_crypt(&mut stream, config, Some(&a.session_key), &keys)?;
            AuthState::Done
        }
        (Some(a), _, _) => {
            negotiate_crypt(&mut stream, config, session_key.as_deref(), &accept.keys)?;
            AuthState::Proof(a)
        }
        (None, _, _) => {
            negotiate_crypt(&mut stream, config, session_key.as_deref(), &accept.keys)?;
            AuthState::Legacy
        }
    };
    dbg_log(&format!(
        "crypt negotiated; encrypted={}",
        stream.is_encrypted()
    ));

    Ok(Handshake {
        stream,
        protocol_version,
        auth,
    })
}

fn connect_socket(config: &ConnectConfig) -> Result<TcpStream> {
    let addrs: Vec<_> = (config.host.as_str(), config.port)
        .to_socket_addrs()?
        .collect();
    if addrs.is_empty() {
        return Err(Error::protocol("host resolution returned no addresses"));
    }

    let mut last_err = None;
    for addr in addrs {
        let result = match config.connect_timeout {
            Some(timeout) => TcpStream::connect_timeout(&addr, timeout),
            None => TcpStream::connect(addr),
        };
        match result {
            Ok(sock) => return Ok(sock),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Err(Error::Timeout),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err
        .unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no socket address resolved")
        })
        .into())
}

/// Calcula a prova SRP a partir do salt/B do servidor. Retorna `None` para um
/// accept simples (sem dados SRP) ou quando o servidor já nos considera autenticados.
fn compute_auth(
    config: &ConnectConfig,
    srp: &mut SrpClient,
    accept: &Accept,
) -> Result<Option<AuthData>> {
    if accept.data.is_empty() || accept.authenticated {
        return Ok(None);
    }

    let hash = match accept.plugin.as_str() {
        "Srp256" => SrpHash::Sha256,
        "Srp" => SrpHash::Sha1,
        other => return Err(Error::auth(format!("unsupported auth plugin '{other}'"))),
    };
    srp.set_hash(hash);

    let (salt, b_pub) = parse_server_data(&accept.data)?;
    let user = config.normalized_user();
    let (proof, key) = srp.proof(&user, &config.password, &salt, &b_pub)?;

    Ok(Some(AuthData {
        plugin: accept.plugin.clone(),
        proof_hex: crate::auth::srp::to_hex(&proof),
        session_key: key,
    }))
}

/// Conclui a autenticação SRP via `op_cont_auth` e devolve o buffer de chaves de
/// cifra que vem na resposta (`p_resp_data`). É o caminho que o fbclient usa com
/// servidores `WireCrypt=Required`: as chaves (com o nonce dos plugins ChaCha)
/// só chegam após esta rodada. Layout do `op_cont_auth`:
/// `data(prova, cstring) | name(plugin) | list(plugins) | keys(cstring vazia)`.
fn continue_auth(stream: &mut FbStream, auth: &AuthData) -> Result<Vec<u8>> {
    let mut w = op_packet(op::CONT_AUTH);
    w.put_str(&auth.proof_hex);
    w.put_str(&auth.plugin);
    w.put_str("Srp256,Srp,Legacy_Auth");
    w.put_bytes(&[]);
    stream.send(&w)?;
    let resp = read_response(stream)?;
    Ok(resp.data)
}

/// Lê a resposta para `op_attach`/`op_create`/`op_service_attach`. Com a
/// autenticação carregada no PB o servidor normalmente responde `op_response`
/// diretamente, mas pode conduzir uma ou mais rodadas de `op_cont_auth` antes;
/// absorva-as.
pub(crate) fn attach_response(stream: &mut FbStream) -> Result<crate::wire::response::Response> {
    loop {
        let code = read_op(stream)?;
        if code == op::RESPONSE {
            return read_response_body(stream)?.into_result();
        } else if code == op::CONT_AUTH {
            // data, name, list, keys — consome e continua; o servidor virá
            // em seguida com o op_response real.
            for _ in 0..4 {
                let _ = stream.read_bytes()?;
            }
        } else {
            return Err(Error::protocol(format!(
                "unexpected packet after attach: {} ({code})",
                op_name(code)
            )));
        }
    }
}

/// Negocia a criptografia de comunicação (wire) conforme a postura [`WireCrypt`] requisitada.
fn negotiate_crypt(
    stream: &mut FbStream,
    config: &ConnectConfig,
    session_key: Option<&[u8]>,
    keys: &[u8],
) -> Result<()> {
    if config.wire_crypt == WireCrypt::Disabled {
        return Ok(());
    }

    let key = match session_key {
        Some(k) => k,
        None => {
            if config.wire_crypt == WireCrypt::Required {
                return Err(Error::auth(
                    "encryption required but no session key was negotiated",
                ));
            }
            return Ok(());
        }
    };

    // O servidor anuncia seus plugins de wire-crypt no buffer de troca de chaves
    // (`keys`). Para ChaCha/ChaCha64 o nome vem seguido de `\0` e do nonce (12 ou
    // 8 bytes); Arc4 não tem nonce. Preferimos a cifra mais forte disponível.
    let (plugin, nonce) = if let Some(n) = find_after(keys, b"ChaCha\x00", 12) {
        (WireCryptPlugin::ChaCha, n)
    } else if let Some(n) = find_after(keys, b"ChaCha64\x00", 8) {
        (WireCryptPlugin::ChaCha64, n)
    } else if contains_subslice(keys, b"Arc4") {
        (WireCryptPlugin::Arc4, Vec::new())
    } else {
        if config.wire_crypt == WireCrypt::Required {
            return Err(Error::auth("server offers no supported wire-crypt plugin"));
        }
        return Ok(()); // continua em texto puro
    };

    let mut w = op_packet(op::CRYPT);
    w.put_str(plugin.name()); // plugin
    w.put_str("Symmetric"); // tipo de chave
    stream.send(&w)?;

    // A partir daqui a comunicação (wire) está criptografada em ambas as direções.
    let (rd, wr) = make_ciphers(plugin, key, &nonce);
    stream.enable_encryption(rd, wr);

    read_response(stream)?;
    Ok(())
}

/// Procura `marker` em `keys` e devolve os `n` bytes seguintes (o nonce do
/// plugin de wire-crypt), se houver espaço.
fn find_after(keys: &[u8], marker: &[u8], n: usize) -> Option<Vec<u8>> {
    let i = keys.windows(marker.len()).position(|w| w == marker)?;
    let start = i + marker.len();
    keys.get(start..start + n).map(|s| s.to_vec())
}

// ---------------------------------------------------------------------------
// Construção do buffer de parâmetros
// ---------------------------------------------------------------------------

fn wire_crypt_level(wc: WireCrypt) -> i32 {
    match wc {
        WireCrypt::Disabled => wire_crypt::DISABLED,
        WireCrypt::Enabled => wire_crypt::ENABLED,
        WireCrypt::Required => wire_crypt::REQUIRED,
    }
}

/// Constrói o bloco `p_cnct_user_id`: usuário, negociação de plugin, a chave
/// pública SRP (em pedaços), e o nível de cifra desejado.
fn build_cnct_block(config: &ConnectConfig, public_key_hex: &str) -> Vec<u8> {
    let mut b = Vec::new();
    let user = config.normalized_user();

    push_cnct(&mut b, cnct::LOGIN, user.as_bytes());
    push_cnct(&mut b, cnct::PLUGIN_NAME, b"Srp256");
    push_cnct(&mut b, cnct::PLUGIN_LIST, b"Srp256,Srp");

    // Usuário / host do SO, para monitoramento no lado do servidor (espelha fbclient).
    if let Some(os_user) = os_user() {
        push_cnct(&mut b, cnct::USER, os_user.as_bytes());
    }
    if let Some(host) = host_name() {
        push_cnct(&mut b, cnct::HOST, host.as_bytes());
    }

    // CNCT_specific_data carrega hex(A), dividido em pedaços de <=254 bytes cada
    // prefixados por um byte de índice de sequência.
    let data = public_key_hex.as_bytes();
    let mut idx: u8 = 0;
    let mut off = 0;
    while off < data.len() {
        let end = (off + 254).min(data.len());
        let chunk = &data[off..end];
        b.push(cnct::SPECIFIC_DATA);
        b.push((chunk.len() + 1) as u8);
        b.push(idx);
        b.extend_from_slice(chunk);
        idx = idx.wrapping_add(1);
        off = end;
    }

    push_cnct(
        &mut b,
        cnct::CLIENT_CRYPT,
        &wire_crypt_level(config.wire_crypt).to_le_bytes(),
    );
    b
}

fn push_cnct(buf: &mut Vec<u8>, tag: u8, value: &[u8]) {
    debug_assert!(value.len() <= u8::MAX as usize);
    buf.push(tag);
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

/// Constrói o Database Parameter Buffer (DPB) para attach/create.
fn build_dpb(config: &ConnectConfig, create: bool, auth: &AuthState) -> Vec<u8> {
    let mut pb = ParameterBuffer::new(DPB_VERSION1);

    pb.int(dpb::SQL_DIALECT, config.dialect);
    pb.string(dpb::LC_CTYPE, &config.charset);
    pb.string(dpb::USER_NAME, &config.normalized_user());

    match auth {
        AuthState::Proof(a) => {
            pb.string(dpb::AUTH_PLUGIN_NAME, &a.plugin);
            pb.string(dpb::AUTH_PLUGIN_LIST, "Srp256,Srp");
            pb.string(dpb::SPECIFIC_AUTH_DATA, &a.proof_hex);
        }
        AuthState::Legacy => {
            // Nenhuma sessão SRP negociada: recorre a uma senha legada.
            pb.string(dpb::PASSWORD, &config.password);
        }
        // Já autenticado via cont_auth: nada de prova/senha no DPB.
        AuthState::Done => {}
    }

    if let Some(role) = &config.role {
        pb.string(dpb::ROLE_NAME, role);
    }
    if let Some(tz) = &config.timezone {
        pb.string(dpb::SESSION_TIME_ZONE, tz);
    }
    if let Some(workers) = config.parallel_workers {
        pb.int(dpb::PARALLEL_WORKERS, workers);
    }
    if let Some(t) = config.connect_timeout {
        pb.int(
            dpb::CONNECT_TIMEOUT,
            t.as_secs().clamp(1, i32::MAX as u64) as i32,
        );
    }
    if create && let Some(size) = config.page_size {
        pb.int(dpb::PAGE_SIZE, size);
    }

    pb.int(dpb::PROCESS_ID, std::process::id() as i32);
    pb.string(dpb::PROCESS_NAME, &process_name());

    pb.into_vec()
}

fn process_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
        .map(|mut s| {
            s.truncate(255);
            s
        })
        .unwrap_or_else(|| "fdb_driver".to_string())
}

fn dbg_log(msg: &str) {
    if std::env::var_os("FB_DEBUG").is_some() {
        eprintln!("[fdb] {msg}");
    }
}

fn hexdump(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for x in b {
        let _ = write!(s, "{x:02x} ");
    }
    s
}

fn os_user() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .map(|mut s| {
            s.truncate(255);
            s
        })
}

fn host_name() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .map(|mut s| {
            s.truncate(255);
            s
        })
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Constrói uma op genérica de requisição/resposta de info (usada por transações e
/// statements). Retorna o corpo bruto do pacote `op_info_*` para `opcode`.
pub(crate) fn info_request(opcode: i32, handle: i32, items: &[u8], buffer_len: i32) -> XdrWriter {
    let mut w = op_packet(opcode);
    w.put_i32(handle);
    w.put_i32(0); // incarnation (encarnação)
    w.put_bytes(items);
    w.put_i32(buffer_len);
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cnct_block_chunks_public_key() {
        let cfg = ConnectConfig::new().user("sysdba");
        // hex de 256 chars -> pedaço 0 (254) + pedaço 1 (2).
        let hex = "a".repeat(256);
        let block = build_cnct_block(&cfg, &hex);

        // Encontra os dois clumplets specific-data e verifica seus bytes de índice.
        let mut i = 0;
        let mut chunks = Vec::new();
        while i < block.len() {
            let tag = block[i];
            let len = block[i + 1] as usize;
            let val = &block[i + 2..i + 2 + len];
            if tag == cnct::SPECIFIC_DATA {
                chunks.push((val[0], val.len() - 1));
            }
            i += 2 + len;
        }
        assert_eq!(chunks, vec![(0u8, 254usize), (1u8, 2usize)]);
    }

    #[test]
    fn dpb_has_dialect_and_charset() {
        let cfg = ConnectConfig::new().charset("UTF8").dialect(3);
        let dpb = build_dpb(&cfg, false, &AuthState::Legacy);
        assert_eq!(dpb[0], DPB_VERSION1);
        // clumplet de dialect presente.
        assert!(dpb.windows(1).any(|w| w[0] == dpb::SQL_DIALECT));
        // string de charset presente.
        assert!(contains_subslice(&dpb, b"UTF8"));
    }

    #[test]
    fn subslice_search() {
        assert!(contains_subslice(b"xxArc4yy", b"Arc4"));
        assert!(!contains_subslice(b"xxChaChayy", b"Arc4"));
    }
}
