//! The TCP connection: protocol negotiation, SRP authentication, optional wire
//! encryption, and database attach/create.

use tokio::net::TcpStream;

use crate::auth::srp::{parse_server_data, SrpClient, SrpHash};
use crate::auth::wirecrypt::{make_ciphers, WireCryptPlugin};
use crate::config::{ConnectConfig, WireCrypt};
use crate::error::{Error, Result};
use crate::wire::consts::*;
use crate::wire::response::{read_op, read_response, read_response_body};
use crate::wire::stream::{op_name, op_packet, FbStream};
use crate::wire::xdr::{ParameterBuffer, XdrWriter};

/// Protocol versions we offer, in ascending preference (`weight`).
const OFFERED_PROTOCOLS: &[i32] = &[
    PROTOCOL_VERSION13,
    PROTOCOL_VERSION15,
    PROTOCOL_VERSION16,
    PROTOCOL_VERSION17,
    PROTOCOL_VERSION18,
    PROTOCOL_VERSION19,
];

/// An authenticated attachment to a database.
pub struct Connection {
    stream: FbStream,
    db_handle: i32,
    protocol_version: i32,
}

impl Connection {
    /// Connect to the server and attach to an existing database.
    pub async fn connect(config: &ConnectConfig) -> Result<Connection> {
        Self::open(config, false).await
    }

    /// Connect and create a new database, then attach to it.
    pub async fn create_database(config: &ConnectConfig) -> Result<Connection> {
        Self::open(config, true).await
    }

    async fn open(config: &ConnectConfig, create: bool) -> Result<Connection> {
        let fut = Self::open_inner(config, create);
        match config.connect_timeout {
            Some(t) => tokio::time::timeout(t, fut).await.map_err(|_| Error::Timeout)?,
            None => fut.await,
        }
    }

    async fn open_inner(config: &ConnectConfig, create: bool) -> Result<Connection> {
        let addr = (config.host.as_str(), config.port);
        let sock = TcpStream::connect(addr).await?;
        let mut stream = FbStream::new(sock);

        let mut srp = SrpClient::new(SrpHash::Sha256);

        // --- op_connect ----------------------------------------------------
        let pubkey = srp.public_key_hex();
        let cnct = build_cnct_block(config, &pubkey);
        dbg_log(&format!("pubkey hex ({} chars)", pubkey.len()));
        dbg_log(&format!("cnct ({} bytes): {}", cnct.len(), hexdump(&cnct)));
        let mut w = op_packet(op::CONNECT);
        w.put_i32(if create { op::CREATE } else { op::ATTACH }); // p_cnct_operation
        w.put_i32(CONNECT_VERSION3);
        w.put_i32(ARCH_GENERIC);
        w.put_str(&config.database); // p_cnct_file
        w.put_i32(OFFERED_PROTOCOLS.len() as i32);
        w.put_bytes(&cnct); // p_cnct_user_id
        for (i, &version) in OFFERED_PROTOCOLS.iter().enumerate() {
            w.put_i32(version);
            w.put_i32(ARCH_GENERIC);
            w.put_i32(PTYPE_RPC); // min acceptable type
            w.put_i32(PTYPE_BATCH_SEND); // max acceptable type (no lazy-send)
            w.put_i32((i + 1) as i32); // weight
        }
        stream.send(&w).await?;
        dbg_log("sent op_connect");

        // --- accept / authenticate ----------------------------------------
        let accept = read_accept(&mut stream).await?;
        // The version arrives as a sign-extended USHORT (e.g. 0xffff8013);
        // keep the low 15 bits to recover the base version (flag stripped).
        let protocol_version = accept.version & 0x7fff;
        dbg_log(&format!(
            "accept: proto={protocol_version} plugin={:?} authenticated={} data_len={} keys_len={}",
            accept.plugin,
            accept.authenticated,
            accept.data.len(),
            accept.keys.len()
        ));

        // Compute the SRP proof; it travels inside the attach DPB
        // (isc_dpb_specific_auth_data), the path fbclient/isql use.
        let auth = compute_auth(config, &mut srp, &accept)?;
        let session_key = auth.as_ref().map(|a| a.session_key.clone());
        dbg_log(&format!("auth computed; have_proof={}", auth.is_some()));

        // --- wire encryption ----------------------------------------------
        negotiate_crypt(&mut stream, config, session_key.as_deref(), &accept.keys).await?;
        dbg_log(&format!("crypt negotiated; encrypted={}", stream.is_encrypted()));

        // --- attach / create ----------------------------------------------
        let dpb = build_dpb(config, create, auth.as_ref());
        let mut w = op_packet(if create { op::CREATE } else { op::ATTACH });
        w.put_i32(0); // database object id
        w.put_str(&config.database);
        w.put_bytes(&dpb);
        stream.send(&w).await?;
        let resp = attach_response(&mut stream).await?;

        Ok(Connection { stream, db_handle: resp.handle, protocol_version })
    }

    /// Detach from the database and close the socket.
    pub async fn close(mut self) -> Result<()> {
        let mut w = op_packet(op::DETACH);
        w.put_i32(self.db_handle);
        self.stream.send(&w).await?;
        let _ = read_response(&mut self.stream).await?;
        Ok(())
    }

    /// Round-trip a `op_ping` to check the connection is alive.
    pub async fn ping(&mut self) -> Result<()> {
        let w = op_packet(op::PING);
        self.stream.send(&w).await?;
        read_response(&mut self.stream).await?;
        Ok(())
    }

    /// The negotiated protocol version (base number, e.g. `18` for FB5).
    pub fn protocol_version(&self) -> i32 {
        self.protocol_version
    }

    /// Whether the negotiated protocol supports the batch (array-DML) ops.
    pub fn supports_batch(&self) -> bool {
        self.protocol_version >= 16
    }

    /// Whether the negotiated protocol supports scrollable cursors.
    pub fn supports_fetch_scroll(&self) -> bool {
        self.protocol_version >= 17
    }

    /// Whether the wire is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.stream.is_encrypted()
    }

    // -- internal accessors for sibling modules ----------------------------

    pub(crate) fn io(&mut self) -> &mut FbStream {
        &mut self.stream
    }

    pub(crate) fn db_handle(&self) -> i32 {
        self.db_handle
    }
}

/// What the server told us in its accept packet.
struct Accept {
    version: i32,
    /// Server SRP data (salt + B); empty for a plain `op_accept`.
    data: Vec<u8>,
    /// Chosen auth plugin name.
    plugin: String,
    /// Whether the server considers us already authenticated.
    authenticated: bool,
    /// Crypt key-exchange buffer (lists available wire-crypt plugins).
    keys: Vec<u8>,
}

async fn read_accept(stream: &mut FbStream) -> Result<Accept> {
    let code = read_op(stream).await?;
    match code {
        c if c == op::ACCEPT => {
            let version = stream.read_i32().await?;
            let _arch = stream.read_i32().await?;
            let _ptype = stream.read_i32().await?;
            Ok(Accept { version, data: Vec::new(), plugin: String::new(), authenticated: true, keys: Vec::new() })
        }
        // op_accept_data and op_cond_accept share an identical wire layout; the
        // only difference is whether the client must still finish auth, which
        // we read from the `authenticated` flag.
        c if c == op::ACCEPT_DATA || c == op::COND_ACCEPT => {
            let version = stream.read_i32().await?;
            let _arch = stream.read_i32().await?;
            let _ptype = stream.read_i32().await?;
            let data = stream.read_bytes().await?;
            let plugin = String::from_utf8_lossy(&stream.read_bytes().await?).trim().to_string();
            let authenticated = stream.read_i32().await? != 0;
            let keys = stream.read_bytes().await?;
            Ok(Accept { version, data, plugin, authenticated, keys })
        }
        c if c == op::REJECT => Err(Error::auth("server rejected the connection")),
        c if c == op::RESPONSE => {
            // An error response during connect.
            crate::wire::response::read_response_body(stream).await?.into_result()?;
            Err(Error::protocol("unexpected op_response during connect"))
        }
        other => Err(Error::protocol(format!(
            "unexpected handshake packet {} ({other})",
            op_name(other)
        ))),
    }
}

/// The SRP proof to embed in the attach DPB, plus the derived session key.
struct AuthData {
    plugin: String,
    proof_hex: String,
    session_key: Vec<u8>,
}

/// Compute the SRP proof from the server's salt/B. Returns `None` for a plain
/// accept (no SRP data) or when the server already considers us authenticated.
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
    let (proof, key) = srp.proof(&user, &config.password, &salt, &b_pub);

    Ok(Some(AuthData {
        plugin: accept.plugin.clone(),
        proof_hex: crate::auth::srp::to_hex(&proof),
        session_key: key,
    }))
}

/// Read the response to `op_attach`/`op_create`. With auth carried in the DPB
/// the server normally replies `op_response` directly, but it may drive one or
/// more `op_cont_auth` rounds first; absorb them.
async fn attach_response(stream: &mut FbStream) -> Result<crate::wire::response::Response> {
    loop {
        let code = read_op(stream).await?;
        if code == op::RESPONSE {
            return read_response_body(stream).await?.into_result();
        } else if code == op::CONT_AUTH {
            // data, name, list, keys — consume and continue; the server will
            // follow with the real op_response.
            for _ in 0..4 {
                let _ = stream.read_bytes().await?;
            }
        } else {
            return Err(Error::protocol(format!(
                "unexpected packet after attach: {} ({code})",
                op_name(code)
            )));
        }
    }
}

/// Negotiate wire encryption per the requested [`WireCrypt`] posture.
async fn negotiate_crypt(
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
                return Err(Error::auth("encryption required but no session key was negotiated"));
            }
            return Ok(());
        }
    };

    // The server advertises its wire-crypt plugins as readable names inside the
    // key-exchange buffer. We currently implement Arc4 only.
    let arc4_available = contains_subslice(keys, b"Arc4");
    if !arc4_available {
        if config.wire_crypt == WireCrypt::Required {
            return Err(Error::auth("server does not offer the Arc4 wire-crypt plugin"));
        }
        return Ok(()); // continue in clear text
    }

    let mut w = op_packet(op::CRYPT);
    w.put_str(WireCryptPlugin::Arc4.name()); // plugin
    w.put_str("Symmetric"); // key type
    stream.send(&w).await?;

    // From here the wire is encrypted in both directions.
    let (rd, wr) = make_ciphers(WireCryptPlugin::Arc4, key);
    stream.enable_encryption(rd, wr);

    read_response(stream).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Parameter-buffer construction
// ---------------------------------------------------------------------------

fn wire_crypt_level(wc: WireCrypt) -> i32 {
    match wc {
        WireCrypt::Disabled => wire_crypt::DISABLED,
        WireCrypt::Enabled => wire_crypt::ENABLED,
        WireCrypt::Required => wire_crypt::REQUIRED,
    }
}

/// Build the `p_cnct_user_id` block: user, plugin negotiation, the SRP public
/// key (chunked), and the desired crypt level.
fn build_cnct_block(config: &ConnectConfig, public_key_hex: &str) -> Vec<u8> {
    let mut b = Vec::new();
    let user = config.normalized_user();

    push_cnct(&mut b, cnct::LOGIN, user.as_bytes());
    push_cnct(&mut b, cnct::PLUGIN_NAME, b"Srp256");
    push_cnct(&mut b, cnct::PLUGIN_LIST, b"Srp256,Srp");

    // OS user / host, for server-side monitoring (mirrors fbclient).
    if let Some(os_user) = os_user() {
        push_cnct(&mut b, cnct::USER, os_user.as_bytes());
    }
    if let Some(host) = host_name() {
        push_cnct(&mut b, cnct::HOST, host.as_bytes());
    }

    // CNCT_specific_data carries hex(A), split into <=254-byte chunks each
    // prefixed by a sequence index byte.
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

    push_cnct(&mut b, cnct::CLIENT_CRYPT, &wire_crypt_level(config.wire_crypt).to_le_bytes());
    b
}

fn push_cnct(buf: &mut Vec<u8>, tag: u8, value: &[u8]) {
    debug_assert!(value.len() <= u8::MAX as usize);
    buf.push(tag);
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

/// Build the Database Parameter Buffer for attach/create.
fn build_dpb(config: &ConnectConfig, create: bool, auth: Option<&AuthData>) -> Vec<u8> {
    let mut pb = ParameterBuffer::new(DPB_VERSION1);

    pb.int(dpb::SQL_DIALECT, config.dialect);
    pb.string(dpb::LC_CTYPE, &config.charset);
    pb.string(dpb::USER_NAME, &config.normalized_user());

    match auth {
        Some(a) => {
            pb.string(dpb::AUTH_PLUGIN_NAME, &a.plugin);
            pb.string(dpb::AUTH_PLUGIN_LIST, "Srp256,Srp");
            pb.string(dpb::SPECIFIC_AUTH_DATA, &a.proof_hex);
        }
        None => {
            // No SRP session negotiated: fall back to a legacy password.
            pb.string(dpb::PASSWORD, &config.password);
        }
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
        pb.int(dpb::CONNECT_TIMEOUT, t.as_secs().clamp(1, i32::MAX as u64) as i32);
    }
    if create {
        if let Some(size) = config.page_size {
            pb.int(dpb::PAGE_SIZE, size);
        }
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
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).ok().map(|mut s| {
        s.truncate(255);
        s
    })
}

fn host_name() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()))
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

/// Build a generic info request/response op (used by transactions and
/// statements). Returns the raw `op_info_*` packet body for `opcode`.
pub(crate) fn info_request(opcode: i32, handle: i32, items: &[u8], buffer_len: i32) -> XdrWriter {
    let mut w = op_packet(opcode);
    w.put_i32(handle);
    w.put_i32(0); // incarnation
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
        // 256-char hex -> chunk 0 (254) + chunk 1 (2).
        let hex = "a".repeat(256);
        let block = build_cnct_block(&cfg, &hex);

        // Find the two specific-data clumplets and check their index bytes.
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
        let dpb = build_dpb(&cfg, false, None);
        assert_eq!(dpb[0], DPB_VERSION1);
        // dialect clumplet present.
        assert!(dpb.windows(1).any(|w| w[0] == dpb::SQL_DIALECT));
        // charset string present.
        assert!(contains_subslice(&dpb, b"UTF8"));
    }

    #[test]
    fn subslice_search() {
        assert!(contains_subslice(b"xxArc4yy", b"Arc4"));
        assert!(!contains_subslice(b"xxChaChayy", b"Arc4"));
    }
}
