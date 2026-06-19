//! Framed, optionally-encrypted packet stream over a TCP connection.
//!
//! Firebird has no overall packet-length prefix: each operation is a sequence
//! of XDR fields whose shape depends on the op code. We therefore read fields
//! on demand straight from the socket rather than buffering whole packets.
//!
//! After the wire-crypt handshake (`op_crypt`) every subsequent byte in both
//! directions passes through a stream [`Cipher`]. Because stream ciphers are
//! position-dependent, the cipher is applied to raw bytes exactly once, in
//! order, as they cross the socket.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::wire::consts::{op, INFO_END};
use crate::wire::xdr::{pad4, XdrWriter};

/// A symmetric stream cipher applied to the wire after `op_crypt`.
///
/// Implementations mutate the buffer in place. The same byte position must be
/// processed exactly once; the stream layer guarantees this.
pub trait Cipher: Send {
    fn process(&mut self, data: &mut [u8]);
}

/// The framed connection to a Firebird server.
pub struct FbStream {
    sock: TcpStream,
    /// Decrypted bytes already pulled from the socket but not yet consumed.
    rbuf: Vec<u8>,
    rpos: usize,
    /// Outgoing bytes accumulated before a flush.
    wbuf: Vec<u8>,
    read_cipher: Option<Box<dyn Cipher>>,
    write_cipher: Option<Box<dyn Cipher>>,
}

impl FbStream {
    pub fn new(sock: TcpStream) -> Self {
        let _ = sock.set_nodelay(true);
        FbStream {
            sock,
            rbuf: Vec::with_capacity(8192),
            rpos: 0,
            wbuf: Vec::with_capacity(1024),
            read_cipher: None,
            write_cipher: None,
        }
    }

    /// Install the negotiated wire ciphers. Called once, right after the crypt
    /// handshake; all traffic from this point is encrypted.
    pub fn enable_encryption(&mut self, read: Box<dyn Cipher>, write: Box<dyn Cipher>) {
        self.read_cipher = Some(read);
        self.write_cipher = Some(write);
    }

    pub fn is_encrypted(&self) -> bool {
        self.read_cipher.is_some()
    }

    // -- writing -----------------------------------------------------------

    /// Append an XDR-built operation to the send buffer. Use [`Self::flush`]
    /// to push it to the socket. Most callers use [`Self::send`].
    pub fn enqueue(&mut self, w: &XdrWriter) {
        self.wbuf.extend_from_slice(w.as_slice());
    }

    /// Flush all buffered output, encrypting if a cipher is installed.
    pub async fn flush(&mut self) -> Result<()> {
        if self.wbuf.is_empty() {
            return Ok(());
        }
        if let Some(c) = self.write_cipher.as_mut() {
            c.process(&mut self.wbuf);
        }
        self.sock.write_all(&self.wbuf).await?;
        self.sock.flush().await?;
        self.wbuf.clear();
        Ok(())
    }

    /// Enqueue and immediately flush one operation.
    pub async fn send(&mut self, w: &XdrWriter) -> Result<()> {
        self.enqueue(w);
        self.flush().await
    }

    // -- reading -----------------------------------------------------------

    /// Ensure at least `n` decrypted bytes are available at the read cursor,
    /// pulling (and decrypting) more from the socket as needed.
    async fn fill(&mut self, n: usize) -> Result<()> {
        // Compact occasionally so the buffer doesn't grow unbounded.
        if self.rpos > 0 && self.rpos == self.rbuf.len() {
            self.rbuf.clear();
            self.rpos = 0;
        } else if self.rpos > 16 * 1024 {
            self.rbuf.drain(..self.rpos);
            self.rpos = 0;
        }

        while self.rbuf.len() - self.rpos < n {
            let mut chunk = [0u8; 8192];
            let got = self.sock.read(&mut chunk).await?;
            if got == 0 {
                return Err(Error::Closed);
            }
            let slice = &mut chunk[..got];
            if let Some(c) = self.read_cipher.as_mut() {
                c.process(slice);
            }
            self.rbuf.extend_from_slice(slice);
        }
        Ok(())
    }

    /// Consume `n` bytes from the read cursor (no XDR padding).
    pub async fn read_raw(&mut self, n: usize) -> Result<Vec<u8>> {
        self.fill(n).await?;
        let start = self.rpos;
        self.rpos += n;
        Ok(self.rbuf[start..start + n].to_vec())
    }

    pub async fn read_i32(&mut self) -> Result<i32> {
        self.fill(4).await?;
        let b = &self.rbuf[self.rpos..self.rpos + 4];
        let v = i32::from_be_bytes(b.try_into().unwrap());
        self.rpos += 4;
        Ok(v)
    }

    pub async fn read_i64(&mut self) -> Result<i64> {
        self.fill(8).await?;
        let b = &self.rbuf[self.rpos..self.rpos + 8];
        let v = i64::from_be_bytes(b.try_into().unwrap());
        self.rpos += 8;
        Ok(v)
    }

    pub async fn read_f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(self.read_i64().await? as u64))
    }

    /// Skip XDR padding so the absolute byte offset since stream start lands on
    /// a 4-byte boundary. We track alignment via `data_len`, not `rpos`, so the
    /// caller passes the length of the data field just read.
    pub async fn read_pad(&mut self, data_len: usize) -> Result<()> {
        let pad = pad4(data_len) - data_len;
        if pad > 0 {
            let _ = self.read_raw(pad).await?;
        }
        Ok(())
    }

    /// Read a length-prefixed, 4-byte-aligned opaque buffer.
    pub async fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.read_i32().await? as usize;
        let data = self.read_raw(len).await?;
        self.read_pad(len).await?;
        Ok(data)
    }

    /// Read a Firebird quad (blob/transaction id): two XDR words, high then low.
    pub async fn read_quad(&mut self) -> Result<u64> {
        Ok(self.read_i64().await? as u64)
    }
}

/// Helper: build an info-request result terminator check. Returns the items up
/// to (but excluding) the `isc_info_end` byte, validating it isn't truncated.
pub fn info_payload(buf: &[u8]) -> Result<&[u8]> {
    match buf.last() {
        Some(&INFO_END) => Ok(&buf[..buf.len() - 1]),
        Some(&crate::wire::consts::INFO_TRUNCATED) => {
            Err(Error::protocol("info response truncated; buffer too small"))
        }
        _ => Ok(buf),
    }
}

/// Convenience for building a single-op packet body.
pub fn op_packet(opcode: i32) -> XdrWriter {
    let mut w = XdrWriter::new();
    w.put_i32(opcode);
    w
}

/// The op code names, for diagnostics.
pub fn op_name(code: i32) -> &'static str {
    match code {
        op::RESPONSE => "op_response",
        op::ACCEPT => "op_accept",
        op::ACCEPT_DATA => "op_accept_data",
        op::COND_ACCEPT => "op_cond_accept",
        op::REJECT => "op_reject",
        op::DISCONNECT => "op_disconnect",
        op::FETCH_RESPONSE => "op_fetch_response",
        op::SQL_RESPONSE => "op_sql_response",
        op::CONT_AUTH => "op_cont_auth",
        op::CRYPT => "op_crypt",
        op::CRYPT_KEY_CALLBACK => "op_crypt_key_callback",
        op::BATCH_CS => "op_batch_cs",
        op::TRUSTED_AUTH => "op_trusted_auth",
        _ => "op_<other>",
    }
}
