//! Fluxo (stream) de pacotes enquadrado, opcionalmente criptografado, sobre uma conexão TCP.
//!
//! O Firebird não tem um prefixo de comprimento geral para o pacote: cada operação é uma sequência
//! de campos XDR cujo formato depende do op code. Por isso lemos os campos
//! sob demanda diretamente do socket em vez de armazenar pacotes inteiros em buffer.
//!
//! Após o handshake de wire-crypt (`op_crypt`) cada byte subsequente em ambas
//! as direções passa por uma [`Cipher`] de fluxo (stream). Como as cifras de fluxo (stream) são
//! dependentes de posição, a cifra é aplicada aos bytes brutos exatamente uma vez, em
//! ordem, conforme atravessam o socket.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::error::{Error, Result};
use crate::wire::consts::{INFO_END, op};
use crate::wire::xdr::{XdrWriter, pad4};

/// Uma cifra de fluxo (stream) simétrica aplicada ao protocolo de comunicação (wire protocol) após `op_crypt`.
///
/// As implementações alteram o buffer no lugar. A mesma posição de byte deve ser
/// processada exatamente uma vez; a camada de fluxo (stream) garante isso.
pub trait Cipher: Send {
    fn process(&mut self, data: &mut [u8]);
}

/// A conexão enquadrada com um servidor Firebird.
pub struct FbStream {
    sock: TcpStream,
    /// Bytes descriptografados já extraídos do socket mas ainda não consumidos.
    rbuf: Vec<u8>,
    rpos: usize,
    /// Bytes de saida acumulados antes de um descarregamento (flush).
    wbuf: Vec<u8>,
    read_cipher: Option<Box<dyn Cipher>>,
    write_cipher: Option<Box<dyn Cipher>>,
    /// Verdadeiro após um erro de I/O ou um desync de protocolo: o stream pode
    /// ter bytes pendentes em estado desconhecido e não deve ser reutilizado (o
    /// pool descarta conexões assim marcadas em vez de devolvê-las).
    broken: bool,
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
            broken: false,
        }
    }

    /// Marca o stream como inutilizável (erro de I/O ou desync de protocolo).
    pub fn mark_broken(&mut self) {
        self.broken = true;
    }

    /// Se o stream sofreu um erro de I/O ou desync e não deve ser reutilizado.
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// Instala as cifras de wire negociadas. Chamado uma vez, logo após o handshake
    /// de crypt; todo o tráfego a partir deste ponto é criptografado.
    pub fn enable_encryption(&mut self, read: Box<dyn Cipher>, write: Box<dyn Cipher>) {
        self.read_cipher = Some(read);
        self.write_cipher = Some(write);
    }

    pub fn is_encrypted(&self) -> bool {
        self.read_cipher.is_some()
    }

    /// O IP do servidor (peer) deste socket. Usado para abrir o canal auxiliar de
    /// eventos no mesmo host.
    pub fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.sock.peer_addr().ok().map(|a| a.ip())
    }

    // -- escrita -----------------------------------------------------------

    /// Anexa uma operação construída em XDR ao buffer de envio. Use [`Self::flush`]
    /// para empurrá-la ao socket. A maioria dos chamadores usa [`Self::send`].
    pub fn enqueue(&mut self, w: &XdrWriter) {
        self.wbuf.extend_from_slice(w.as_slice());
    }

    /// Descarrega (flush) toda a saida em buffer, criptografando se uma cifra estiver instalada.
    pub fn flush(&mut self) -> Result<()> {
        if self.wbuf.is_empty() {
            return Ok(());
        }
        if let Some(c) = self.write_cipher.as_mut() {
            c.process(&mut self.wbuf);
        }
        if let Err(e) = self.sock.write_all(&self.wbuf) {
            self.broken = true;
            return Err(e.into());
        }
        if let Err(e) = self.sock.flush() {
            self.broken = true;
            return Err(e.into());
        }
        self.wbuf.clear();
        Ok(())
    }

    /// Enfileira e imediatamente descarrega (flush) uma operação.
    pub fn send(&mut self, w: &XdrWriter) -> Result<()> {
        self.enqueue(w);
        self.flush()
    }

    // -- leitura -----------------------------------------------------------

    /// Garante que pelo menos `n` bytes descriptografados estejam disponíveis no cursor de leitura,
    /// extraindo (e descriptografando) mais do socket conforme necessário.
    fn fill(&mut self, n: usize) -> Result<()> {
        // Compacta ocasionalmente para que o buffer não cresça indefinidamente.
        if self.rpos > 0 && self.rpos == self.rbuf.len() {
            self.rbuf.clear();
            self.rpos = 0;
        } else if self.rpos > 16 * 1024 {
            self.rbuf.drain(..self.rpos);
            self.rpos = 0;
        }

        while self.rbuf.len() - self.rpos < n {
            let mut chunk = [0u8; 8192];
            let got = match self.sock.read(&mut chunk) {
                Ok(n) => n,
                Err(e) => {
                    self.broken = true;
                    return Err(e.into());
                }
            };
            if got == 0 {
                self.broken = true;
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

    /// Consome `n` bytes do cursor de leitura (sem preenchimento (padding) XDR).
    pub fn read_raw(&mut self, n: usize) -> Result<Vec<u8>> {
        self.fill(n)?;
        let start = self.rpos;
        self.rpos += n;
        Ok(self.rbuf[start..start + n].to_vec())
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        self.fill(4)?;
        let b = &self.rbuf[self.rpos..self.rpos + 4];
        let v = i32::from_be_bytes(b.try_into().unwrap());
        self.rpos += 4;
        Ok(v)
    }

    pub fn read_i64(&mut self) -> Result<i64> {
        self.fill(8)?;
        let b = &self.rbuf[self.rpos..self.rpos + 8];
        let v = i64::from_be_bytes(b.try_into().unwrap());
        self.rpos += 8;
        Ok(v)
    }

    pub fn read_f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(self.read_i64()? as u64))
    }

    /// Pula o preenchimento (padding) XDR para que o deslocamento absoluto de bytes desde o início do
    /// fluxo (stream) caia em um limite de 4 bytes. Rastreamos o alinhamento via `data_len`, não `rpos`,
    /// então o chamador passa o comprimento do campo de dados recém-lido.
    pub fn read_pad(&mut self, data_len: usize) -> Result<()> {
        let pad = pad4(data_len) - data_len;
        if pad > 0 {
            let _ = self.read_raw(pad)?;
        }
        Ok(())
    }

    /// Lê um buffer opaco com prefixo de comprimento, alinhado em 4 bytes.
    pub fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.read_i32()? as usize;
        let data = self.read_raw(len)?;
        self.read_pad(len)?;
        Ok(data)
    }

    /// Lê um quad do Firebird (id de blob/transação): duas palavras XDR, alta depois baixa.
    pub fn read_quad(&mut self) -> Result<u64> {
        Ok(self.read_i64()? as u64)
    }
}

/// Auxiliar: constrói uma verificação do terminador do resultado de uma info-request. Retorna os itens até
/// (mas excluindo) o byte `isc_info_end`, validando que não está truncado.
pub fn info_payload(buf: &[u8]) -> Result<&[u8]> {
    match buf.last() {
        Some(&INFO_END) => Ok(&buf[..buf.len() - 1]),
        Some(&crate::wire::consts::INFO_TRUNCATED) => {
            Err(Error::protocol("info response truncated; buffer too small"))
        }
        _ => Ok(buf),
    }
}

/// Conveniência para construir o corpo de um pacote de operação única.
pub fn op_packet(opcode: i32) -> XdrWriter {
    let mut w = XdrWriter::new();
    w.put_i32(opcode);
    w
}

/// Os nomes dos op codes, para diagnóstico.
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
