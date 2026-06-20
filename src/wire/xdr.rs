//! Codificação/decodificação XDR (RFC 4506) conforme usada pelo protocolo de comunicação (wire protocol) do Firebird.
//!
//! Tudo é big-endian e preenchido (padding) até um limite de 4 bytes. Os inteiros são
//! de 32 bits no wire mesmo quando o valor lógico é menor. Este módulo
//! fornece auxiliares [`XdrWriter`]/[`XdrReader`] em memória mais construtores de clumplet
//! para os vários buffers de parâmetros (DPB/TPB/SPB/BPB/batch PB).

use crate::error::{Error, Result};

/// Arredonda `n` para cima até o próximo múltiplo de 4.
#[inline]
pub const fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

/// Constrói um fluxo (stream) de bytes XDR em memória.
#[derive(Debug, Default, Clone)]
pub struct XdrWriter {
    buf: Vec<u8>,
}

impl XdrWriter {
    #[inline]
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(64) }
    }

    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self { buf: Vec::with_capacity(cap) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// Anexa um inteiro big-endian de 32 bits.
    #[inline]
    pub fn put_i32(&mut self, v: i32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    #[inline]
    pub fn put_u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Anexa um inteiro big-endian de 64 bits (duas palavras XDR).
    #[inline]
    pub fn put_i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    #[inline]
    pub fn put_f64(&mut self, v: f64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Anexa bytes brutos sem prefixo de comprimento e sem preenchimento (padding).
    #[inline]
    pub fn put_raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Preenche (padding) o buffer com bytes zero até o próximo limite de 4 bytes.
    #[inline]
    pub fn align(&mut self) -> &mut Self {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        self
    }

    /// Anexa um opaco/string XDR: comprimento de 4 bytes, os dados, depois preenchimento (padding) com zeros
    /// até um limite de 4 bytes. Este é o formato `cstring`/`buffer` usado para DPBs,
    /// texto SQL, blobs de mensagem, etc.
    pub fn put_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.put_i32(data.len() as i32);
        self.buf.extend_from_slice(data);
        self.align();
        self
    }

    /// Conveniência para [`Self::put_bytes`] sobre um slice de string.
    #[inline]
    pub fn put_str(&mut self, s: &str) -> &mut Self {
        self.put_bytes(s.as_bytes())
    }
}

/// Lê um fluxo (stream) de bytes XDR produzido pelo servidor.
#[derive(Debug, Clone)]
pub struct XdrReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> XdrReader<'a> {
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            return Err(Error::protocol(format!(
                "short XDR read: need {n} bytes, have {}",
                self.remaining()
            )));
        }
        Ok(())
    }

    #[inline]
    pub fn get_i32(&mut self) -> Result<i32> {
        self.need(4)?;
        let v = i32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    #[inline]
    pub fn get_u32(&mut self) -> Result<u32> {
        Ok(self.get_i32()? as u32)
    }

    #[inline]
    pub fn get_i64(&mut self) -> Result<i64> {
        self.need(8)?;
        let v = i64::from_be_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    #[inline]
    pub fn get_f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(self.get_i64()? as u64))
    }

    /// Lê `n` bytes brutos sem preenchimento (padding).
    pub fn get_raw(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Pula o preenchimento (padding) até o próximo limite de 4 bytes, relativo ao início do buffer.
    #[inline]
    pub fn align(&mut self) -> Result<()> {
        let pad = pad4(self.pos) - self.pos;
        if pad > 0 {
            self.need(pad)?;
            self.pos += pad;
        }
        Ok(())
    }

    /// Lê um buffer opaco com prefixo de comprimento, alinhado em 4 bytes (espelho de
    /// [`XdrWriter::put_bytes`]).
    pub fn get_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.get_i32()? as usize;
        let data = self.get_raw(len)?;
        self.align()?;
        Ok(data)
    }

    /// Como [`Self::get_bytes`] mas retorna uma cópia própria.
    pub fn get_bytes_owned(&mut self) -> Result<Vec<u8>> {
        Ok(self.get_bytes()?.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Construtores de buffer de parâmetros (clumplet)
// ---------------------------------------------------------------------------

/// Um buffer de parâmetros (DPB/TPB/SPB/BPB) construído como uma sequência de clumplets.
///
/// Os clumplets "tradicionais" são `tag(1) + length(1) + value`. A versão 2 do DPB
/// do Firebird, em vez disso, usa comprimentos de 4 bytes; este construtor segue a forma clássica
/// de 1 byte que todo servidor ainda aceita para os itens que emitimos.
#[derive(Debug, Clone)]
pub struct ParameterBuffer {
    buf: Vec<u8>,
}

impl ParameterBuffer {
    /// Inicia um buffer com o byte de versão fornecido (ex.: `DPB_VERSION1`).
    pub fn new(version: u8) -> Self {
        Self { buf: vec![version] }
    }

    /// Inicia um buffer sem byte de versão inicial (batch PB e alguns SPBs).
    pub fn raw() -> Self {
        Self { buf: Vec::new() }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        // Um byte de versão sozinho conta como "sem parâmetros".
        self.buf.len() <= 1
    }

    /// Uma tag isolada sem valor.
    pub fn tag(&mut self, tag: u8) -> &mut Self {
        self.buf.push(tag);
        self
    }

    /// `tag + len + bytes`, comprimento codificado como um único byte (valor <= 255).
    pub fn bytes(&mut self, tag: u8, value: &[u8]) -> &mut Self {
        debug_assert!(value.len() <= u8::MAX as usize, "clumplet value too long");
        self.buf.push(tag);
        self.buf.push(value.len() as u8);
        self.buf.extend_from_slice(value);
        self
    }

    #[inline]
    pub fn string(&mut self, tag: u8, value: &str) -> &mut Self {
        self.bytes(tag, value.as_bytes())
    }

    /// Um clumplet cujo valor é um inteiro little-endian de largura mínima.
    /// Os inteiros do buffer de parâmetros do Firebird são little-endian (diferente do quadro
    /// XDR), codificados com o menor número de bytes que cabem.
    pub fn int(&mut self, tag: u8, value: i32) -> &mut Self {
        let le = value.to_le_bytes();
        // Número de bytes significativos (pelo menos 1).
        let mut n = 4;
        while n > 1 && le[n - 1] == 0 {
            n -= 1;
        }
        self.bytes(tag, &le[..n])
    }

    /// Um clumplet que carrega um valor `u32` little-endian de largura fixa.
    pub fn int_u32(&mut self, tag: u8, value: u32) -> &mut Self {
        self.bytes(tag, &value.to_le_bytes())
    }

    /// Um clumplet que carrega um valor `u64` little-endian de largura fixa (batch PB).
    pub fn int_u64(&mut self, tag: u8, value: u64) -> &mut Self {
        self.bytes(tag, &value.to_le_bytes())
    }

    /// `tag + len + bytes` usando um comprimento little-endian de 4 bytes, conforme exigido
    /// pelos itens de comprimento variável do batch parameter buffer.
    pub fn bytes_be_len4(&mut self, tag: u8, value: &[u8]) -> &mut Self {
        self.buf.push(tag);
        self.buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(value);
        self
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Decodifica um inteiro little-endian de até 8 bytes (valor de item de info /
/// buffer de parâmetros).
pub fn read_le_int(bytes: &[u8]) -> i64 {
    let mut v: i64 = 0;
    for (i, &b) in bytes.iter().enumerate().take(8) {
        v |= (b as i64) << (8 * i);
    }
    v
}

/// Decodifica um inteiro little-endian de até 8 bytes, estendendo o sinal a partir de sua
/// largura. Usado para campos que podem ser negativos (ex.: o `scale` de uma coluna).
pub fn read_le_int_signed(bytes: &[u8]) -> i64 {
    let v = read_le_int(bytes);
    let width = bytes.len().min(8);
    if width == 0 || width == 8 {
        return v;
    }
    let bits = width * 8;
    let sign = 1i64 << (bits - 1);
    if v & sign != 0 {
        v | !((1i64 << bits) - 1) // define todos os bits altos acima da largura do valor
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ints_and_bytes() {
        let mut w = XdrWriter::new();
        w.put_i32(-7).put_i64(1 << 40).put_bytes(b"hello").put_str("hi");
        let bytes = w.into_vec();

        let mut r = XdrReader::new(&bytes);
        assert_eq!(r.get_i32().unwrap(), -7);
        assert_eq!(r.get_i64().unwrap(), 1 << 40);
        assert_eq!(r.get_bytes().unwrap(), b"hello");
        assert_eq!(r.get_bytes().unwrap(), b"hi");
        assert!(r.is_empty());
    }

    #[test]
    fn put_bytes_is_padded() {
        let mut w = XdrWriter::new();
        w.put_bytes(b"abc"); // 4 (len) + 3 (dados) + 1 (preenchimento) = 8
        assert_eq!(w.len(), 8);
        assert_eq!(&w.as_slice()[4..7], b"abc");
        assert_eq!(w.as_slice()[7], 0);
    }

    #[test]
    fn clumplet_minimal_int_width() {
        let mut pb = ParameterBuffer::new(crate::wire::consts::DPB_VERSION1);
        pb.int(crate::wire::consts::dpb::SQL_DIALECT, 3);
        // version(1) + tag(1) + len(1) + valor de 1 byte
        assert_eq!(pb.as_slice(), &[1, 63, 1, 3]);
    }

    #[test]
    fn le_int_decode() {
        assert_eq!(read_le_int(&[0x10, 0x27]), 10000);
        assert_eq!(read_le_int(&[0xff]), 255);
    }
}
