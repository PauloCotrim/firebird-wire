//! Leitura e escrita de BLOBs.
//!
//! ## Leitura
//!
//! Uma coluna BLOB chega numa linha como um id de 8 bytes ([`Value::Blob`]); o
//! conteúdo é buscado à parte. O fluxo clássico é:
//!
//! 1. [`Connection::open_blob`] envia `op_open_blob2` (id + transação) e recebe
//!    um handle de blob.
//! 2. [`Blob::read_segment`] envia `op_get_segment` repetidamente; cada resposta
//!    traz um ou mais segmentos empacotados (`comprimento(2 LE) + bytes`) e um
//!    status que indica quando o blob acabou.
//! 3. [`Blob::close`] envia `op_close_blob`.
//!
//! Para o caso comum, [`Connection::read_blob`] faz tudo de uma vez e devolve os
//! bytes. Os BLOBs são lidos pelo protocolo clássico (não inline): ver a nota
//! sobre `inline_blob_size` em `statement.rs`.
//!
//! ## Escrita
//!
//! 1. [`Connection::create_blob`] envia `op_create_blob2` (transação) e recebe
//!    um handle + o blob_id atribuído pelo servidor.
//! 2. [`BlobWriter::write`] envia `op_put_segment` em partes de no máximo
//!    `MAX_SEGMENT` bytes. Cada segmento vai empacotado como `[len_lo, len_hi,
//!    bytes...]` dentro de uma cstring XDR.
//! 3. [`BlobWriter::close`] envia `op_close_blob` e devolve o blob_id para usar
//!    como [`Value::Blob`] em INSERT/UPDATE.
//!
//! Para o caso comum, [`Connection::write_blob`] faz tudo e devolve o id.
//!
//! [`Value::Blob`]: crate::value::Value::Blob

use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::transaction::Transaction;
use crate::wire::consts::op;
use crate::wire::response::{pipeline_requests, read_response};
use crate::wire::stream::op_packet;

/// Tamanho máximo de um segmento por chamada de `op_put_segment` (limite do protocolo).
const MAX_SEGMENT: usize = 65_535;

/// Quantos `op_get_segment`/`op_put_segment` manter em voo ao transferir um blob
/// inteiro. Cada round-trip move até ~64 KiB; sem pipeline, a latência da rede
/// domina em blobs grandes. 8 × 64 KiB ≈ 512 KiB em voo cobre o produto
/// banda × atraso de redes típicas sem estourar buffers TCP.
const PIPELINE_WINDOW: usize = 8;

/// Código GDS `isc_segstr_eof`: resposta do servidor a um `op_get_segment` num
/// blob já esgotado. A leitura em pipeline pode pedir segmentos além do fim
/// (só se sabe do EOF ao ler a resposta); esses pedidos excedentes recebem este
/// erro, que é esperado e descartado.
const ISC_SEGSTR_EOF: i32 = 335_544_367;

/// Status de `op_get_segment` em `p_resp_object`: 0 = segmento(s) lido(s) e pode
/// haver mais; 1 = `isc_segment` (o último segmento não coube no buffer, continua
/// no próximo); 2 = `isc_segstr_eof` (fim do blob). Só o EOF muda nosso fluxo —
/// 0 e 1 ambos significam "continue lendo".
const SEG_EOF: i32 = 2;

/// Quantos bytes pedir por `op_get_segment`.
const SEGMENT_BUFFER: i32 = 0xffff;

/// Um BLOB aberto para leitura no servidor.
#[derive(Debug)]
pub struct Blob {
    handle: i32,
    eof: bool,
    /// Verdadeiro após `close`; suprime o aviso de [`Drop`].
    done: bool,
}

impl Blob {
    /// O handle do blob no lado do servidor.
    pub fn handle(&self) -> i32 {
        self.handle
    }

    /// Verdadeiro depois que o servidor sinalizou fim do blob.
    pub fn is_eof(&self) -> bool {
        self.eof
    }

    /// Lê o próximo bloco do blob (um ou mais segmentos, já concatenados). Retorna
    /// um vetor vazio quando não há mais nada. Após o fim, [`Self::is_eof`] fica
    /// verdadeiro.
    pub fn read_segment(&mut self, conn: &mut Connection) -> Result<Vec<u8>> {
        if self.eof {
            return Ok(Vec::new());
        }
        let mut w = op_packet(op::GET_SEGMENT);
        w.put_i32(self.handle);
        w.put_i32(SEGMENT_BUFFER); // comprimento máximo do buffer
        w.put_bytes(&[]); // campo de segmento (cstring vazia na leitura)
        conn.io().send(&w)?;

        let resp = read_response(conn.io())?;
        // p_resp_object carrega o status; p_resp_data, os segmentos empacotados.
        if resp.handle == SEG_EOF {
            self.eof = true;
        }
        Ok(unpack_segments(&resp.data))
    }

    /// Lê o blob inteiro até o fim, concatenando todos os segmentos.
    ///
    /// Os `op_get_segment` são enviados em pipeline (até [`PIPELINE_WINDOW`] em
    /// voo) para não pagar um round-trip por bloco de 64 KiB. Como o EOF só é
    /// conhecido ao ler uma resposta, os pedidos que já estavam em voo além do
    /// fim voltam como `isc_segstr_eof` (ou vazios) e são descartados. A janela
    /// começa em 1 — um blob que cabe numa única resposta (o caso comum) custa
    /// exatamente um round-trip, como antes — e abre ao confirmar que há mais.
    pub fn read_to_end(&mut self, conn: &mut Connection) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        if self.eof {
            return Ok(out);
        }
        let mut window = 1usize;
        let mut outstanding = 0usize;
        // Verdadeiro quando não há mais o que pedir (EOF, bloco vazio ou erro);
        // as respostas ainda em voo continuam sendo drenadas.
        let mut stop = false;
        let mut first_err: Option<Error> = None;
        loop {
            while !stop && outstanding < window {
                let mut w = op_packet(op::GET_SEGMENT);
                w.put_i32(self.handle);
                w.put_i32(SEGMENT_BUFFER);
                w.put_bytes(&[]); // campo de segmento (cstring vazia na leitura)
                conn.io().enqueue(&w);
                outstanding += 1;
            }
            conn.io().flush()?;
            if outstanding == 0 {
                break;
            }
            match read_response(conn.io()) {
                Ok(resp) => {
                    outstanding -= 1;
                    if stop {
                        continue; // resposta excedente pós-EOF/erro: descarta
                    }
                    let got = unpack_segments_into(&resp.data, &mut out);
                    if resp.handle == SEG_EOF {
                        self.eof = true;
                        stop = true;
                    } else if got == 0 {
                        // Um bloco vazio sem EOF não deveria ocorrer; evita laço infinito.
                        stop = true;
                    } else {
                        window = PIPELINE_WINDOW;
                    }
                }
                Err(e) => {
                    outstanding -= 1;
                    if conn.io().is_broken() {
                        return Err(e); // sem sincronia não há como drenar o restante
                    }
                    // `isc_segstr_eof` num pedido excedente pós-EOF é esperado.
                    let benign = stop && e.gds_code() == Some(ISC_SEGSTR_EOF);
                    stop = true;
                    if !benign {
                        first_err.get_or_insert(e);
                    }
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }

    /// Fecha o blob (`op_close_blob`), consumindo o handle.
    pub fn close(mut self, conn: &mut Connection) -> Result<()> {
        self.done = true;
        let mut w = op_packet(op::CLOSE_BLOB);
        w.put_i32(self.handle);
        conn.io().send(&w)?;
        read_response(conn.io())?;
        Ok(())
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        if !self.done {
            crate::warn_unclosed("Blob", self.handle);
        }
    }
}

// ---------------------------------------------------------------------------
// Escrita de BLOBs
// ---------------------------------------------------------------------------

/// Um BLOB aberto para escrita no servidor.
///
/// Criado por [`Connection::create_blob`]. Escreva dados com [`Self::write`] e
/// feche com [`Self::close`] para obter o id do blob. Em caso de erro, use
/// [`Self::cancel`] para liberar o handle no servidor.
#[derive(Debug)]
pub struct BlobWriter {
    handle: i32,
    /// Id atribuído pelo servidor no momento da criação; imutável.
    blob_id: u64,
    /// Verdadeiro após `close`/`cancel`; suprime o aviso de [`Drop`].
    done: bool,
}

impl BlobWriter {
    /// Id do blob no servidor. Use como [`Value::Blob`](crate::value::Value::Blob)
    /// num parâmetro de INSERT/UPDATE após fechar o blob.
    pub fn blob_id(&self) -> u64 {
        self.blob_id
    }

    /// Envia `data` para o servidor em segmentos de no máximo `MAX_SEGMENT`
    /// bytes, usando `op_put_segment`. Pode ser chamado várias vezes.
    ///
    /// Os segmentos vão em pipeline (até [`PIPELINE_WINDOW`] em voo antes de
    /// drenar as respostas), em vez de um round-trip por segmento.
    pub fn write(&self, conn: &mut Connection, data: &[u8]) -> Result<()> {
        pipeline_requests(
            conn.io(),
            data.chunks(MAX_SEGMENT),
            PIPELINE_WINDOW,
            |w, chunk| {
                // O servidor armazena o conteúdo do cstring verbatim — sem prefixo de 2 bytes.
                w.put_i32(op::PUT_SEGMENT);
                w.put_i32(self.handle);
                w.put_i32(chunk.len() as i32); // comprimento bruto do segmento
                w.put_bytes(chunk); // cstring: bytes brutos + padding XDR
            },
        )
    }

    /// Cancela o blob (`op_cancel_blob`), descartando o conteúdo já enviado.
    /// Use quando ocorrer um erro após [`Connection::create_blob`].
    pub fn cancel(mut self, conn: &mut Connection) -> Result<()> {
        self.done = true;
        let mut w = op_packet(op::CANCEL_BLOB);
        w.put_i32(self.handle);
        conn.io().send(&w)?;
        read_response(conn.io())?;
        Ok(())
    }

    /// Fecha o blob (`op_close_blob`) e devolve o seu id para usar como parâmetro
    /// de coluna BLOB em INSERT/UPDATE.
    pub fn close(mut self, conn: &mut Connection) -> Result<u64> {
        self.done = true;
        let mut w = op_packet(op::CLOSE_BLOB);
        w.put_i32(self.handle);
        conn.io().send(&w)?;
        read_response(conn.io())?;
        Ok(self.blob_id)
    }
}

impl Drop for BlobWriter {
    fn drop(&mut self) {
        if !self.done {
            crate::warn_unclosed("BlobWriter", self.handle);
        }
    }
}

impl Connection {
    /// Abre um BLOB para leitura pelo seu id (obtido de uma coluna
    /// [`Value::Blob`](crate::value::Value::Blob)).
    pub fn open_blob(&mut self, tx: &Transaction, blob_id: u64) -> Result<Blob> {
        let mut w = op_packet(op::OPEN_BLOB2);
        w.put_bytes(&[]); // BPB vazia (cstring) — usa o tipo de blob padrão
        w.put_i32(tx.handle()); // transação
        w.put_i64(blob_id as i64); // id do blob (quad de 8 bytes, big-endian)
        self.io().send(&w)?;
        let resp = read_response(self.io())?;
        Ok(Blob {
            handle: resp.handle,
            eof: false,
            done: false,
        })
    }

    /// Cria um BLOB vazio para escrita (`op_create_blob2`). Escreva dados com
    /// [`BlobWriter::write`] e finalize com [`BlobWriter::close`] para obter o
    /// id do blob. Em caso de erro, chame [`BlobWriter::cancel`].
    pub fn create_blob(&mut self, tx: &Transaction) -> Result<BlobWriter> {
        let mut w = op_packet(op::CREATE_BLOB2);
        w.put_bytes(&[]); // BPB vazia — tipo de blob padrão
        w.put_i32(tx.handle());
        w.put_i64(0); // blob_id ignorado na criação; o servidor atribui um novo
        self.io().send(&w)?;
        let resp = read_response(self.io())?;
        Ok(BlobWriter {
            handle: resp.handle,
            blob_id: resp.blob_id,
            done: false,
        })
    }

    /// Conveniência: cria um BLOB, escreve `data` integralmente e o fecha,
    /// devolvendo o id para usar como parâmetro de coluna BLOB.
    pub fn write_blob(&mut self, tx: &Transaction, data: &[u8]) -> Result<u64> {
        let writer = self.create_blob(tx)?;
        // `write` toma `&self` (não consome writer), então podemos cancelar em caso de erro.
        if let Err(e) = writer.write(self, data) {
            match writer.cancel(self) {
                Ok(()) | Err(_) => {}
            }
            return Err(e);
        }
        writer.close(self)
    }

    /// Conveniência: abre o BLOB, lê todo o conteúdo e o fecha, devolvendo os
    /// bytes. Fecha mesmo se a leitura falhar.
    pub fn read_blob(&mut self, tx: &Transaction, blob_id: u64) -> Result<Vec<u8>> {
        let mut blob = self.open_blob(tx, blob_id)?;
        let result = blob.read_to_end(self);
        let close = blob.close(self);
        match (result, close) {
            (Ok(data), Ok(())) => Ok(data),
            (Err(e), _) => Err(e),
            (Ok(_), Err(e)) => Err(e),
        }
    }
}

/// Desempacota o buffer de resposta do `op_get_segment`: uma sequência de
/// segmentos, cada um precedido por seu comprimento (2 bytes, little-endian).
fn unpack_segments(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    unpack_segments_into(data, &mut out);
    out
}

/// Como [`unpack_segments`], mas anexa direto em `out` — evita um `Vec`
/// intermediário por bloco em [`Blob::read_to_end`]. Retorna quantos bytes
/// foram anexados.
fn unpack_segments_into(data: &[u8], out: &mut Vec<u8>) -> usize {
    let before = out.len();
    let mut i = 0;
    while i + 2 <= data.len() {
        let len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
        i += 2;
        let end = (i + len).min(data.len());
        out.extend_from_slice(&data[i..end]);
        i = end;
    }
    out.len() - before
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpacks_packed_segments() {
        // Dois segmentos: "Hi" (len 2) e "there" (len 5).
        let buf = [2, 0, b'H', b'i', 5, 0, b't', b'h', b'e', b'r', b'e'];
        assert_eq!(unpack_segments(&buf), b"Hithere");
    }

    #[test]
    fn unpacks_empty_buffer() {
        assert!(unpack_segments(&[]).is_empty());
    }

    #[test]
    fn unpack_into_appends_and_counts() {
        let mut out = b"pre".to_vec();
        let buf = [2, 0, b'H', b'i', 5, 0, b't', b'h', b'e', b'r', b'e'];
        assert_eq!(unpack_segments_into(&buf, &mut out), 7);
        assert_eq!(out, b"preHithere");
        assert_eq!(unpack_segments_into(&[], &mut out), 0);
        assert_eq!(out, b"preHithere");
    }
}
