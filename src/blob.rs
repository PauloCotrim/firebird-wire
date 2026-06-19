//! Leitura de BLOBs.
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
//! [`Value::Blob`]: crate::value::Value::Blob

use crate::connection::Connection;
use crate::error::Result;
use crate::transaction::Transaction;
use crate::wire::consts::op;
use crate::wire::response::read_response;
use crate::wire::stream::op_packet;

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
    pub async fn read_segment(&mut self, conn: &mut Connection) -> Result<Vec<u8>> {
        if self.eof {
            return Ok(Vec::new());
        }
        let mut w = op_packet(op::GET_SEGMENT);
        w.put_i32(self.handle);
        w.put_i32(SEGMENT_BUFFER); // comprimento máximo do buffer
        w.put_bytes(&[]); // campo de segmento (cstring vazia na leitura)
        conn.io().send(&w).await?;

        let resp = read_response(conn.io()).await?;
        // p_resp_object carrega o status; p_resp_data, os segmentos empacotados.
        if resp.handle == SEG_EOF {
            self.eof = true;
        }
        Ok(unpack_segments(&resp.data))
    }

    /// Lê o blob inteiro até o fim, concatenando todos os segmentos.
    pub async fn read_to_end(&mut self, conn: &mut Connection) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let chunk = self.read_segment(conn).await?;
            out.extend_from_slice(&chunk);
            if self.eof {
                break;
            }
            // Um bloco vazio sem EOF não deveria ocorrer; evita laço infinito.
            if chunk.is_empty() {
                break;
            }
        }
        Ok(out)
    }

    /// Fecha o blob (`op_close_blob`), consumindo o handle.
    pub async fn close(self, conn: &mut Connection) -> Result<()> {
        let mut w = op_packet(op::CLOSE_BLOB);
        w.put_i32(self.handle);
        conn.io().send(&w).await?;
        read_response(conn.io()).await?;
        Ok(())
    }
}

impl Connection {
    /// Abre um BLOB para leitura pelo seu id (obtido de uma coluna
    /// [`Value::Blob`](crate::value::Value::Blob)).
    pub async fn open_blob(&mut self, tx: &Transaction, blob_id: u64) -> Result<Blob> {
        let mut w = op_packet(op::OPEN_BLOB2);
        w.put_bytes(&[]); // BPB vazia (cstring) — usa o tipo de blob padrão
        w.put_i32(tx.handle()); // transação
        w.put_i64(blob_id as i64); // id do blob (quad de 8 bytes, big-endian)
        self.io().send(&w).await?;
        let resp = read_response(self.io()).await?;
        Ok(Blob { handle: resp.handle, eof: false })
    }

    /// Conveniência: abre o BLOB, lê todo o conteúdo e o fecha, devolvendo os
    /// bytes. Fecha mesmo se a leitura falhar.
    pub async fn read_blob(&mut self, tx: &Transaction, blob_id: u64) -> Result<Vec<u8>> {
        let mut blob = self.open_blob(tx, blob_id).await?;
        let result = blob.read_to_end(self).await;
        let close = blob.close(self).await;
        let data = result?;
        close?;
        Ok(data)
    }
}

/// Desempacota o buffer de resposta do `op_get_segment`: uma sequência de
/// segmentos, cada um precedido por seu comprimento (2 bytes, little-endian).
fn unpack_segments(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= data.len() {
        let len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
        i += 2;
        let end = (i + len).min(data.len());
        out.extend_from_slice(&data[i..end]);
        i = end;
    }
    out
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
}
