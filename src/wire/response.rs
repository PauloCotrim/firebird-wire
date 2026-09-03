//! Leitura genérica de resposta: `op_response` mais o vetor de status final.

use crate::charset::Charset;
use crate::error::{DatabaseError, Error, Result, StatusArg, StatusVector};
use crate::wire::consts::{arg, op};
use crate::wire::stream::{FbStream, op_name};
use crate::wire::xdr::XdrWriter;

/// Um pacote `op_response` analisado (`P_RESP`).
#[derive(Debug, Clone)]
pub struct Response {
    /// Id do objeto / handle retornado pela operação (`p_resp_object`).
    pub handle: i32,
    /// Id do blob (`p_resp_blob_id`), significativo apenas para operações de blob.
    pub blob_id: u64,
    /// Carga de dados variável (`p_resp_data`).
    pub data: Vec<u8>,
    /// O vetor de status; pode carregar avisos mesmo em caso de sucesso.
    pub status: StatusVector,
}

impl Response {
    /// Transforma um vetor de status que carrega erro em [`Error::Database`]; caso contrário
    /// produz a resposta (os avisos são mantidos em `status`).
    pub fn into_result(self) -> Result<Response> {
        if self.status.is_error() {
            return Err(Error::Database(DatabaseError::new(self.status)));
        }
        Ok(self)
    }
}

/// Lê o próximo op code, pulando de forma transparente os pacotes keep-alive `op_dummy`
/// e `op_void`.
pub fn read_op(stream: &mut FbStream) -> Result<i32> {
    loop {
        let code = stream.read_i32()?;
        if code == op::DUMMY || code == op::VOID {
            continue;
        }
        return Ok(code);
    }
}

/// Decodifica uma string do vetor de status.
///
/// O servidor manda esse texto no charset da conexão — é dele que sai a
/// mensagem de uma exceção do usuário, com os acentos do idioma do banco.
/// Decodificar tudo como UTF-8 transformava "Ação não encontrada" em
/// "A��o n�o encontrada", e o dano é irreversível: os bytes originais somem
/// no `U+FFFD`.
///
/// Numa conexão UTF-8 o texto ainda pode vir noutro charset (o da mensagem
/// gravada no banco, o do sistema do servidor). Quando os bytes não formam
/// UTF-8 válido, decodificamos como Windows-1252, que aceita qualquer byte e
/// acerta o Latin-1 que esses casos costumam ser — melhor do que devolver
/// caractere de substituição.
fn decode_text(charset: Charset, raw: Vec<u8>) -> String {
    match charset {
        Charset::Utf8 | Charset::Unknown => match String::from_utf8(raw) {
            Ok(s) => s,
            Err(e) => Charset::Win1252.decode(e.as_bytes()),
        },
        outro => outro.decode_owned(raw),
    }
}

/// Lê um vetor de status campo a campo do fluxo (stream).
pub fn read_status_vector(stream: &mut FbStream) -> Result<StatusVector> {
    let charset = stream.charset();
    let mut args = Vec::new();
    let mut sql_state = None;

    loop {
        let tag = stream.read_i32()?;
        match tag {
            t if t == arg::END => break,
            t if t == arg::GDS => args.push(StatusArg::Gds(stream.read_i32()?)),
            t if t == arg::WARNING => args.push(StatusArg::Warning(stream.read_i32()?)),
            t if t == arg::NUMBER => args.push(StatusArg::Number(stream.read_i32()?)),
            t if t == arg::STRING || t == arg::CSTRING => {
                let s = decode_text(charset, stream.read_bytes()?);
                args.push(StatusArg::Str(s));
            }
            t if t == arg::INTERPRETED => {
                let s = decode_text(charset, stream.read_bytes()?);
                args.push(StatusArg::Interpreted(s));
            }
            // O SQLSTATE são cinco caracteres ASCII (`42S02` e afins).
            t if t == arg::SQL_STATE => {
                sql_state = Some(String::from_utf8_lossy(&stream.read_bytes()?).into_owned());
            }
            other => {
                let _ = stream.read_i32()?;
                args.push(StatusArg::Number(other));
            }
        }
    }

    Ok(StatusVector { args, sql_state })
}

/// Lê o corpo `P_RESP` que segue um op code `op_response` já consumido.
pub fn read_response_body(stream: &mut FbStream) -> Result<Response> {
    let handle = stream.read_i32()?;
    let blob_id = stream.read_quad()?;
    let data = stream.read_bytes()?;
    let status = read_status_vector(stream)?;
    Ok(Response {
        handle,
        blob_id,
        data,
        status,
    })
}

/// Lê o próximo pacote, exigindo que seja um `op_response`, e converte qualquer
/// status de erro em [`Error::Database`].
pub fn read_response(stream: &mut FbStream) -> Result<Response> {
    let code = read_op(stream)?;
    if code != op::RESPONSE {
        // Recebemos um pacote que não esperávamos: o stream está fora de sincronia
        // e não pode ser reutilizado com segurança.
        stream.mark_broken();
        return Err(Error::protocol(format!(
            "expected op_response, got {} ({code})",
            op_name(code)
        )));
    }
    read_response_body(stream)?.into_result()
}

/// Envia uma sequência de operações em pipeline: mantém até `window` pacotes em
/// voo antes de drenar as respostas, em vez de esperar um round-trip por pacote.
/// Cada item de `items` vira um pacote via `build` (o writer chega vazio).
///
/// A janela limita quanto acumula nos buffers TCP dos dois lados (as respostas
/// só são drenadas aqui): sem ela, o servidor poderia bloquear escrevendo
/// respostas que ninguém lê e parar de ler nossos pedidos — deadlock.
///
/// Se uma resposta trouxer erro de banco, o stream continua em sincronia; os
/// pedidos restantes deixam de ser enviados, as respostas já em voo são
/// drenadas e o primeiro erro é retornado. Erros de I/O/desync abortam
/// imediatamente (o stream já está marcado como quebrado).
pub fn pipeline_requests<T>(
    stream: &mut FbStream,
    mut items: impl Iterator<Item = T>,
    window: usize,
    mut build: impl FnMut(&mut XdrWriter, T),
) -> Result<()> {
    debug_assert!(window > 0);
    let mut w = XdrWriter::new();
    let mut outstanding = 0usize;
    let mut first_err: Option<Error> = None;
    loop {
        // Reabastece a janela enquanto houver itens e nenhum erro registrado.
        while first_err.is_none() && outstanding < window {
            let Some(item) = items.next() else { break };
            w.clear();
            build(&mut w, item);
            stream.enqueue(&w);
            outstanding += 1;
        }
        stream.flush()?;
        if outstanding == 0 {
            break;
        }
        match read_response(stream) {
            Ok(_) => outstanding -= 1,
            Err(e) => {
                outstanding -= 1;
                if stream.is_broken() {
                    // Sem sincronia não há como drenar o restante.
                    return Err(e);
                }
                first_err.get_or_insert(e);
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "Ação do Projeto" em Windows-1252 — os bytes que o servidor manda numa
    /// conexão WIN1252, que é como os bancos deste driver costumam rodar.
    const ACAO_WIN1252: &[u8] = b"A\xe7\xe3o do Projeto";

    #[test]
    fn texto_do_status_sai_no_charset_da_conexao() {
        assert_eq!(
            decode_text(Charset::Win1252, ACAO_WIN1252.to_vec()),
            "Ação do Projeto"
        );
        assert_eq!(
            decode_text(Charset::Latin1, ACAO_WIN1252.to_vec()),
            "Ação do Projeto"
        );
    }

    /// Numa conexão UTF-8 o texto ainda pode vir noutro charset (a mensagem
    /// gravada no banco, o idioma do sistema do servidor). Antes isso virava
    /// `U+FFFD` e a mensagem chegava ilegível ao usuário.
    #[test]
    fn bytes_que_nao_sao_utf8_caem_para_win1252_em_vez_de_perder_o_acento() {
        let s = decode_text(Charset::Utf8, ACAO_WIN1252.to_vec());
        assert_eq!(s, "Ação do Projeto");
        assert!(!s.contains('\u{FFFD}'));
    }

    #[test]
    fn utf8_valido_atravessa_intacto() {
        assert_eq!(
            decode_text(Charset::Utf8, "Ação do Projeto".as_bytes().to_vec()),
            "Ação do Projeto"
        );
    }
}
