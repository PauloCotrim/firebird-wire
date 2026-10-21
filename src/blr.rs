//! Geração de BLR (Binary Language Representation) para descrições de mensagens.
//!
//! A mensagem de entrada/saída de uma instrução é descrita ao servidor por um
//! pequeno programa BLR. Para cada coluna emitimos seu descritor de tipo seguido
//! de um indicador de nulo `blr_short` (o servidor empacota os nulos reais em um
//! bitmap inicial na transmissão, mas o formato declarado ainda carrega os
//! indicadores).

use crate::value::ColumnMeta;
use crate::wire::consts::{blr, sql_type};

/// Constrói o BLR que descreve uma mensagem de SAÍDA (colunas selecionadas).
/// Para os tipos WITH TIME ZONE, pede o formato ESTENDIDO (`_EX`) para que o
/// servidor já inclua o offset resolvido (com horário de verão) — assim o driver
/// consegue a hora local mesmo sem uma base de dados de zonas.
pub fn message_blr(columns: &[ColumnMeta]) -> Vec<u8> {
    message_blr_impl(columns, true)
}

/// Igual a [`message_blr`], mas para a mensagem de ENTRADA (parâmetros). Usa o
/// formato base (não-`_EX`) das zonas: na entrada o offset é informativo e o
/// servidor o recalcula a partir da zona.
pub fn input_blr(columns: &[ColumnMeta]) -> Vec<u8> {
    message_blr_impl(columns, false)
}

fn message_blr_impl(columns: &[ColumnMeta], for_output: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(16 + columns.len() * 6);
    b.push(blr::VERSION5);
    b.push(blr::BEGIN);
    b.push(blr::MESSAGE);
    b.push(0); // message number
    let field_count = (columns.len() * 2) as u16; // dados + indicador de nulo cada
    b.extend_from_slice(&field_count.to_le_bytes());

    for col in columns {
        push_type(&mut b, col, for_output);
        // indicador de nulo
        b.push(blr::SHORT);
        b.push(0);
    }

    b.push(blr::END);
    b.push(blr::EOC);
    b
}

fn push_type(b: &mut Vec<u8>, col: &ColumnMeta, for_output: bool) {
    let scale = col.scale as i8 as u8;
    match sql_type::base(col.sql_type) {
        // Como o `BlrFromMessage` do fbclient: blr_text2/blr_varying2 com o
        // charset da coluna (byte baixo do sub_type; o alto é a collation).
        // Sem ele o servidor assume o charset da conexão e converte também
        // colunas OCTETS, o que estraga bytes que não formam texto válido.
        sql_type::TEXT => {
            b.push(blr::TEXT2);
            b.extend_from_slice(&((col.sub_type & 0xff) as u16).to_le_bytes());
            b.extend_from_slice(&(col.length as u16).to_le_bytes());
        }
        sql_type::VARYING => {
            b.push(blr::VARYING2);
            b.extend_from_slice(&((col.sub_type & 0xff) as u16).to_le_bytes());
            b.extend_from_slice(&(col.length as u16).to_le_bytes());
        }
        sql_type::SHORT => {
            b.push(blr::SHORT);
            b.push(scale);
        }
        sql_type::LONG => {
            b.push(blr::LONG);
            b.push(scale);
        }
        sql_type::INT64 => {
            b.push(blr::INT64);
            b.push(scale);
        }
        sql_type::INT128 => {
            b.push(blr::INT128);
            b.push(scale);
        }
        sql_type::QUAD => {
            b.push(blr::QUAD);
            b.push(scale);
        }
        sql_type::FLOAT => b.push(blr::FLOAT),
        sql_type::DOUBLE | sql_type::D_FLOAT => b.push(blr::DOUBLE),
        sql_type::TYPE_DATE => b.push(blr::SQL_DATE),
        sql_type::TYPE_TIME => b.push(blr::SQL_TIME),
        sql_type::TIMESTAMP => b.push(blr::TIMESTAMP),
        sql_type::BLOB => {
            // blr_blob2: o servidor reconhece o campo como BLOB pela metadata
            // (necessário para o batch habilitar o stream de blobs). Segue o
            // sub_type (2 LE) e o charset (2 LE). Como o fbclient
            // (`BlrFromMessage`), o charset é o da própria coluna, que o DSQL
            // informa no campo de escala dos BLOBs de texto. Declarado como 0
            // (NONE), o servidor converte cada BLOB de texto na atribuição, e
            // num Batch reaproveitado isso acaba em "invalid BLOB ID".
            let charset = if col.sub_type == 1 { col.scale.max(0) as u16 } else { 0 };
            b.push(blr::BLOB2);
            b.extend_from_slice(&(col.sub_type as u16).to_le_bytes());
            b.extend_from_slice(&charset.to_le_bytes());
        }
        sql_type::BOOLEAN => b.push(blr::BOOL),
        // `? IS NULL`: o DSQL descreve o parâmetro como SQL_NULL. O fbclient o
        // declara como blr_text do comprimento informado (BlrFromMessage.cpp).
        sql_type::NULL => {
            b.push(blr::TEXT);
            b.extend_from_slice(&(col.length as u16).to_le_bytes());
        }
        sql_type::DEC16 => b.push(blr::DEC64),
        sql_type::DEC34 => b.push(blr::DEC128),
        sql_type::TIME_TZ | sql_type::TIME_TZ_EX => {
            b.push(if for_output {
                blr::EX_TIME_TZ
            } else {
                blr::SQL_TIME_TZ
            });
        }
        sql_type::TIMESTAMP_TZ | sql_type::TIMESTAMP_TZ_EX => {
            b.push(if for_output {
                blr::EX_TIMESTAMP_TZ
            } else {
                blr::TIMESTAMP_TZ
            });
        }
        other => {
            // Recorre a um quad para que a mensagem continue parseável; o
            // decodificador de valor o tratará como bytes brutos.
            let _ = other;
            b.push(blr::QUAD);
            b.push(0);
        }
    }
}

/// O buffer de info-items enviado com `op_prepare_statement` para descrever
/// tanto os parâmetros de entrada (`bind`) quanto as colunas de saída (`select`).
/// Espelha o que fbclient/isql solicitam.
pub fn prepare_info_items() -> &'static [u8] {
    use crate::wire::consts::isql::*;
    &[
        STMT_TYPE,
        // parâmetros de entrada
        BIND,
        DESCRIBE_VARS,
        SQLDA_SEQ,
        TYPE,
        SUB_TYPE,
        SCALE,
        LENGTH,
        FIELD,
        RELATION,
        ALIAS,
        OWNER,
        DESCRIBE_END,
        // colunas de saída
        SELECT,
        DESCRIBE_VARS,
        SQLDA_SEQ,
        TYPE,
        SUB_TYPE,
        SCALE,
        LENGTH,
        FIELD,
        RELATION,
        ALIAS,
        OWNER,
        DESCRIBE_END,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blr_for_smallint_and_varchar() {
        let cols = vec![
            ColumnMeta {
                sql_type: sql_type::SHORT,
                scale: 0,
                ..Default::default()
            },
            ColumnMeta {
                sql_type: sql_type::VARYING,
                length: 15,
                ..Default::default()
            },
        ];
        let blr_bytes = message_blr(&cols);
        // version5, begin, message, msg#0, count=4(LE), short/0, short/0(null),
        // varying2/charset 0/15(LE), short/0(null), end, eoc — igual à
        // captura do isql (PROTOCOL-NOTES.md, op_fetch)
        assert_eq!(
            blr_bytes,
            vec![5, 2, 4, 0, 4, 0, 7, 0, 7, 0, 38, 0, 0, 15, 0, 7, 0, 255, 76]
        );
    }
}
