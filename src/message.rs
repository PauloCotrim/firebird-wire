//! Decodificação de mensagens de linha.
//!
//! Formato da transmissão (payload do op_fetch_response): um bitmap de nulos
//! little-endian inicial de `align4(ceil(ncols/8))` bytes (bit *i* ligado ⇒
//! coluna *i* é NULL), seguido do valor codificado em XDR de cada coluna
//! NÃO-NULL, em ordem. Colunas nulas não contribuem com bytes, então as
//! mensagens têm comprimento variável e devem ser decodificadas campo a campo
//! direto do stream.

use crate::charset::Charset;
use crate::error::{Error, Result};
use crate::value::{align4, ColumnMeta, Value};
use crate::wire::consts::sql_type;
use crate::wire::stream::FbStream;

/// Número de bytes no bitmap de nulos inicial para `ncols` colunas.
pub fn null_bitmap_len(ncols: usize) -> usize {
    align4(ncols.div_ceil(8))
}

/// Comprimento do buffer de mensagem *do lado do cliente* (não compactado) que o
/// servidor espera em `op_batch_create` (`p_batch_msglen`). É o layout que o BLR
/// descreve: cada campo é alinhado à sua fronteira natural, seguido de um
/// indicador de nulo `SQL_SHORT` (2 bytes, alinhamento 2). Sem arredondamento
/// final — confirmado por captura (INTEGER + VARCHAR(20) → 30 bytes).
pub fn message_buffer_len(columns: &[ColumnMeta]) -> u32 {
    let mut off: usize = 0;
    for col in columns {
        let (len, alignment) = type_size_align(col);
        off = align_up(off, alignment);
        off += len;
        // indicador de nulo: SQL_SHORT, 2 bytes, alinhamento 2.
        off = align_up(off, 2);
        off += 2;
    }
    off as u32
}

#[inline]
fn align_up(n: usize, alignment: usize) -> usize {
    (n + alignment - 1) & !(alignment - 1)
}

/// `(comprimento dos dados, alinhamento)` de um campo no buffer de mensagem.
fn type_size_align(col: &ColumnMeta) -> (usize, usize) {
    let n = col.length as usize;
    match sql_type::base(col.sql_type) {
        sql_type::TEXT => (n, 1),
        sql_type::VARYING => (n + 2, 2),
        sql_type::SHORT => (2, 2),
        sql_type::LONG => (4, 4),
        sql_type::FLOAT => (4, 4),
        sql_type::TYPE_DATE | sql_type::TYPE_TIME => (4, 4),
        sql_type::INT64 => (8, 8),
        sql_type::DOUBLE | sql_type::D_FLOAT => (8, 8),
        sql_type::TIMESTAMP => (8, 4),
        sql_type::BLOB | sql_type::QUAD => (8, 4),
        sql_type::INT128 => (16, 8),
        sql_type::BOOLEAN => (1, 1),
        sql_type::DEC16 => (8, 8),
        sql_type::DEC34 => (16, 8),
        _ => (8, 8),
    }
}

/// Codifica uma linha (mensagem de parâmetros de entrada) no formato de
/// transmissão que o servidor espera: um bitmap de nulos little-endian inicial
/// seguido do valor XDR de cada coluna NÃO-NULL, em ordem. O inverso de
/// [`decode_row`].
pub fn encode_row(columns: &[ColumnMeta], values: &[Value], charset: Charset) -> Result<Vec<u8>> {
    if values.len() != columns.len() {
        return Err(Error::protocol(format!(
            "parameter count mismatch: statement expects {}, got {}",
            columns.len(),
            values.len()
        )));
    }
    let mut out = vec![0u8; null_bitmap_len(columns.len())];
    for (i, (col, val)) in columns.iter().zip(values).enumerate() {
        if val.is_null() {
            out[i / 8] |= 1 << (i % 8);
        } else {
            encode_value(&mut out, col, val, charset)?;
        }
    }
    Ok(out)
}

fn put_i32_be(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_pad(out: &mut Vec<u8>, data_len: usize) {
    for _ in 0..(align4(data_len) - data_len) {
        out.push(0);
    }
}

fn encode_value(out: &mut Vec<u8>, col: &ColumnMeta, val: &Value, charset: Charset) -> Result<()> {
    let mismatch = || Error::protocol(format!("value does not fit column type {}", col.sql_type));
    match sql_type::base(col.sql_type) {
        sql_type::SHORT => put_i32_be(out, i32::from(val.as_i64().ok_or_else(mismatch)? as i16)),
        sql_type::LONG => put_i32_be(out, val.as_i64().ok_or_else(mismatch)? as i32),
        sql_type::INT64 => out.extend_from_slice(&val.as_i64().ok_or_else(mismatch)?.to_be_bytes()),
        sql_type::INT128 => match val {
            Value::Int128(v) => out.extend_from_slice(&v.to_be_bytes()),
            _ => out.extend_from_slice(&i128::from(val.as_i64().ok_or_else(mismatch)?).to_be_bytes()),
        },
        sql_type::FLOAT => match val {
            Value::Float(f) => out.extend_from_slice(&f.to_bits().to_be_bytes()),
            Value::Double(f) => out.extend_from_slice(&(*f as f32).to_bits().to_be_bytes()),
            _ => return Err(mismatch()),
        },
        sql_type::DOUBLE | sql_type::D_FLOAT => match val {
            Value::Double(f) => out.extend_from_slice(&f.to_bits().to_be_bytes()),
            Value::Float(f) => out.extend_from_slice(&(f64::from(*f)).to_bits().to_be_bytes()),
            _ => return Err(mismatch()),
        },
        sql_type::VARYING => {
            let bytes = text_bytes(val, charset)?;
            put_i32_be(out, bytes.len() as i32);
            out.extend_from_slice(&bytes);
            put_pad(out, bytes.len());
        }
        sql_type::TEXT => {
            let bytes = text_bytes(val, charset)?;
            let n = col.length as usize;
            out.extend_from_slice(&bytes);
            // Preenche CHAR(n) à direita com espaços até sua largura declarada.
            for _ in bytes.len()..n {
                out.push(b' ');
            }
            put_pad(out, n.max(bytes.len()));
        }
        sql_type::TYPE_DATE => put_i32_be(out, expect_date(val)?),
        sql_type::TYPE_TIME => put_i32_be(out, expect_time(val)? as i32),
        sql_type::TIMESTAMP => match val {
            Value::Timestamp(d, t) => {
                put_i32_be(out, *d);
                put_i32_be(out, *t as i32);
            }
            _ => return Err(mismatch()),
        },
        sql_type::BOOLEAN => {
            out.push(matches!(val, Value::Bool(true)) as u8);
            put_pad(out, 1);
        }
        sql_type::BLOB | sql_type::QUAD => match val {
            Value::Blob(id) => out.extend_from_slice(&id.to_be_bytes()),
            _ => return Err(mismatch()),
        },
        _ => return Err(Error::protocol(format!("unsupported parameter type {}", col.sql_type))),
    }
    Ok(())
}

fn text_bytes(val: &Value, charset: Charset) -> Result<std::borrow::Cow<'_, [u8]>> {
    use std::borrow::Cow;
    match val {
        // Texto é transcodificado para o charset da conexão; bytes/OCTETS vão crus.
        Value::Text(s) => Ok(Cow::Owned(charset.encode(s))),
        Value::Bytes(b) => Ok(Cow::Borrowed(b)),
        _ => Err(Error::protocol("expected a text/bytes value")),
    }
}

fn expect_date(val: &Value) -> Result<i32> {
    match val {
        Value::Date(d) => Ok(*d),
        Value::Timestamp(d, _) => Ok(*d),
        _ => Err(Error::protocol("expected a DATE value")),
    }
}

fn expect_time(val: &Value) -> Result<u32> {
    match val {
        Value::Time(t) => Ok(*t),
        Value::Timestamp(_, t) => Ok(*t),
        _ => Err(Error::protocol("expected a TIME value")),
    }
}

/// Decodifica uma linha do stream a partir dos metadados das colunas de saída.
/// `charset` é o charset da conexão, usado para decodificar CHAR/VARCHAR.
pub async fn decode_row(
    stream: &mut FbStream,
    columns: &[ColumnMeta],
    charset: Charset,
) -> Result<Vec<Value>> {
    let bitmap = stream.read_raw(null_bitmap_len(columns.len())).await?;
    let mut values = Vec::with_capacity(columns.len());
    for (i, col) in columns.iter().enumerate() {
        let is_null = bitmap[i / 8] & (1 << (i % 8)) != 0;
        if is_null {
            values.push(Value::Null);
        } else {
            values.push(decode_value(stream, col, charset).await?);
        }
    }
    Ok(values)
}

async fn decode_value(stream: &mut FbStream, col: &ColumnMeta, charset: Charset) -> Result<Value> {
    Ok(match sql_type::base(col.sql_type) {
        sql_type::SHORT => Value::Short(stream.read_i32().await? as i16),
        sql_type::LONG => Value::Int(stream.read_i32().await?),
        sql_type::INT64 => Value::BigInt(stream.read_i64().await?),
        sql_type::INT128 => {
            let b = stream.read_raw(16).await?;
            Value::Int128(i128::from_be_bytes(b.try_into().unwrap()))
        }
        sql_type::FLOAT => Value::Float(f32::from_bits(stream.read_i32().await? as u32)),
        sql_type::DOUBLE | sql_type::D_FLOAT => Value::Double(stream.read_f64().await?),
        sql_type::TEXT => {
            let n = col.length as usize;
            let raw = stream.read_raw(n).await?;
            stream.read_pad(n).await?;
            text_or_bytes(col, raw, charset)
        }
        sql_type::VARYING => {
            let raw = stream.read_bytes().await?; // prefixado por comprimento + com padding
            text_or_bytes(col, raw, charset)
        }
        sql_type::TYPE_DATE => Value::Date(stream.read_i32().await?),
        sql_type::TYPE_TIME => Value::Time(stream.read_i32().await? as u32),
        sql_type::TIMESTAMP => {
            let date = stream.read_i32().await?;
            let time = stream.read_i32().await? as u32;
            Value::Timestamp(date, time)
        }
        sql_type::BLOB | sql_type::QUAD => Value::Blob(stream.read_quad().await?),
        sql_type::BOOLEAN => {
            let b = stream.read_raw(1).await?;
            stream.read_pad(1).await?;
            Value::Bool(b[0] != 0)
        }
        _ => {
            // Tipo desconhecido: consome sua largura declarada como bytes opacos.
            let n = col.xdr_len();
            Value::Bytes(stream.read_raw(n).await?)
        }
    })
}

/// Charset OCTETS (sub_type 1 para texto) permanece binário; todo o resto é
/// decodificado conforme o charset da conexão (o servidor translitera o texto
/// para esse charset antes de enviar).
fn text_or_bytes(col: &ColumnMeta, raw: Vec<u8>, charset: Charset) -> Value {
    const CS_OCTETS: i32 = 1;
    if col.sub_type == CS_OCTETS {
        Value::Bytes(raw)
    } else {
        let s = charset.decode(&raw);
        // Remove o preenchimento (padding) à direita do CHAR; VARCHAR já carrega
        // seus bytes exatos.
        if sql_type::base(col.sql_type) == sql_type::TEXT {
            Value::Text(s.trim_end_matches(' ').to_string())
        } else {
            Value::Text(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(sql_type: i32, length: i32) -> ColumnMeta {
        ColumnMeta { sql_type, length, ..Default::default() }
    }

    #[test]
    fn buffer_len_integer_and_varchar() {
        // INTEGER + VARCHAR(20): confirmado por captura do cliente C (IBatch) = 30.
        // int(4)@0 + null(2)@4 → 6; varchar(22)@6 + null(2)@28 → 30.
        let cols = [col(sql_type::LONG, 4), col(sql_type::VARYING, 20)];
        assert_eq!(message_buffer_len(&cols), 30);
    }

    #[test]
    fn buffer_len_respects_alignment() {
        // SMALLINT(2)@0 + null(2)@2 → 4; BIGINT alinha a 8 → 8, +8 → 16,
        // null(2)@16 → 18.
        let cols = [col(sql_type::SHORT, 2), col(sql_type::INT64, 8)];
        assert_eq!(message_buffer_len(&cols), 18);
    }

    #[test]
    fn encode_row_is_4_aligned() {
        // Cada mensagem codificada deve terminar em fronteira de 4 bytes para que
        // a concatenação no op_batch_msg permaneça alinhada.
        let cols = [col(sql_type::LONG, 4), col(sql_type::VARYING, 20)];
        let msg =
            encode_row(&cols, &[Value::Int(1), Value::Text("um".into())], Charset::Utf8).unwrap();
        assert_eq!(msg.len() % 4, 0);
        assert_eq!(msg.len(), 16); // bitmap(4) + int(4) + len(4)+"um"+pad(2)=8
    }
}
