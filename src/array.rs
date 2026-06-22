//! Colunas ARRAY do SQL (`op_get_slice` / `op_put_slice` / `op_slice`).
//!
//! Um ARRAY do Firebird é armazenado como um blob especial: numa linha a coluna
//! chega como um id de 8 bytes ([`Value::Array`]), igual a um blob. Para ler ou
//! escrever os elementos é preciso descrever a fatia com a **SDL** (Slice
//! Description Language) — um pequeno bytecode que diz o tipo do elemento, a
//! relação/campo e os limites de cada dimensão.
//!
//! ## Fluxo
//!
//! 1. [`Connection::array_desc`] consulta `RDB$RELATION_FIELDS`/`RDB$FIELDS`/
//!    `RDB$FIELD_DIMENSIONS` e monta um [`ArrayDesc`] (tipo BLR do elemento,
//!    tamanho, escala, dimensões).
//! 2. [`Connection::read_array`] envia `op_get_slice` (id + SDL) e decodifica a
//!    resposta `op_slice` num `Vec<Value>` (um por elemento, em ordem).
//! 3. [`Connection::write_array`] envia `op_put_slice` (SDL + dados) e devolve o
//!    id do novo array, que então vai como [`Value::Array`] num INSERT/UPDATE.
//!
//! ## Codificação na transmissão (wire)
//!
//! A `op_slice` traz `p_slr_length` (tamanho da fatia na representação do
//! cliente = nº de elementos × *stride*) seguido do comprimento XDR e dos dados.
//! Cada elemento é serializado por `xdr_datum`: tipos de largura fixa vão como
//! inteiros XDR (4 ou 8 bytes); `VARYING` vai como `comprimento(4 B) + bytes +
//! padding até 4`; `TEXT` como `bytes + padding até 4`. O nº de elementos é
//! `p_slr_length / stride` — derivamos o stride do [`ArrayDesc`], pois o
//! comprimento XDR reportado é o tamanho lógico, não a contagem de bytes na rede.

use crate::charset::Charset;
use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::transaction::Transaction;
use crate::value::Value;
use crate::wire::consts::{blr, op, sdl};
use crate::wire::response::{read_op, read_response, read_response_body};
use crate::wire::stream::{op_name, op_packet, FbStream};

/// Os limites (inferior, superior) de uma dimensão de array, ambos inclusivos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dimension {
    pub lower: i32,
    pub upper: i32,
}

impl Dimension {
    /// Quantos elementos esta dimensão contém.
    pub fn len(&self) -> usize {
        (self.upper - self.lower + 1).max(0) as usize
    }

    /// Verdadeiro se a dimensão é vazia (superior < inferior).
    pub fn is_empty(&self) -> bool {
        self.upper < self.lower
    }
}

/// Descreve uma coluna ARRAY: o tipo do elemento e as dimensões. Obtido por
/// [`Connection::array_desc`]; consumido por [`Connection::read_array`] /
/// [`Connection::write_array`] para montar a SDL.
#[derive(Debug, Clone)]
pub struct ArrayDesc {
    /// Nome da relação (tabela), como armazenado (normalmente em maiúsculas).
    pub relation: String,
    /// Nome do campo (coluna), como armazenado.
    pub field: String,
    /// Tipo BLR do elemento (= `RDB$FIELD_TYPE`; ex.: 37 = VARYING, 8 = LONG).
    pub blr_type: u8,
    /// Sub-tipo (charset para texto: 1 = OCTETS; sub-tipo de blob, etc.).
    pub sub_type: i32,
    /// Escala (para NUMERIC/DECIMAL e inteiros escalados).
    pub scale: i32,
    /// Comprimento do elemento em bytes (largura declarada do tipo).
    pub length: u16,
    /// Limites de cada dimensão, da mais externa para a mais interna.
    pub dimensions: Vec<Dimension>,
}

impl ArrayDesc {
    /// Número total de elementos (produto dos tamanhos de todas as dimensões).
    pub fn element_count(&self) -> usize {
        self.dimensions.iter().map(Dimension::len).product()
    }

    /// O *stride* de um elemento na representação do cliente (o `dsc_length` que o
    /// servidor usa para dividir `p_slr_length` e obter a contagem de elementos).
    fn element_stride(&self) -> usize {
        match self.blr_type {
            blr::VARYING => self.length as usize + 2,
            blr::TEXT => self.length as usize,
            blr::SHORT => 2,
            blr::LONG | blr::FLOAT | blr::SQL_DATE | blr::SQL_TIME => 4,
            blr::INT64 | blr::DOUBLE | blr::D_FLOAT | blr::TIMESTAMP | blr::QUAD | blr::DEC64 => 8,
            blr::INT128 | blr::DEC128 => 16,
            blr::BOOL => 1,
            // Tipos não previstos: usa o comprimento declarado.
            _ => self.length.max(1) as usize,
        }
    }

    /// Tamanho total da fatia na representação do cliente (`p_slc_length`).
    fn slice_len(&self) -> usize {
        self.element_count() * self.element_stride()
    }

    /// Gera a SDL que descreve a fatia inteira deste array. Reproduz o algoritmo
    /// `gen_sdl` do fbclient (verificado byte a byte contra uma captura de
    /// `isc_array_get_slice` em `JOB.LANGUAGE_REQ`).
    pub fn to_sdl(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(32);
        s.push(sdl::VERSION1);
        // Descritor do elemento dentro de um `struct` de 1 campo (códigos BLR).
        s.push(sdl::STRUCT);
        s.push(1);
        s.push(self.blr_type);
        match self.blr_type {
            // Texto: comprimento como palavra de 2 bytes (LE).
            blr::TEXT | blr::VARYING => s.extend_from_slice(&self.length.to_le_bytes()),
            // Inteiros escalados: a escala como um byte com sinal.
            blr::SHORT | blr::LONG | blr::INT64 | blr::INT128 | blr::QUAD => {
                s.push(self.scale as i8 as u8)
            }
            // Os demais tipos não têm operando no descritor.
            _ => {}
        }
        // Relação e campo.
        s.push(sdl::RELATION);
        s.push(self.relation.len() as u8);
        s.extend_from_slice(self.relation.as_bytes());
        s.push(sdl::FIELD);
        s.push(self.field.len() as u8);
        s.extend_from_slice(self.field.as_bytes());
        // Um laço por dimensão: do1 quando o limite inferior é 1 (caso comum, só o
        // superior viaja); senão do2 com os dois limites.
        for (i, dim) in self.dimensions.iter().enumerate() {
            if dim.lower == 1 {
                s.push(sdl::DO1);
                s.push(i as u8);
                put_sdl_literal(&mut s, dim.upper);
            } else {
                s.push(sdl::DO2);
                s.push(i as u8);
                put_sdl_literal(&mut s, dim.lower);
                put_sdl_literal(&mut s, dim.upper);
            }
        }
        // Atribui o (único) elemento do struct indexado pelas variáveis de laço.
        s.push(sdl::ELEMENT);
        s.push(1);
        s.push(sdl::SCALAR);
        s.push(0); // índice do elemento no struct
        s.push(self.dimensions.len() as u8); // nº de subscritos = nº de dimensões
        for i in 0..self.dimensions.len() {
            s.push(sdl::VARIABLE);
            s.push(i as u8);
        }
        s.push(sdl::EOC);
        s
    }
}

/// Emite um literal inteiro de SDL com a menor largura que o comporta.
fn put_sdl_literal(s: &mut Vec<u8>, v: i32) {
    if (i8::MIN as i32..=i8::MAX as i32).contains(&v) {
        s.push(sdl::TINY_INTEGER);
        s.push(v as i8 as u8);
    } else if (i16::MIN as i32..=i16::MAX as i32).contains(&v) {
        s.push(sdl::SHORT_INTEGER);
        s.extend_from_slice(&(v as i16).to_le_bytes());
    } else {
        s.push(sdl::LONG_INTEGER);
        s.extend_from_slice(&v.to_le_bytes());
    }
}

impl Connection {
    /// Monta o [`ArrayDesc`] de uma coluna ARRAY consultando o catálogo do
    /// sistema (`RDB$*`), exatamente como o fbclient faz antes de uma fatia.
    /// `relation`/`field` são os nomes como armazenados (normalmente maiúsculas;
    /// um `ColumnMeta` de saída já os traz assim).
    pub async fn array_desc(
        &mut self,
        tx: &Transaction,
        relation: &str,
        field: &str,
    ) -> Result<ArrayDesc> {
        // 1. Tipo/escala/comprimento/dimensões + a "fonte" do campo (o domínio,
        //    p.ex. "RDB$4"), que é a chave de RDB$FIELD_DIMENSIONS.
        let mut stmt = self
            .prepare(
                tx,
                "SELECT f.RDB$FIELD_TYPE, f.RDB$FIELD_SUB_TYPE, f.RDB$FIELD_SCALE, \
                 f.RDB$FIELD_LENGTH, f.RDB$DIMENSIONS, f.RDB$FIELD_NAME \
                 FROM RDB$RELATION_FIELDS rf \
                 JOIN RDB$FIELDS f ON f.RDB$FIELD_NAME = rf.RDB$FIELD_SOURCE \
                 WHERE rf.RDB$RELATION_NAME = ? AND rf.RDB$FIELD_NAME = ?",
            )
            .await?;
        stmt.execute(self, tx, &[Value::Text(relation.into()), Value::Text(field.into())]).await?;
        let rows = stmt.fetch_all(self).await?;
        stmt.drop_statement(self).await?;

        let row = rows.into_iter().next().ok_or_else(|| {
            Error::protocol(format!("coluna '{relation}.{field}' não encontrada no catálogo"))
        })?;
        let blr_type = val_i64(&row[0]).unwrap_or(0) as u8;
        let sub_type = val_i64(&row[1]).unwrap_or(0) as i32;
        let scale = val_i64(&row[2]).unwrap_or(0) as i32;
        let length = val_i64(&row[3]).unwrap_or(0) as u16;
        let dims = val_i64(&row[4]).unwrap_or(0);
        let source = row[5].as_str().unwrap_or("").trim_end().to_string();
        if dims <= 0 {
            return Err(Error::protocol(format!("'{relation}.{field}' não é uma coluna ARRAY")));
        }

        // 2. Limites de cada dimensão, em ordem.
        let mut stmt = self
            .prepare(
                tx,
                "SELECT fd.RDB$LOWER_BOUND, fd.RDB$UPPER_BOUND \
                 FROM RDB$FIELD_DIMENSIONS fd WHERE fd.RDB$FIELD_NAME = ? \
                 ORDER BY fd.RDB$DIMENSION",
            )
            .await?;
        stmt.execute(self, tx, &[Value::Text(source)]).await?;
        let dim_rows = stmt.fetch_all(self).await?;
        stmt.drop_statement(self).await?;

        let dimensions: Vec<Dimension> = dim_rows
            .iter()
            .map(|r| Dimension {
                lower: val_i64(&r[0]).unwrap_or(1) as i32,
                upper: val_i64(&r[1]).unwrap_or(0) as i32,
            })
            .collect();

        Ok(ArrayDesc { relation: relation.into(), field: field.into(), blr_type, sub_type, scale, length, dimensions })
    }

    /// Lê todos os elementos de um array (`op_get_slice`). `array_id` é o id que
    /// veio na coluna ([`Value::Array`]); `desc` descreve o tipo e as dimensões.
    /// Devolve um valor por elemento, na ordem em que o servidor os transmite.
    pub async fn read_array(
        &mut self,
        tx: &Transaction,
        array_id: u64,
        desc: &ArrayDesc,
    ) -> Result<Vec<Value>> {
        let sdl = desc.to_sdl();
        let count = desc.element_count();

        let mut w = op_packet(op::GET_SLICE);
        w.put_i32(tx.handle());
        w.put_i64(array_id as i64); // id do array (quad)
        w.put_i32(desc.slice_len() as i32); // p_slc_length: tamanho da fatia pedida
        w.put_bytes(&sdl);
        w.put_bytes(&[]); // parâmetros da fatia: nenhum
        w.put_i32(0); // fatia de saída vazia (no get não enviamos dados)
        self.io().send(&w).await?;

        // A resposta de sucesso é um op_slice (sem vetor de status); um erro vem
        // como op_response.
        let code = read_op(self.io()).await?;
        if code == op::RESPONSE {
            read_response_body(self.io()).await?.into_result()?;
            return Err(Error::protocol("op_get_slice falhou sem status de erro"));
        }
        if code != op::SLICE {
            return Err(Error::protocol(format!(
                "esperava op_slice, recebi {} ({code})",
                op_name(code)
            )));
        }
        let _slr_length = self.io().read_i32().await?; // tamanho na repr. do cliente
        let _xdr_length = self.io().read_i32().await?; // comprimento lógico XDR

        let charset = self.charset();
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(decode_element(self.io(), desc, charset).await?);
        }
        Ok(out)
    }

    /// Cria um novo array com `values` (`op_put_slice`) e devolve seu id, para
    /// usar como [`Value::Array`] num INSERT/UPDATE. O número de valores deve
    /// bater com `desc.element_count()`.
    pub async fn write_array(
        &mut self,
        tx: &Transaction,
        desc: &ArrayDesc,
        values: &[Value],
    ) -> Result<u64> {
        let count = desc.element_count();
        if values.len() != count {
            return Err(Error::protocol(format!(
                "o array espera {count} elementos, recebeu {}",
                values.len()
            )));
        }
        let sdl = desc.to_sdl();
        let charset = self.charset();

        // Serializa os elementos no formato xdr_datum (mesmo do op_slice de leitura).
        let mut data = Vec::new();
        for v in values {
            encode_element(&mut data, desc, v, charset)?;
        }

        let mut w = op_packet(op::PUT_SLICE);
        w.put_i32(tx.handle());
        w.put_i64(0); // id 0 ⇒ o servidor aloca um array novo
        w.put_i32(desc.slice_len() as i32); // p_slc_length na repr. do cliente
        w.put_bytes(&sdl);
        w.put_bytes(&[]); // parâmetros: nenhum
        w.put_i32(desc.slice_len() as i32); // comprimento lógico da fatia
        w.put_raw(&data);
        w.align();
        self.io().send(&w).await?;

        // O id do novo array volta no campo blob_id do op_response.
        Ok(read_response(self.io()).await?.blob_id)
    }
}

/// Visão `i64` de um valor numérico do catálogo (SMALLINT/INTEGER), ou `None`.
fn val_i64(v: &Value) -> Option<i64> {
    v.as_i64()
}

/// Decodifica um elemento da fatia conforme seu tipo BLR (formato xdr_datum).
async fn decode_element(stream: &mut FbStream, desc: &ArrayDesc, charset: Charset) -> Result<Value> {
    Ok(match desc.blr_type {
        blr::SHORT => Value::Short(stream.read_i32().await? as i16),
        blr::LONG => Value::Int(stream.read_i32().await?),
        blr::INT64 => Value::BigInt(stream.read_i64().await?),
        blr::INT128 => {
            let b = stream.read_raw(16).await?;
            Value::Int128(i128::from_be_bytes(b.try_into().unwrap()))
        }
        blr::FLOAT => Value::Float(f32::from_bits(stream.read_i32().await? as u32)),
        blr::DOUBLE | blr::D_FLOAT => Value::Double(stream.read_f64().await?),
        blr::SQL_DATE => Value::Date(stream.read_i32().await?),
        blr::SQL_TIME => Value::Time(stream.read_i32().await? as u32),
        blr::TIMESTAMP => {
            let date = stream.read_i32().await?;
            let time = stream.read_i32().await? as u32;
            Value::Timestamp(date, time)
        }
        blr::BOOL => {
            let b = stream.read_raw(1).await?;
            stream.read_pad(1).await?;
            Value::Bool(b[0] != 0)
        }
        blr::DEC64 => {
            let b = stream.read_raw(8).await?;
            Value::DecFloat(crate::decfloat::DecFloat::from_decimal64(b.try_into().unwrap()))
        }
        blr::DEC128 => {
            let b = stream.read_raw(16).await?;
            Value::DecFloat(crate::decfloat::DecFloat::from_decimal128(b.try_into().unwrap()))
        }
        blr::TEXT => {
            let n = desc.length as usize;
            let raw = stream.read_raw(n).await?;
            stream.read_pad(n).await?;
            text_or_bytes(desc, raw, charset, true)
        }
        blr::VARYING => {
            let raw = stream.read_bytes().await?; // comprimento(4) + bytes + padding
            text_or_bytes(desc, raw, charset, false)
        }
        other => {
            // Tipo não tratado: consome o stride como bytes opacos.
            let _ = other;
            Value::Bytes(stream.read_raw(desc.element_stride()).await?)
        }
    })
}

/// Serializa um elemento no formato xdr_datum (espelho de [`decode_element`]).
fn encode_element(out: &mut Vec<u8>, desc: &ArrayDesc, val: &Value, charset: Charset) -> Result<()> {
    let mismatch = || Error::protocol(format!("valor não cabe no tipo de elemento BLR {}", desc.blr_type));
    match desc.blr_type {
        blr::SHORT => put_i32_be(out, i32::from(val.as_i64().ok_or_else(mismatch)? as i16)),
        blr::LONG => put_i32_be(out, val.as_i64().ok_or_else(mismatch)? as i32),
        blr::INT64 => out.extend_from_slice(&val.as_i64().ok_or_else(mismatch)?.to_be_bytes()),
        blr::INT128 => match val {
            Value::Int128(v) => out.extend_from_slice(&v.to_be_bytes()),
            _ => out.extend_from_slice(&i128::from(val.as_i64().ok_or_else(mismatch)?).to_be_bytes()),
        },
        blr::FLOAT => match val {
            Value::Float(f) => out.extend_from_slice(&f.to_bits().to_be_bytes()),
            Value::Double(f) => out.extend_from_slice(&(*f as f32).to_bits().to_be_bytes()),
            _ => return Err(mismatch()),
        },
        blr::DOUBLE | blr::D_FLOAT => match val {
            Value::Double(f) => out.extend_from_slice(&f.to_bits().to_be_bytes()),
            Value::Float(f) => out.extend_from_slice(&f64::from(*f).to_bits().to_be_bytes()),
            _ => return Err(mismatch()),
        },
        blr::SQL_DATE => match val {
            Value::Date(d) | Value::Timestamp(d, _) => put_i32_be(out, *d),
            _ => return Err(mismatch()),
        },
        blr::SQL_TIME => match val {
            Value::Time(t) | Value::Timestamp(_, t) => put_i32_be(out, *t as i32),
            _ => return Err(mismatch()),
        },
        blr::TIMESTAMP => match val {
            Value::Timestamp(d, t) => {
                put_i32_be(out, *d);
                put_i32_be(out, *t as i32);
            }
            _ => return Err(mismatch()),
        },
        blr::BOOL => {
            out.push(matches!(val, Value::Bool(true)) as u8);
            put_pad(out, 1);
        }
        blr::DEC64 => match val {
            Value::DecFloat(d) => out.extend_from_slice(&d.to_decimal64().ok_or_else(mismatch)?),
            _ => return Err(mismatch()),
        },
        blr::DEC128 => match val {
            Value::DecFloat(d) => out.extend_from_slice(&d.to_decimal128().ok_or_else(mismatch)?),
            _ => return Err(mismatch()),
        },
        blr::VARYING => {
            let bytes = elem_text_bytes(val, charset)?;
            put_i32_be(out, bytes.len() as i32);
            out.extend_from_slice(&bytes);
            put_pad(out, bytes.len());
        }
        blr::TEXT => {
            let bytes = elem_text_bytes(val, charset)?;
            let n = desc.length as usize;
            out.extend_from_slice(&bytes);
            for _ in bytes.len()..n {
                out.push(b' '); // CHAR(n) é preenchido à direita com espaços
            }
            put_pad(out, n.max(bytes.len()));
        }
        _ => return Err(Error::protocol(format!("tipo de elemento BLR {} não suportado para escrita", desc.blr_type))),
    }
    Ok(())
}

fn put_i32_be(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_pad(out: &mut Vec<u8>, data_len: usize) {
    for _ in 0..(crate::value::align4(data_len) - data_len) {
        out.push(0);
    }
}

fn elem_text_bytes(val: &Value, charset: Charset) -> Result<std::borrow::Cow<'_, [u8]>> {
    use std::borrow::Cow;
    match val {
        Value::Text(s) => Ok(Cow::Owned(charset.encode(s))),
        Value::Bytes(b) => Ok(Cow::Borrowed(b)),
        _ => Err(Error::protocol("esperava um valor de texto/bytes para elemento de array")),
    }
}

/// Texto OCTETS (sub-tipo 1) fica como bytes; o resto é decodificado pelo charset
/// da conexão. CHAR tem o padding de espaços removido (`is_char`).
fn text_or_bytes(desc: &ArrayDesc, raw: Vec<u8>, charset: Charset, is_char: bool) -> Value {
    const CS_OCTETS: i32 = 1;
    if desc.sub_type == CS_OCTETS {
        Value::Bytes(raw)
    } else {
        let s = charset.decode(&raw);
        if is_char {
            Value::Text(s.trim_end_matches(' ').to_string())
        } else {
            Value::Text(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varchar15_1to5() -> ArrayDesc {
        ArrayDesc {
            relation: "JOB".into(),
            field: "LANGUAGE_REQ".into(),
            blr_type: blr::VARYING,
            sub_type: 0,
            scale: 0,
            length: 15,
            dimensions: vec![Dimension { lower: 1, upper: 5 }],
        }
    }

    #[test]
    fn sdl_matches_captured_bytes() {
        // SDL exata capturada de isc_array_get_slice em JOB.LANGUAGE_REQ
        // (VARCHAR(15)[1:5]) contra o employee.fdb.
        let expected: &[u8] = &[
            0x01, 0x06, 0x01, 0x25, 0x0f, 0x00, 0x02, 0x03, b'J', b'O', b'B', 0x04, 0x0c, b'L',
            b'A', b'N', b'G', b'U', b'A', b'G', b'E', b'_', b'R', b'E', b'Q', 0x23, 0x00, 0x09,
            0x05, 0x24, 0x01, 0x08, 0x00, 0x01, 0x07, 0x00, 0xff,
        ];
        assert_eq!(varchar15_1to5().to_sdl(), expected);
    }

    #[test]
    fn element_count_and_stride() {
        let d = varchar15_1to5();
        assert_eq!(d.element_count(), 5);
        assert_eq!(d.element_stride(), 17); // VARCHAR(15) ⇒ 15 + 2
        assert_eq!(d.slice_len(), 85);
    }

    #[test]
    fn sdl_uses_do2_when_lower_bound_not_one() {
        let mut d = varchar15_1to5();
        d.dimensions = vec![Dimension { lower: -2, upper: 3 }];
        let s = d.to_sdl();
        // Procura o verbo de laço: deve ser DO2 (34) com os dois limites.
        let pos = s.iter().position(|&b| b == sdl::DO2).expect("esperava DO2");
        assert_eq!(s[pos + 1], 0); // variável 0
        assert_eq!(s[pos + 2], sdl::TINY_INTEGER);
        assert_eq!(s[pos + 3] as i8, -2); // limite inferior
        assert_eq!(s[pos + 4], sdl::TINY_INTEGER);
        assert_eq!(s[pos + 5] as i8, 3); // limite superior
        assert_eq!(d.element_count(), 6);
    }

    #[test]
    fn sdl_multidim_emits_two_loops_and_two_subscripts() {
        let mut d = varchar15_1to5();
        d.blr_type = blr::LONG;
        d.length = 4;
        d.dimensions = vec![Dimension { lower: 1, upper: 2 }, Dimension { lower: 1, upper: 3 }];
        let s = d.to_sdl();
        assert_eq!(s.iter().filter(|&&b| b == sdl::DO1).count(), 2);
        assert_eq!(s.iter().filter(|&&b| b == sdl::VARIABLE).count(), 2);
        assert_eq!(d.element_count(), 6);
        // scalar com ndims = 2.
        let pos = s.iter().position(|&b| b == sdl::SCALAR).unwrap();
        assert_eq!(s[pos + 2], 2);
    }
}
