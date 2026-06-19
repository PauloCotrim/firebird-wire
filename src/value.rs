//! Valores SQL e metadados de coluna.

use crate::wire::consts::sql_type;

/// Um valor SQL decodificado. Tipos numéricos com escala diferente de zero
/// (NUMERIC/DECIMAL) mantêm seu inteiro bruto; consulte a [`ColumnMeta::scale`]
/// da coluna para renderizar o ponto decimal.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// SMALLINT (também a mantissa bruta de um NUMERIC com escala baseado em SMALLINT).
    Short(i16),
    /// INTEGER (ou NUMERIC com escala baseado em INTEGER).
    Int(i32),
    /// BIGINT (ou NUMERIC com escala baseado em BIGINT).
    BigInt(i64),
    Float(f32),
    Double(f64),
    /// Texto CHAR/VARCHAR (decodificado com perdas como UTF-8/latin-1 pelo charset do chamador).
    Text(String),
    /// Bytes brutos para CHAR/VARCHAR binário (OCTETS) e outros dados opacos.
    Bytes(Vec<u8>),
    /// Identificador de blob (busque o conteúdo separadamente).
    Blob(u64),
    /// Dias desde 1858-11-17 (a época Firebird/Modified-Julian).
    Date(i32),
    /// Hora em décimos de milésimo de segundo desde a meia-noite.
    Time(u32),
    /// Par (data, hora) usando as duas codificações acima.
    Timestamp(i32, u32),
    /// Inteiro de 128 bits (INT128 / NUMERIC amplo).
    Int128(i128),
}

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Visão `i64` de melhor esforço de um valor inteiro.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Short(v) => Some(*v as i64),
            Value::Int(v) => Some(*v as i64),
            Value::BigInt(v) => Some(*v),
            Value::Int128(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// Empresta o texto de um valor de string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }
}

/// Metadados que descrevem uma coluna da saída de uma instrução preparada (ou um
/// de seus parâmetros de entrada).
#[derive(Debug, Clone, Default)]
pub struct ColumnMeta {
    /// Posição na mensagem, começando em zero.
    pub index: usize,
    /// Tipo SQL base (`SQL_*`, com o bit anulável removido).
    pub sql_type: i32,
    pub sub_type: i32,
    pub scale: i32,
    /// Comprimento declarado em bytes (CHAR/VARCHAR) ou largura do tipo.
    pub length: i32,
    pub nullable: bool,
    /// Nome subjacente da coluna.
    pub field: String,
    pub relation: String,
    /// Alias de saída (o nome que a lista SELECT deu a ela).
    pub alias: String,
    pub owner: String,
}

impl ColumnMeta {
    /// O nome que os chamadores veem para esta coluna (alias se presente, senão field).
    pub fn name(&self) -> &str {
        if self.alias.is_empty() { &self.field } else { &self.alias }
    }

    /// Bytes que esta coluna ocupa em uma mensagem de linha XDR quando não-nula.
    pub(crate) fn xdr_len(&self) -> usize {
        match sql_type::base(self.sql_type) {
            sql_type::TEXT => align4(self.length as usize),
            sql_type::VARYING => 4 + align4(self.length as usize),
            sql_type::SHORT | sql_type::LONG => 4,
            sql_type::INT64 => 8,
            sql_type::INT128 => 16,
            sql_type::FLOAT => 4,
            sql_type::DOUBLE | sql_type::D_FLOAT => 8,
            sql_type::TYPE_DATE | sql_type::TYPE_TIME => 4,
            sql_type::TIMESTAMP => 8,
            sql_type::BLOB | sql_type::QUAD => 8,
            sql_type::BOOLEAN => 4,
            sql_type::DEC16 => 8,
            sql_type::DEC34 => 16,
            _ => 8,
        }
    }
}

#[inline]
pub(crate) fn align4(n: usize) -> usize {
    (n + 3) & !3
}
