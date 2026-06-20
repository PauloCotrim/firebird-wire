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

/// Diferença em dias entre a época do Firebird (1858-11-17, a época do Dia
/// Juliano Modificado) e a época Unix (1970-01-01). Usada para converter o
/// inteiro bruto de [`Value::Date`] em uma data civil.
const FB_EPOCH_TO_UNIX_DAYS: i32 = 40587;

/// Unidades de tempo do Firebird por segundo: o tempo é contado em frações de
/// 1/10000 de segundo (décimos de milissegundo) a partir da meia-noite.
const FB_TIME_UNITS_PER_SEC: u32 = 10_000;

/// Uma data civil (calendário gregoriano proléptico) já decodificada do inteiro
/// bruto que o Firebird transmite em [`Value::Date`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CivilDate {
    pub year: i32,
    /// Mês 1..=12.
    pub month: u32,
    /// Dia 1..=31.
    pub day: u32,
}

/// Uma hora do dia já decodificada do inteiro bruto de [`Value::Time`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CivilTime {
    /// Hora 0..=23.
    pub hour: u32,
    /// Minuto 0..=59.
    pub minute: u32,
    /// Segundo 0..=59.
    pub second: u32,
    /// Fração de segundo em unidades de 1/10000 s (0..=9999).
    pub frac: u32,
}

impl CivilTime {
    /// Fração de segundo expressa em nanossegundos (0..=999_999_900).
    pub fn nanos(&self) -> u32 {
        self.frac * 100_000
    }
}

/// Um carimbo de data/hora civil decodificado de [`Value::Timestamp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CivilTimestamp {
    pub date: CivilDate,
    pub time: CivilTime,
}

/// Converte um contador de dias desde 1970-01-01 em (ano, mês, dia) no
/// calendário gregoriano proléptico. Algoritmo de Howard Hinnant
/// (`civil_from_days`), válido para qualquer data.
fn civil_from_unix_days(z: i64) -> CivilDate {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // dia da era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };
    CivilDate { year: year as i32, month, day }
}

/// Inverso de [`civil_from_unix_days`]: (ano, mês, dia) → dias desde 1970-01-01.
fn unix_days_from_civil(d: CivilDate) -> i64 {
    let y = d.year as i64 - if d.month <= 2 { 1 } else { 0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = d.month as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d.day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

impl CivilDate {
    /// Inteiro bruto que o Firebird usa para esta data (dias desde 1858-11-17).
    pub fn to_fb_days(self) -> i32 {
        (unix_days_from_civil(self) as i32) + FB_EPOCH_TO_UNIX_DAYS
    }
}

impl CivilTime {
    /// Inteiro bruto que o Firebird usa para esta hora (frações de 1/10000 s
    /// desde a meia-noite).
    pub fn to_fb_time(self) -> u32 {
        ((self.hour * 3600 + self.minute * 60 + self.second) * FB_TIME_UNITS_PER_SEC) + self.frac
    }
}

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Constrói um [`Value::Date`] a partir de uma data civil.
    pub fn date(year: i32, month: u32, day: u32) -> Value {
        Value::Date(CivilDate { year, month, day }.to_fb_days())
    }

    /// Constrói um [`Value::Time`] a partir de uma hora civil (`frac` em 1/10000 s).
    pub fn time(hour: u32, minute: u32, second: u32, frac: u32) -> Value {
        Value::Time(CivilTime { hour, minute, second, frac }.to_fb_time())
    }

    /// Constrói um [`Value::Timestamp`] a partir de data + hora civis.
    pub fn timestamp(date: CivilDate, time: CivilTime) -> Value {
        Value::Timestamp(date.to_fb_days(), time.to_fb_time())
    }

    /// Decodifica um [`Value::Date`] (ou a parte de data de um `Timestamp`) em
    /// uma data civil.
    pub fn as_civil_date(&self) -> Option<CivilDate> {
        match self {
            Value::Date(d) | Value::Timestamp(d, _) => {
                Some(civil_from_unix_days(*d as i64 - FB_EPOCH_TO_UNIX_DAYS as i64))
            }
            _ => None,
        }
    }

    /// Decodifica um [`Value::Time`] (ou a parte de hora de um `Timestamp`) em
    /// uma hora civil.
    pub fn as_civil_time(&self) -> Option<CivilTime> {
        let t = match self {
            Value::Time(t) | Value::Timestamp(_, t) => *t,
            _ => return None,
        };
        let frac = t % FB_TIME_UNITS_PER_SEC;
        let secs = t / FB_TIME_UNITS_PER_SEC;
        Some(CivilTime {
            hour: secs / 3600,
            minute: (secs % 3600) / 60,
            second: secs % 60,
            frac,
        })
    }

    /// Decodifica um [`Value::Timestamp`] em data + hora civis.
    pub fn as_civil_timestamp(&self) -> Option<CivilTimestamp> {
        match self {
            Value::Timestamp(..) => Some(CivilTimestamp {
                date: self.as_civil_date()?,
                time: self.as_civil_time()?,
            }),
            _ => None,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_roundtrip_and_known_points() {
        // A época do Firebird (dia 0) é 1858-11-17.
        assert_eq!(
            Value::Date(0).as_civil_date(),
            Some(CivilDate { year: 1858, month: 11, day: 17 })
        );
        // A época Unix em dias do Firebird = 40587.
        assert_eq!(
            Value::Date(40_587).as_civil_date(),
            Some(CivilDate { year: 1970, month: 1, day: 1 })
        );
        // Ida e volta por várias datas, incluindo um ano bissexto e fim de ano.
        for (y, m, d) in [
            (1858, 11, 17),
            (1970, 1, 1),
            (2000, 2, 29),
            (2026, 6, 20),
            (1, 1, 1),
            (2400, 12, 31),
        ] {
            let v = Value::date(y, m, d);
            assert_eq!(v.as_civil_date(), Some(CivilDate { year: y, month: m, day: d }));
        }
    }

    #[test]
    fn time_roundtrip() {
        // Meia-noite.
        assert_eq!(
            Value::Time(0).as_civil_time(),
            Some(CivilTime { hour: 0, minute: 0, second: 0, frac: 0 })
        );
        // 23:59:59 e 0.9999 s = (23*3600+59*60+59)*10000 + 9999.
        let raw = (23 * 3600 + 59 * 60 + 59) * 10_000 + 9999;
        assert_eq!(
            Value::Time(raw).as_civil_time(),
            Some(CivilTime { hour: 23, minute: 59, second: 59, frac: 9999 })
        );
        let v = Value::time(13, 45, 30, 1234);
        let ct = v.as_civil_time().unwrap();
        assert_eq!((ct.hour, ct.minute, ct.second, ct.frac), (13, 45, 30, 1234));
        assert_eq!(ct.nanos(), 123_400_000);
    }

    #[test]
    fn timestamp_splits_date_and_time() {
        let date = CivilDate { year: 2026, month: 6, day: 20 };
        let time = CivilTime { hour: 9, minute: 30, second: 15, frac: 0 };
        let v = Value::timestamp(date, time);
        let ts = v.as_civil_timestamp().unwrap();
        assert_eq!(ts.date, date);
        assert_eq!(ts.time, time);
        // Um Date puro não produz um timestamp civil.
        assert_eq!(Value::Date(0).as_civil_timestamp(), None);
        // Mas a parte de data de um Timestamp é acessível por as_civil_date.
        assert_eq!(v.as_civil_date(), Some(date));
        assert_eq!(v.as_civil_time(), Some(time));
    }
}
