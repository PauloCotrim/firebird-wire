//! Valores SQL e metadados de coluna.

use crate::wire::consts::sql_type;

/// Um valor SQL decodificado. Tipos numéricos com escala diferente de zero
/// (NUMERIC/DECIMAL) mantêm seu inteiro bruto; consulte a [`ColumnMeta::scale`]
/// da coluna para renderizar o ponto decimal.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Valor SQL `NULL`.
    Null,
    /// Booleano SQL (`BOOLEAN`).
    Bool(bool),
    /// SMALLINT (também a mantissa bruta de um NUMERIC com escala baseado em SMALLINT).
    Short(i16),
    /// INTEGER (ou NUMERIC com escala baseado em INTEGER).
    Int(i32),
    /// BIGINT (ou NUMERIC com escala baseado em BIGINT).
    BigInt(i64),
    /// Número de ponto flutuante de 32 bits (`FLOAT`).
    Float(f32),
    /// Número de ponto flutuante de 64 bits (`DOUBLE PRECISION`).
    Double(f64),
    /// Texto CHAR/VARCHAR, decodificado conforme o charset da conexão (ver
    /// [`crate::charset::Charset`]); CHAR vem sem o padding de espaços à direita.
    Text(String),
    /// Bytes brutos para CHAR/VARCHAR binário (OCTETS) e outros dados opacos.
    Bytes(Vec<u8>),
    /// Identificador de blob (busque o conteúdo separadamente).
    Blob(u64),
    /// Identificador de ARRAY (um quad, como o blob). Leia os elementos com
    /// [`crate::Connection::read_array`] usando o [`crate::ArrayDesc`] da coluna.
    Array(u64),
    /// Dias desde 1858-11-17 (a época Firebird/Modified-Julian).
    Date(i32),
    /// Hora em décimos de milésimo de segundo desde a meia-noite.
    Time(u32),
    /// Par (data, hora) usando as duas codificações acima.
    Timestamp(i32, u32),
    /// Inteiro de 128 bits (INT128 / NUMERIC amplo).
    Int128(i128),
    /// `DECFLOAT(16)`/`DECFLOAT(34)` decodificado (ponto flutuante decimal IEEE).
    DecFloat(crate::decfloat::DecFloat),
    /// `TIME WITH TIME ZONE` (FB4+): hora UTC + zona.
    TimeTz(TimeTz),
    /// `TIMESTAMP WITH TIME ZONE` (FB4+): carimbo UTC + zona.
    TimestampTz(TimestampTz),
}

/// Valor SQL emprestado para envio de parâmetros sem materializar um [`Value`]
/// owned. Útil principalmente para texto e bytes (`&str`/`&[u8]`).
///
/// Valores recebidos do servidor continuam usando [`Value`], porque o buffer de
/// rede não vive além da decodificação da linha.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ValueRef<'a> {
    /// Valor SQL `NULL`.
    Null,
    /// Booleano SQL (`BOOLEAN`).
    Bool(bool),
    /// SMALLINT.
    Short(i16),
    /// INTEGER.
    Int(i32),
    /// BIGINT.
    BigInt(i64),
    /// Número de ponto flutuante de 32 bits (`FLOAT`).
    Float(f32),
    /// Número de ponto flutuante de 64 bits (`DOUBLE PRECISION`).
    Double(f64),
    /// Texto CHAR/VARCHAR emprestado.
    Text(&'a str),
    /// Bytes brutos emprestados.
    Bytes(&'a [u8]),
    /// Identificador de blob.
    Blob(u64),
    /// Identificador de ARRAY.
    Array(u64),
    /// Dias desde 1858-11-17.
    Date(i32),
    /// Hora em décimos de milésimo de segundo desde a meia-noite.
    Time(u32),
    /// Par (data, hora).
    Timestamp(i32, u32),
    /// Inteiro de 128 bits.
    Int128(i128),
    /// `DECFLOAT(16)`/`DECFLOAT(34)`.
    DecFloat(crate::decfloat::DecFloat),
    /// `TIME WITH TIME ZONE`.
    TimeTz(TimeTz),
    /// `TIMESTAMP WITH TIME ZONE`.
    TimestampTz(TimestampTz),
}

/// `TIME WITH TIME ZONE`: a hora é armazenada em UTC; a zona é um id do Firebird
/// (veja [`crate::tz`]). O `offset` (minutos a leste de UTC) é o offset RESOLVIDO
/// para este instante — o servidor o calcula (já aplicando horário de verão) e o
/// envia no formato estendido (`_EX`), então vale tanto para zonas por offset
/// quanto para zonas nomeadas. Use [`TimeTz::local`] para a hora de parede local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeTz {
    /// Hora UTC em frações de 1/10000 s desde a meia-noite.
    pub utc_time: u32,
    /// Id de zona do Firebird.
    pub zone: u16,
    /// Offset resolvido a leste de UTC, em minutos.
    pub offset: i16,
}

/// `TIMESTAMP WITH TIME ZONE`: data/hora em UTC + zona. Veja [`TimeTz`] para a
/// semântica de `zone`/`offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampTz {
    /// Dias UTC desde a época do Firebird (1858-11-17).
    pub utc_date: i32,
    /// Hora UTC em frações de 1/10000 s desde a meia-noite.
    pub utc_time: u32,
    /// Id de zona do Firebird.
    pub zone: u16,
    /// Offset resolvido a leste de UTC, em minutos.
    pub offset: i16,
}

/// Unidades de tempo do Firebird em um dia inteiro (24 h × 1/10000 s).
const FB_TIME_UNITS_PER_DAY: i64 = 24 * 3600 * FB_TIME_UNITS_PER_SEC as i64;

impl TimeTz {
    /// Nome IANA da zona, ou `None` para zonas baseadas em offset.
    pub fn zone_name(&self) -> Option<&'static str> {
        crate::tz::zone_name(self.zone)
    }

    /// Rótulo legível da zona (nome IANA ou `±HH:MM`).
    pub fn zone_label(&self) -> String {
        crate::tz::zone_label(self.zone)
    }

    /// Hora de parede LOCAL (UTC + offset), normalizada ao intervalo de um dia.
    pub fn local(&self) -> CivilTime {
        let units = (self.utc_time as i64 + self.offset as i64 * 60 * FB_TIME_UNITS_PER_SEC as i64)
            .rem_euclid(FB_TIME_UNITS_PER_DAY) as u32;
        Value::Time(units).as_civil_time().unwrap()
    }
}

impl TimestampTz {
    /// Nome IANA da zona, ou `None` para zonas baseadas em offset.
    pub fn zone_name(&self) -> Option<&'static str> {
        crate::tz::zone_name(self.zone)
    }

    /// Rótulo legível da zona (nome IANA ou `±HH:MM`).
    pub fn zone_label(&self) -> String {
        crate::tz::zone_label(self.zone)
    }

    /// Data + hora de parede LOCAL (UTC + offset).
    pub fn local(&self) -> CivilTimestamp {
        let total = self.utc_date as i64 * FB_TIME_UNITS_PER_DAY
            + self.utc_time as i64
            + self.offset as i64 * 60 * FB_TIME_UNITS_PER_SEC as i64;
        let date = total.div_euclid(FB_TIME_UNITS_PER_DAY);
        let time = total.rem_euclid(FB_TIME_UNITS_PER_DAY) as u32;
        CivilTimestamp {
            date: Value::Date(date as i32).as_civil_date().unwrap(),
            time: Value::Time(time).as_civil_time().unwrap(),
        }
    }
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
    /// Ano no calendário gregoriano.
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
    /// Parte de data.
    pub date: CivilDate,
    /// Parte de hora.
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
    CivilDate {
        year: year as i32,
        month,
        day,
    }
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
    /// Verdadeiro quando o valor é [`Value::Null`].
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Constrói um [`Value::Date`] a partir de uma data civil.
    pub fn date(year: i32, month: u32, day: u32) -> Value {
        Value::Date(CivilDate { year, month, day }.to_fb_days())
    }

    /// Constrói um [`Value::Time`] a partir de uma hora civil (`frac` em 1/10000 s).
    pub fn time(hour: u32, minute: u32, second: u32, frac: u32) -> Value {
        Value::Time(
            CivilTime {
                hour,
                minute,
                second,
                frac,
            }
            .to_fb_time(),
        )
    }

    /// Constrói um [`Value::Timestamp`] a partir de data + hora civis.
    pub fn timestamp(date: CivilDate, time: CivilTime) -> Value {
        Value::Timestamp(date.to_fb_days(), time.to_fb_time())
    }

    /// Decodifica um [`Value::Date`] (ou a parte de data de um `Timestamp`) em
    /// uma data civil.
    pub fn as_civil_date(&self) -> Option<CivilDate> {
        match self {
            Value::Date(d) | Value::Timestamp(d, _) => Some(civil_from_unix_days(
                *d as i64 - FB_EPOCH_TO_UNIX_DAYS as i64,
            )),
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

impl<'a> ValueRef<'a> {
    /// Verdadeiro quando o valor é [`ValueRef::Null`].
    pub fn is_null(self) -> bool {
        matches!(self, ValueRef::Null)
    }

    /// Visão `i64` de melhor esforço de um valor inteiro.
    pub fn as_i64(self) -> Option<i64> {
        match self {
            ValueRef::Short(v) => Some(v as i64),
            ValueRef::Int(v) => Some(v as i64),
            ValueRef::BigInt(v) => Some(v),
            ValueRef::Int128(v) => i64::try_from(v).ok(),
            _ => None,
        }
    }

    /// Empresta o texto de um valor de string.
    pub fn as_str(self) -> Option<&'a str> {
        match self {
            ValueRef::Text(s) => Some(s),
            _ => None,
        }
    }
}

impl<'a> From<&'a Value> for ValueRef<'a> {
    fn from(v: &'a Value) -> Self {
        match v {
            Value::Null => ValueRef::Null,
            Value::Bool(v) => ValueRef::Bool(*v),
            Value::Short(v) => ValueRef::Short(*v),
            Value::Int(v) => ValueRef::Int(*v),
            Value::BigInt(v) => ValueRef::BigInt(*v),
            Value::Float(v) => ValueRef::Float(*v),
            Value::Double(v) => ValueRef::Double(*v),
            Value::Text(v) => ValueRef::Text(v),
            Value::Bytes(v) => ValueRef::Bytes(v),
            Value::Blob(v) => ValueRef::Blob(*v),
            Value::Array(v) => ValueRef::Array(*v),
            Value::Date(v) => ValueRef::Date(*v),
            Value::Time(v) => ValueRef::Time(*v),
            Value::Timestamp(d, t) => ValueRef::Timestamp(*d, *t),
            Value::Int128(v) => ValueRef::Int128(*v),
            Value::DecFloat(v) => ValueRef::DecFloat(*v),
            Value::TimeTz(v) => ValueRef::TimeTz(*v),
            Value::TimestampTz(v) => ValueRef::TimestampTz(*v),
        }
    }
}

impl From<bool> for ValueRef<'_> {
    fn from(v: bool) -> Self {
        ValueRef::Bool(v)
    }
}

impl From<i16> for ValueRef<'_> {
    fn from(v: i16) -> Self {
        ValueRef::Short(v)
    }
}

impl From<i32> for ValueRef<'_> {
    fn from(v: i32) -> Self {
        ValueRef::Int(v)
    }
}

impl From<i64> for ValueRef<'_> {
    fn from(v: i64) -> Self {
        ValueRef::BigInt(v)
    }
}

impl From<i128> for ValueRef<'_> {
    fn from(v: i128) -> Self {
        ValueRef::Int128(v)
    }
}

impl From<f32> for ValueRef<'_> {
    fn from(v: f32) -> Self {
        ValueRef::Float(v)
    }
}

impl From<f64> for ValueRef<'_> {
    fn from(v: f64) -> Self {
        ValueRef::Double(v)
    }
}

impl<'a> From<&'a str> for ValueRef<'a> {
    fn from(v: &'a str) -> Self {
        ValueRef::Text(v)
    }
}

impl<'a> From<&'a String> for ValueRef<'a> {
    fn from(v: &'a String) -> Self {
        ValueRef::Text(v)
    }
}

impl<'a> From<&'a [u8]> for ValueRef<'a> {
    fn from(v: &'a [u8]) -> Self {
        ValueRef::Bytes(v)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for ValueRef<'a> {
    fn from(v: &'a [u8; N]) -> Self {
        ValueRef::Bytes(v)
    }
}

impl<'a> From<&'a Vec<u8>> for ValueRef<'a> {
    fn from(v: &'a Vec<u8>) -> Self {
        ValueRef::Bytes(v)
    }
}

impl From<crate::decfloat::DecFloat> for ValueRef<'_> {
    fn from(v: crate::decfloat::DecFloat) -> Self {
        ValueRef::DecFloat(v)
    }
}

impl From<TimeTz> for ValueRef<'_> {
    fn from(v: TimeTz) -> Self {
        ValueRef::TimeTz(v)
    }
}

impl From<TimestampTz> for ValueRef<'_> {
    fn from(v: TimestampTz) -> Self {
        ValueRef::TimestampTz(v)
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<i16> for Value {
    fn from(v: i16) -> Self {
        Value::Short(v)
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Int(v)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::BigInt(v)
    }
}

impl From<i128> for Value {
    fn from(v: i128) -> Self {
        Value::Int128(v)
    }
}

impl From<f32> for Value {
    fn from(v: f32) -> Self {
        Value::Float(v)
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Double(v)
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::Text(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::Text(v.to_string())
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::Bytes(v)
    }
}

impl From<&[u8]> for Value {
    fn from(v: &[u8]) -> Self {
        Value::Bytes(v.to_vec())
    }
}

#[cfg(feature = "chrono")]
impl From<chrono::NaiveDate> for CivilDate {
    fn from(v: chrono::NaiveDate) -> Self {
        use chrono::Datelike;

        CivilDate {
            year: v.year(),
            month: v.month(),
            day: v.day(),
        }
    }
}

#[cfg(feature = "chrono")]
impl From<chrono::NaiveTime> for CivilTime {
    fn from(v: chrono::NaiveTime) -> Self {
        use chrono::Timelike;

        CivilTime {
            hour: v.hour(),
            minute: v.minute(),
            second: v.second(),
            frac: v.nanosecond() / 100_000,
        }
    }
}

#[cfg(feature = "chrono")]
impl From<chrono::NaiveDateTime> for CivilTimestamp {
    fn from(v: chrono::NaiveDateTime) -> Self {
        CivilTimestamp {
            date: v.date().into(),
            time: v.time().into(),
        }
    }
}

#[cfg(feature = "chrono")]
impl From<chrono::NaiveDate> for Value {
    fn from(v: chrono::NaiveDate) -> Self {
        Value::Date(CivilDate::from(v).to_fb_days())
    }
}

#[cfg(feature = "chrono")]
impl From<chrono::NaiveTime> for Value {
    fn from(v: chrono::NaiveTime) -> Self {
        Value::Time(CivilTime::from(v).to_fb_time())
    }
}

#[cfg(feature = "chrono")]
impl From<chrono::NaiveDateTime> for Value {
    fn from(v: chrono::NaiveDateTime) -> Self {
        Value::timestamp(v.date().into(), v.time().into())
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<&Value> for chrono::NaiveDate {
    type Error = crate::Error;

    fn try_from(v: &Value) -> Result<Self, Self::Error> {
        let d = v
            .as_civil_date()
            .ok_or_else(|| crate::Error::protocol("expected a DATE/TIMESTAMP value"))?;
        chrono::NaiveDate::from_ymd_opt(d.year, d.month, d.day)
            .ok_or_else(|| crate::Error::protocol("DATE value is out of chrono range"))
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<Value> for chrono::NaiveDate {
    type Error = crate::Error;

    fn try_from(v: Value) -> Result<Self, Self::Error> {
        chrono::NaiveDate::try_from(&v)
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<&Value> for chrono::NaiveTime {
    type Error = crate::Error;

    fn try_from(v: &Value) -> Result<Self, Self::Error> {
        let t = v
            .as_civil_time()
            .ok_or_else(|| crate::Error::protocol("expected a TIME/TIMESTAMP value"))?;
        chrono::NaiveTime::from_hms_nano_opt(t.hour, t.minute, t.second, t.nanos())
            .ok_or_else(|| crate::Error::protocol("TIME value is out of chrono range"))
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<Value> for chrono::NaiveTime {
    type Error = crate::Error;

    fn try_from(v: Value) -> Result<Self, Self::Error> {
        chrono::NaiveTime::try_from(&v)
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<&Value> for chrono::NaiveDateTime {
    type Error = crate::Error;

    fn try_from(v: &Value) -> Result<Self, Self::Error> {
        let ts = v
            .as_civil_timestamp()
            .ok_or_else(|| crate::Error::protocol("expected a TIMESTAMP value"))?;
        let date = chrono::NaiveDate::from_ymd_opt(ts.date.year, ts.date.month, ts.date.day)
            .ok_or_else(|| crate::Error::protocol("TIMESTAMP date is out of chrono range"))?;
        date.and_hms_nano_opt(
            ts.time.hour,
            ts.time.minute,
            ts.time.second,
            ts.time.nanos(),
        )
        .ok_or_else(|| crate::Error::protocol("TIMESTAMP time is out of chrono range"))
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<Value> for chrono::NaiveDateTime {
    type Error = crate::Error;

    fn try_from(v: Value) -> Result<Self, Self::Error> {
        chrono::NaiveDateTime::try_from(&v)
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
    /// Sub-tipo Firebird. Para texto pode indicar charset; para BLOB indica o sub-tipo do BLOB.
    pub sub_type: i32,
    /// Escala de tipos numéricos (`NUMERIC`/`DECIMAL`); valores negativos indicam casas decimais.
    pub scale: i32,
    /// Comprimento declarado em bytes (CHAR/VARCHAR) ou largura do tipo.
    pub length: i32,
    /// Verdadeiro se a coluna ou parâmetro aceita `NULL`.
    pub nullable: bool,
    /// Nome subjacente da coluna.
    pub field: String,
    /// Nome da relação/tabela de origem, quando o servidor informa.
    pub relation: String,
    /// Alias de saída (o nome que a lista SELECT deu a ela).
    pub alias: String,
    /// Dono da relação de origem, quando o servidor informa.
    pub owner: String,
}

impl ColumnMeta {
    /// O nome que os chamadores veem para esta coluna (alias se presente, senão field).
    pub fn name(&self) -> &str {
        if self.alias.is_empty() {
            &self.field
        } else {
            &self.alias
        }
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
            sql_type::BLOB | sql_type::QUAD | sql_type::ARRAY => 8,
            sql_type::BOOLEAN => 4,
            sql_type::DEC16 => 8,
            sql_type::DEC34 => 16,
            // Formato estendido (`_EX`) pedido na saída: 3 ou 4 inteiros XDR.
            sql_type::TIME_TZ | sql_type::TIME_TZ_EX => 12,
            sql_type::TIMESTAMP_TZ | sql_type::TIMESTAMP_TZ_EX => 16,
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
            Some(CivilDate {
                year: 1858,
                month: 11,
                day: 17
            })
        );
        // A época Unix em dias do Firebird = 40587.
        assert_eq!(
            Value::Date(40_587).as_civil_date(),
            Some(CivilDate {
                year: 1970,
                month: 1,
                day: 1
            })
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
            assert_eq!(
                v.as_civil_date(),
                Some(CivilDate {
                    year: y,
                    month: m,
                    day: d
                })
            );
        }
    }

    #[test]
    fn time_roundtrip() {
        // Meia-noite.
        assert_eq!(
            Value::Time(0).as_civil_time(),
            Some(CivilTime {
                hour: 0,
                minute: 0,
                second: 0,
                frac: 0
            })
        );
        // 23:59:59 e 0.9999 s = (23*3600+59*60+59)*10000 + 9999.
        let raw = (23 * 3600 + 59 * 60 + 59) * 10_000 + 9999;
        assert_eq!(
            Value::Time(raw).as_civil_time(),
            Some(CivilTime {
                hour: 23,
                minute: 59,
                second: 59,
                frac: 9999
            })
        );
        let v = Value::time(13, 45, 30, 1234);
        let ct = v.as_civil_time().unwrap();
        assert_eq!((ct.hour, ct.minute, ct.second, ct.frac), (13, 45, 30, 1234));
        assert_eq!(ct.nanos(), 123_400_000);
    }

    #[test]
    fn timestamp_splits_date_and_time() {
        let date = CivilDate {
            year: 2026,
            month: 6,
            day: 20,
        };
        let time = CivilTime {
            hour: 9,
            minute: 30,
            second: 15,
            frac: 0,
        };
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

    #[test]
    fn value_from_rust_primitives() {
        assert_eq!(Value::from(true), Value::Bool(true));
        assert_eq!(Value::from(7_i16), Value::Short(7));
        assert_eq!(Value::from(42_i32), Value::Int(42));
        assert_eq!(Value::from(99_i64), Value::BigInt(99));
        assert_eq!(Value::from(123_i128), Value::Int128(123));
        assert_eq!(Value::from(1.5_f32), Value::Float(1.5));
        assert_eq!(Value::from(2.5_f64), Value::Double(2.5));
        assert_eq!(Value::from("Ana"), Value::Text("Ana".to_string()));
        assert_eq!(
            Value::from("Bruno".to_string()),
            Value::Text("Bruno".to_string())
        );
        assert_eq!(Value::from(vec![1_u8, 2, 3]), Value::Bytes(vec![1, 2, 3]));
        assert_eq!(Value::from(&[4_u8, 5][..]), Value::Bytes(vec![4, 5]));
    }

    #[test]
    fn value_ref_borrows_text_and_bytes() {
        let text = String::from("Ana");
        let bytes = vec![1_u8, 2, 3];
        let owned = Value::Text(text.clone());

        assert_eq!(ValueRef::from("Ana"), ValueRef::Text("Ana"));
        assert_eq!(ValueRef::from(&text), ValueRef::Text("Ana"));
        assert_eq!(ValueRef::from(&bytes), ValueRef::Bytes(&[1, 2, 3]));
        assert_eq!(ValueRef::from(&owned), ValueRef::Text("Ana"));
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_naive_values_convert_to_driver_values() {
        use chrono::{NaiveDate, NaiveDateTime, NaiveTime};

        let date = NaiveDate::from_ymd_opt(2026, 6, 23).unwrap();
        assert_eq!(Value::from(date), Value::date(2026, 6, 23));

        let time = NaiveTime::from_hms_nano_opt(14, 5, 6, 123_456_789).unwrap();
        assert_eq!(Value::from(time), Value::time(14, 5, 6, 1234));

        let timestamp = NaiveDateTime::new(date, time);
        assert_eq!(
            Value::from(timestamp),
            Value::timestamp(
                CivilDate {
                    year: 2026,
                    month: 6,
                    day: 23
                },
                CivilTime {
                    hour: 14,
                    minute: 5,
                    second: 6,
                    frac: 1234
                }
            )
        );
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_naive_values_convert_from_driver_values() {
        use chrono::{NaiveDate, NaiveDateTime, NaiveTime};

        let date = NaiveDate::try_from(&Value::date(2026, 6, 23)).unwrap();
        assert_eq!(date, NaiveDate::from_ymd_opt(2026, 6, 23).unwrap());

        let time = NaiveTime::try_from(&Value::time(14, 5, 6, 1234)).unwrap();
        assert_eq!(
            time,
            NaiveTime::from_hms_nano_opt(14, 5, 6, 123_400_000).unwrap()
        );

        let timestamp = Value::timestamp(
            CivilDate {
                year: 2026,
                month: 6,
                day: 23,
            },
            CivilTime {
                hour: 14,
                minute: 5,
                second: 6,
                frac: 1234,
            },
        );
        let timestamp = NaiveDateTime::try_from(&timestamp).unwrap();
        assert_eq!(
            timestamp,
            NaiveDate::from_ymd_opt(2026, 6, 23)
                .unwrap()
                .and_hms_nano_opt(14, 5, 6, 123_400_000)
                .unwrap()
        );
    }
}
