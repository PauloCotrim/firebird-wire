//! Decodificação de `DECFLOAT(16)`/`DECFLOAT(34)` do Firebird — os formatos de
//! ponto flutuante decimal IEEE 754-2008 *decimal64* e *decimal128*, com o
//! coeficiente em **DPD** (Densely Packed Decimal).
//!
//! O valor é `(-1)^sinal · coeficiente · 10^expoente`. O campo de combinação de
//! 5 bits codifica o dígito mais significativo e os 2 bits altos do expoente
//! enviesado; o restante são a continuação do expoente e os *declets* DPD (cada
//! declet = 10 bits → 3 dígitos decimais). Ver IEEE 754-2008 §3.5 e a
//! especificação de aritmética decimal de Mike Cowlishaw.

use std::fmt;

/// Um valor `DECFLOAT` decodificado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecFloat {
    negative: bool,
    kind: DecKind,
    /// Coeficiente (significando) como inteiro; o valor é `coefficient · 10^exponent`.
    coefficient: u128,
    exponent: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecKind {
    Finite,
    Infinity,
    /// NaN silencioso (quiet) ou sinalizador (signaling) — não distinguimos aqui.
    NaN,
}

impl DecFloat {
    /// Decodifica um `DECFLOAT(16)` (decimal64, 8 bytes) na ordem em que o
    /// Firebird o transmite (big-endian, como o INT128).
    pub fn from_decimal64(bytes: [u8; 8]) -> DecFloat {
        decode(u64::from_be_bytes(bytes) as u128, 64)
    }

    /// Decodifica um `DECFLOAT(34)` (decimal128, 16 bytes), big-endian.
    pub fn from_decimal128(bytes: [u8; 16]) -> DecFloat {
        decode(u128::from_be_bytes(bytes), 128)
    }

    /// Se é negativo (inclui `-0` e `-Infinity`).
    pub fn is_negative(&self) -> bool {
        self.negative
    }

    /// Se é um valor finito (não Infinity nem NaN).
    pub fn is_finite(&self) -> bool {
        self.kind == DecKind::Finite
    }

    /// Se é `NaN` (not a number).
    pub fn is_nan(&self) -> bool {
        self.kind == DecKind::NaN
    }

    /// Se é `Infinity` ou `-Infinity`.
    pub fn is_infinite(&self) -> bool {
        self.kind == DecKind::Infinity
    }

    /// O coeficiente e o expoente de base 10 (`valor = ±coefficient·10^exponent`),
    /// para valores finitos.
    pub fn to_parts(&self) -> Option<(bool, u128, i32)> {
        self.is_finite()
            .then_some((self.negative, self.coefficient, self.exponent))
    }

    /// Constrói um valor finito `(-1)^negative · coefficient · 10^exponent`.
    pub fn from_parts(negative: bool, coefficient: u128, exponent: i32) -> DecFloat {
        DecFloat {
            negative,
            kind: DecKind::Finite,
            coefficient,
            exponent,
        }
    }

    /// `±Infinity`.
    pub fn infinity(negative: bool) -> DecFloat {
        DecFloat {
            negative,
            kind: DecKind::Infinity,
            coefficient: 0,
            exponent: 0,
        }
    }

    /// `NaN` (quiet).
    pub fn nan() -> DecFloat {
        DecFloat {
            negative: false,
            kind: DecKind::NaN,
            coefficient: 0,
            exponent: 0,
        }
    }

    /// Codifica como `DECFLOAT(16)` (decimal64, 8 bytes big-endian, como o
    /// Firebird espera). `None` se o valor não couber em decimal64 (mais de 16
    /// dígitos significativos ou expoente fora de faixa).
    pub fn to_decimal64(&self) -> Option<[u8; 8]> {
        Some((self.encode_bits(64)? as u64).to_be_bytes())
    }

    /// Codifica como `DECFLOAT(34)` (decimal128, 16 bytes big-endian).
    pub fn to_decimal128(&self) -> Option<[u8; 16]> {
        Some(self.encode_bits(128)?.to_be_bytes())
    }

    fn encode_bits(&self, width: u32) -> Option<u128> {
        match self.kind {
            DecKind::Finite => encode(self.negative, self.coefficient, self.exponent, width),
            DecKind::Infinity => Some(special_bits(self.negative, 0b1_1110, width)),
            DecKind::NaN => Some(special_bits(self.negative, 0b1_1111, width)),
        }
    }
}

/// Erro ao analisar uma string em [`DecFloat`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDecFloatError;

impl fmt::Display for ParseDecFloatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("string DECFLOAT inválida")
    }
}

impl std::error::Error for ParseDecFloatError {}

impl std::str::FromStr for DecFloat {
    type Err = ParseDecFloatError;

    /// Analisa um decimal como `-123.45`, `1.5E-3`, `Infinity`/`-Inf`/`NaN`.
    /// Preserva os dígitos exatos (os zeros à direita são significativos).
    fn from_str(s: &str) -> Result<DecFloat, ParseDecFloatError> {
        let t = s.trim();
        let (negative, body) = match t.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, t.strip_prefix('+').unwrap_or(t)),
        };
        match body.to_ascii_lowercase().as_str() {
            "inf" | "infinity" => return Ok(DecFloat::infinity(negative)),
            "nan" => return Ok(DecFloat::nan()),
            "" => return Err(ParseDecFloatError),
            _ => {}
        }
        // Separa a mantissa do expoente científico opcional.
        let (mantissa, exp_part) = match body.split_once(['e', 'E']) {
            Some((m, e)) => (m, e.parse::<i32>().map_err(|_| ParseDecFloatError)?),
            None => (body, 0),
        };
        let (int_part, frac_part) = match mantissa.split_once('.') {
            Some((i, f)) => (i, f),
            None => (mantissa, ""),
        };
        if int_part.is_empty() && frac_part.is_empty() {
            return Err(ParseDecFloatError);
        }
        let mut digits = String::with_capacity(int_part.len() + frac_part.len());
        digits.push_str(int_part);
        digits.push_str(frac_part);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseDecFloatError);
        }
        let coefficient: u128 = digits.parse().map_err(|_| ParseDecFloatError)?;
        let exponent = exp_part - frac_part.len() as i32;
        Ok(DecFloat::from_parts(negative, coefficient, exponent))
    }
}

/// Bits de um valor especial (Infinity/NaN): só o campo de combinação e o sinal.
fn special_bits(negative: bool, combo: u128, width: u32) -> u128 {
    ((negative as u128) << (width - 1)) | (combo << (width - 6))
}

/// Inverso de [`decode`]: monta os bits decimal64/decimal128 de um valor finito.
/// `None` se o coeficiente tiver dígitos demais ou o expoente sair da faixa.
fn encode(negative: bool, coefficient: u128, exponent: i32, width: u32) -> Option<u128> {
    let (ecbits, declets, bias) = match width {
        64 => (8u32, 5u32, 398i32),
        _ => (12u32, 11u32, 6176i32), // 128
    };
    let total_digits = (3 * declets + 1) as usize;
    let digits = coefficient.to_string();
    if digits.len() > total_digits {
        return None; // coeficiente não cabe nesta largura
    }
    let biased = exponent.checked_add(bias)?;
    let max_biased = (1i32 << (ecbits + 2)) - 1;
    if !(0..=max_biased).contains(&biased) {
        return None; // expoente fora de faixa
    }
    let biased = biased as u32;

    // Dígitos com zeros à esquerda até a largura total (MSD + declets×3).
    let mut padded = vec![0u8; total_digits - digits.len()];
    padded.extend(digits.bytes().map(|b| b - b'0'));

    let msd = padded[0] as u32;
    let exp_top2 = (biased >> ecbits) & 0b11;
    let econ = biased & ((1 << ecbits) - 1);
    let combo = if msd <= 7 {
        (exp_top2 << 3) | msd
    } else {
        0b1_1000 | (exp_top2 << 1) | (msd & 1)
    };

    let mut bits: u128 = 0;
    bits |= (negative as u128) << (width - 1);
    bits |= (combo as u128) << (width - 6);
    bits |= (econ as u128) << (width - 6 - ecbits);
    for i in 0..declets as usize {
        let g = &padded[1 + i * 3..1 + i * 3 + 3];
        let dpd = bcd_to_dpd(g[0] as u16, g[1] as u16, g[2] as u16) as u128;
        let bit = ((declets as usize - 1 - i) * 10) as u32;
        bits |= dpd << bit;
    }
    Some(bits)
}

impl fmt::Display for DecFloat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            DecKind::Infinity => f.write_str(if self.negative {
                "-Infinity"
            } else {
                "Infinity"
            }),
            DecKind::NaN => f.write_str("NaN"),
            DecKind::Finite => {
                if self.negative {
                    f.write_str("-")?;
                }
                f.write_str(&render_finite(self.coefficient, self.exponent))
            }
        }
    }
}

/// Renderiza `coefficient · 10^exponent` como uma string decimal simples,
/// preservando os zeros à direita significativos (o DECFLOAT os mantém).
fn render_finite(coefficient: u128, exponent: i32) -> String {
    let digits = coefficient.to_string();
    if exponent >= 0 {
        // Inteiro: acrescenta `exponent` zeros.
        let mut s = digits;
        s.extend(std::iter::repeat_n('0', exponent as usize));
        s
    } else {
        let frac = (-exponent) as usize;
        if digits.len() > frac {
            // Insere o ponto a `frac` casas a partir da direita.
            let point = digits.len() - frac;
            format!("{}.{}", &digits[..point], &digits[point..])
        } else {
            // 0.000… com zeros à esquerda para completar a parte fracionária.
            let zeros = frac - digits.len();
            format!("0.{}{}", "0".repeat(zeros), digits)
        }
    }
}

/// Decodifica o campo de bits de 64 ou 128 bits (MSB = sinal) em [`DecFloat`].
fn decode(bits: u128, width: u32) -> DecFloat {
    let (ecbits, declets, bias) = match width {
        64 => (8u32, 5u32, 398i32),
        _ => (12u32, 11u32, 6176i32), // 128
    };
    let negative = (bits >> (width - 1)) & 1 == 1;
    let combo = ((bits >> (width - 6)) & 0x1F) as u32;

    // Campo de combinação: dígito mais significativo + 2 bits altos do expoente,
    // ou marcador de Infinity/NaN.
    let (msd, exp_top2) = if combo >> 3 == 0b11 {
        if (combo >> 1) & 0b1111 == 0b1111 {
            // 11110 = Infinity, 11111 = NaN.
            let kind = if combo & 1 == 0 {
                DecKind::Infinity
            } else {
                DecKind::NaN
            };
            return DecFloat {
                negative,
                kind,
                coefficient: 0,
                exponent: 0,
            };
        }
        // MSD é 8 ou 9; os 2 bits altos do expoente são (combo>>1)&0b11.
        (8 + (combo & 1), (combo >> 1) & 0b11)
    } else {
        // MSD é 0..=7 (bits baixos); os 2 bits altos do expoente são (combo>>3)&0b11.
        (combo & 0b111, (combo >> 3) & 0b11)
    };

    let econ = ((bits >> (width - 6 - ecbits)) & ((1u128 << ecbits) - 1)) as u32;
    let biased_exp = ((exp_top2 << ecbits) | econ) as i32;
    let exponent = biased_exp - bias;

    // Coeficiente: o MSD seguido de cada declet (3 dígitos) decodificado de DPD.
    let coef_bits = width - 6 - ecbits; // = declets * 10
    let mut coefficient = msd as u128;
    for d in (0..declets).rev() {
        let dpd = ((bits >> (d * 10)) & 0x3FF) as u16;
        debug_assert!((d * 10) < coef_bits);
        coefficient = coefficient * 1000 + dpd_to_int(dpd) as u128;
    }

    DecFloat {
        negative,
        kind: DecKind::Finite,
        coefficient,
        exponent,
    }
}

/// Decodifica um declet DPD de 10 bits nos seus três dígitos decimais (0..=999),
/// via a tabela construída a partir do codificador canônico BCD→DPD.
fn dpd_to_int(dpd: u16) -> u16 {
    DPD_DECODE[dpd as usize & 0x3FF]
}

/// Tabela de decodificação DPD (1024 entradas), construída uma vez invertendo o
/// codificador [`bcd_to_dpd`]. Códigos não canônicos ficam em 0 (o Firebird só
/// emite formas canônicas).
static DPD_DECODE: std::sync::LazyLock<[u16; 1024]> = std::sync::LazyLock::new(|| {
    let mut table = [0u16; 1024];
    for n in 0u16..1000 {
        let (d2, d1, d0) = (n / 100, (n / 10) % 10, n % 10);
        table[bcd_to_dpd(d2, d1, d0) as usize] = n;
    }
    table
});

/// Codifica três dígitos decimais (`d2` mais significativo) em um declet DPD de
/// 10 bits, conforme a tabela canônica de codificação (IEEE 754-2008 / Cowlishaw).
fn bcd_to_dpd(d2: u16, d1: u16, d0: u16) -> u16 {
    // Bits BCD de cada dígito (8s, 4s, 2s, 1s).
    let (a, b, c, dd) = ((d2 >> 3) & 1, (d2 >> 2) & 1, (d2 >> 1) & 1, d2 & 1);
    let (e, f, g, h) = ((d1 >> 3) & 1, (d1 >> 2) & 1, (d1 >> 1) & 1, d1 & 1);
    let (i, j, k, m) = ((d0 >> 3) & 1, (d0 >> 2) & 1, (d0 >> 1) & 1, d0 & 1);
    let aei = (a << 2) | (e << 1) | i;
    // Saída como (b9 b8 b7 | b6 b5 b4 | b3 | b2 b1 b0).
    let (p, q, r, s, t, u, v, x, y, z) = match aei {
        0b000 => (b, c, dd, f, g, h, 0, j, k, m),
        0b001 => (b, c, dd, f, g, h, 1, 0, 0, m),
        0b010 => (b, c, dd, j, k, h, 1, 0, 1, m),
        0b011 => (b, c, dd, 1, 0, h, 1, 1, 1, m),
        0b100 => (j, k, dd, f, g, h, 1, 1, 0, m),
        0b101 => (f, g, dd, 0, 1, h, 1, 1, 1, m),
        0b110 => (j, k, dd, 0, 0, h, 1, 1, 1, m),
        _ => (0, 0, dd, 1, 1, h, 1, 1, 1, m), // 0b111
    };
    (p << 9)
        | (q << 8)
        | (r << 7)
        | (s << 6)
        | (t << 5)
        | (u << 4)
        | (v << 3)
        | (x << 2)
        | (y << 1)
        | z
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpd_roundtrip_all_declets() {
        // Todo dígito 0..=999 codifica e decodifica de volta a si mesmo.
        for n in 0u16..1000 {
            let (d2, d1, d0) = (n / 100, (n / 10) % 10, n % 10);
            let dpd = bcd_to_dpd(d2, d1, d0);
            assert_eq!(dpd_to_int(dpd), n, "falhou para {n}");
        }
    }

    #[test]
    fn dpd_known_anchors() {
        // Vetores canônicos conhecidos da especificação DPD.
        assert_eq!(bcd_to_dpd(0, 0, 5), 0b00_0000_0101); // 005 -> 0x005
        assert_eq!(bcd_to_dpd(0, 0, 9), 0b00_0000_1001); // 009 -> 0x009
        // 765: dígitos < 8 viram a concatenação direta dos 3 bits baixos:
        // (111)(110)(0)(101) = 0b11_1110_0101.
        assert_eq!(bcd_to_dpd(7, 6, 5), 0b11_1110_0101);
        assert_eq!(bcd_to_dpd(9, 9, 9), 0b00_1111_1111); // 999 -> 0x0FF
    }

    #[test]
    fn render_places_decimal_point() {
        assert_eq!(render_finite(12345, -2), "123.45");
        assert_eq!(render_finite(100, -2), "1.00");
        assert_eq!(render_finite(5, -4), "0.0005");
        assert_eq!(render_finite(5, 3), "5000");
        assert_eq!(render_finite(0, 0), "0");
    }

    #[test]
    fn parse_and_roundtrip_encode_decode() {
        use std::str::FromStr;
        for s in [
            "0",
            "1",
            "123.45",
            "-3.14159",
            "100.00",
            "0.0005",
            "5000",
            "-0.0",
            "9999999999999999",
        ] {
            let d = DecFloat::from_str(s).unwrap();
            // decimal128 sempre cabe nestes exemplos; relê o mesmo texto.
            let back = DecFloat::from_decimal128(d.to_decimal128().unwrap());
            assert_eq!(back.to_string(), d.to_string(), "decimal128 falhou em {s}");
        }
        // decimal64 (16 dígitos) com casos que cabem.
        for s in ["123.45", "-3.14159", "0.0005", "1234567890123456"] {
            let d = DecFloat::from_str(s).unwrap();
            let back = DecFloat::from_decimal64(d.to_decimal64().unwrap());
            assert_eq!(back.to_string(), d.to_string(), "decimal64 falhou em {s}");
        }
    }

    #[test]
    fn parse_scientific_and_specials() {
        use std::str::FromStr;
        assert_eq!(DecFloat::from_str("1.5E-3").unwrap().to_string(), "0.0015");
        assert_eq!(DecFloat::from_str("12E3").unwrap().to_string(), "12000");
        assert!(DecFloat::from_str("Infinity").unwrap().is_infinite());
        assert!(DecFloat::from_str("-inf").unwrap().is_infinite());
        assert!(DecFloat::from_str("NaN").unwrap().is_nan());
        assert!(DecFloat::from_str("abc").is_err());
    }

    #[test]
    fn encode_overflow_returns_none() {
        // 17 dígitos não cabem em decimal64 (máx 16).
        let d = DecFloat::from_parts(false, 12_345_678_901_234_567, 0);
        assert!(d.to_decimal64().is_none());
        // Mas cabem em decimal128.
        assert!(d.to_decimal128().is_some());
    }

    #[test]
    fn encode_specials_roundtrip() {
        for d in [
            DecFloat::infinity(false),
            DecFloat::infinity(true),
            DecFloat::nan(),
        ] {
            let back = DecFloat::from_decimal128(d.to_decimal128().unwrap());
            assert_eq!(back.is_infinite(), d.is_infinite());
            assert_eq!(back.is_nan(), d.is_nan());
            assert_eq!(back.is_negative(), d.is_negative());
        }
    }

    #[test]
    fn decimal128_one() {
        // 1 em decimal128 = coeficiente 1, expoente 0 → expoente enviesado = bias.
        // combo "small": exp_top2 ocupa os 2 bits altos (3..4), MSD os 3 baixos.
        let bias = 6176u32; // 0x1820
        let exp_top2 = (bias >> 12) as u128; // 1
        let econ = (bias & 0xFFF) as u128; // 2080
        let combo = exp_top2 << 3; // MSD 0 nos 3 bits baixos
        let last_declet = bcd_to_dpd(0, 0, 1) as u128; // dígito 001
        let bits = (combo << (128 - 6)) | (econ << (128 - 6 - 12)) | last_declet;
        let d = decode(bits, 128);
        assert!(d.is_finite() && !d.is_negative());
        assert_eq!(d.to_parts(), Some((false, 1, 0)));
        assert_eq!(d.to_string(), "1");
    }
}
