//! Decodificação de texto conforme o charset da conexão.
//!
//! O servidor Firebird *translitera* os dados de caractere para o charset da
//! conexão (definido no DPB) antes de enviá-los. Portanto os bytes no wire estão
//! no charset da conexão — não no charset declarado da coluna. Decodificamos
//! aqui de acordo com o charset da conexão; colunas `OCTETS` (binárias) são
//! tratadas à parte em `message.rs` e permanecem como bytes.
//!
//! Suportamos UTF-8 (padrão), ISO-8859-1 (Latin-1) e Windows-1252 nativamente;
//! qualquer outro nome recai em UTF-8 com perdas (`from_utf8_lossy`).

/// Charset da conexão, usado para decodificar CHAR/VARCHAR vindos do servidor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Charset {
    /// UTF-8 (o padrão do driver). Também cobre `UNICODE_FSS`.
    #[default]
    Utf8,
    /// ISO-8859-1 (Latin-1): cada byte `0x00..=0xFF` é o code point `U+0000..=U+00FF`.
    Latin1,
    /// Windows-1252: como Latin-1, mas `0x80..=0x9F` têm mapeamento próprio.
    Win1252,
    /// Charset não reconhecido: decodifica como UTF-8 com perdas.
    Unknown,
}

impl Charset {
    /// Resolve a partir do nome do charset da conexão (ex.: `"UTF8"`,
    /// `"WIN1252"`, `"ISO8859_1"`). A comparação ignora caixa e separadores
    /// (`-`, `_`). Nomes não reconhecidos viram [`Charset::Unknown`].
    pub fn from_name(name: &str) -> Self {
        let n: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_uppercase())
            .collect();
        match n.as_str() {
            "UTF8" | "UNICODEFSS" => Charset::Utf8,
            "ISO88591" | "LATIN1" => Charset::Latin1,
            "WIN1252" | "WINDOWS1252" => Charset::Win1252,
            _ => Charset::Unknown,
        }
    }

    /// Decodifica bytes para `String` conforme o charset.
    pub fn decode(self, raw: &[u8]) -> String {
        match self {
            Charset::Utf8 | Charset::Unknown => String::from_utf8_lossy(raw).into_owned(),
            Charset::Latin1 => raw.iter().map(|&b| b as char).collect(),
            Charset::Win1252 => raw.iter().map(|&b| win1252_char(b)).collect(),
        }
    }

    /// Codifica uma `&str` para bytes conforme o charset (o inverso de
    /// [`Self::decode`]), para enviar parâmetros de texto ao servidor numa conexão
    /// não-UTF8. Caracteres não representáveis no charset alvo viram `?`.
    pub fn encode(self, s: &str) -> Vec<u8> {
        match self {
            Charset::Utf8 | Charset::Unknown => s.as_bytes().to_vec(),
            Charset::Latin1 => s
                .chars()
                .map(|c| if (c as u32) <= 0xFF { c as u8 } else { b'?' })
                .collect(),
            Charset::Win1252 => s.chars().map(win1252_byte).collect(),
        }
    }
}

/// Mapeia um byte Windows-1252 para `char`. Igual a Latin-1 fora de
/// `0x80..=0x9F`; nesse intervalo segue a tabela CP-1252 (posições não
/// atribuídas mapeiam para o controle C1 de mesmo valor).
fn win1252_char(b: u8) -> char {
    match b {
        0x80 => '\u{20AC}', // €
        0x82 => '\u{201A}', // ‚
        0x83 => '\u{0192}', // ƒ
        0x84 => '\u{201E}', // „
        0x85 => '\u{2026}', // …
        0x86 => '\u{2020}', // †
        0x87 => '\u{2021}', // ‡
        0x88 => '\u{02C6}', // ˆ
        0x89 => '\u{2030}', // ‰
        0x8A => '\u{0160}', // Š
        0x8B => '\u{2039}', // ‹
        0x8C => '\u{0152}', // Œ
        0x8E => '\u{017D}', // Ž
        0x91 => '\u{2018}', // '
        0x92 => '\u{2019}', // '
        0x93 => '\u{201C}', // "
        0x94 => '\u{201D}', // "
        0x95 => '\u{2022}', // •
        0x96 => '\u{2013}', // –
        0x97 => '\u{2014}', // —
        0x98 => '\u{02DC}', // ˜
        0x99 => '\u{2122}', // ™
        0x9A => '\u{0161}', // š
        0x9B => '\u{203A}', // ›
        0x9C => '\u{0153}', // œ
        0x9E => '\u{017E}', // ž
        0x9F => '\u{0178}', // Ÿ
        // < 0x80, posições não atribuídas em 0x80..0x9F, e >= 0xA0: como Latin-1.
        other => other as char,
    }
}

/// Mapeia um `char` para um byte Windows-1252 (inverso de [`win1252_char`]).
/// Caracteres fora do CP-1252 viram `?`.
fn win1252_byte(c: char) -> u8 {
    match c {
        '\u{20AC}' => 0x80,
        '\u{201A}' => 0x82,
        '\u{0192}' => 0x83,
        '\u{201E}' => 0x84,
        '\u{2026}' => 0x85,
        '\u{2020}' => 0x86,
        '\u{2021}' => 0x87,
        '\u{02C6}' => 0x88,
        '\u{2030}' => 0x89,
        '\u{0160}' => 0x8A,
        '\u{2039}' => 0x8B,
        '\u{0152}' => 0x8C,
        '\u{017D}' => 0x8E,
        '\u{2018}' => 0x91,
        '\u{2019}' => 0x92,
        '\u{201C}' => 0x93,
        '\u{201D}' => 0x94,
        '\u{2022}' => 0x95,
        '\u{2013}' => 0x96,
        '\u{2014}' => 0x97,
        '\u{02DC}' => 0x98,
        '\u{2122}' => 0x99,
        '\u{0161}' => 0x9A,
        '\u{203A}' => 0x9B,
        '\u{0153}' => 0x9C,
        '\u{017E}' => 0x9E,
        '\u{0178}' => 0x9F,
        // < 0x80 e 0xA0..=0xFF: igual a Latin-1 (o code point é o byte). As
        // posições C1 não atribuídas (0x81/0x8D/0x8F/0x90/0x9D) também caem aqui.
        c if (c as u32) <= 0xFF => c as u8,
        _ => b'?',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_resolution() {
        assert_eq!(Charset::from_name("UTF8"), Charset::Utf8);
        assert_eq!(Charset::from_name("utf-8"), Charset::Utf8);
        assert_eq!(Charset::from_name("ISO8859_1"), Charset::Latin1);
        assert_eq!(Charset::from_name("Latin1"), Charset::Latin1);
        assert_eq!(Charset::from_name("WIN1252"), Charset::Win1252);
        assert_eq!(Charset::from_name("KOI8R"), Charset::Unknown);
    }

    #[test]
    fn latin1_decode() {
        // 0xE9 = 'é' em Latin-1; 0xF1 = 'ñ'.
        assert_eq!(Charset::Latin1.decode(&[0x48, 0xE9, 0xF1]), "Héñ");
    }

    #[test]
    fn win1252_decode() {
        // 0x80 = €, 0x93/0x94 = aspas curvas, 0xE9 = é (igual Latin-1).
        assert_eq!(Charset::Win1252.decode(&[0x80]), "€");
        assert_eq!(Charset::Win1252.decode(&[0x93, 0x94]), "\u{201C}\u{201D}");
        assert_eq!(Charset::Win1252.decode(&[0xE9]), "é");
    }

    #[test]
    fn utf8_passthrough() {
        assert_eq!(Charset::Utf8.decode("café €".as_bytes()), "café €");
    }

    #[test]
    fn encode_inverts_decode() {
        for (cs, bytes) in [
            (Charset::Latin1, vec![0x48u8, 0xE9, 0xF1, 0x20, 0xFF]),
            (Charset::Win1252, vec![0x80, 0x93, 0x94, 0xE9, 0x97]),
        ] {
            let s = cs.decode(&bytes);
            assert_eq!(cs.encode(&s), bytes, "roundtrip falhou para {cs:?}");
        }
    }

    #[test]
    fn encode_unrepresentable_is_question_mark() {
        // '€' (U+20AC) não existe em Latin-1.
        assert_eq!(Charset::Latin1.encode("a€b"), b"a?b");
        // CJK fora de Win-1252.
        assert_eq!(Charset::Win1252.encode("x\u{4E00}y"), b"x?y");
    }
}
