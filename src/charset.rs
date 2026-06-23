//! Decodificação de texto conforme o charset da conexão.
//!
//! O servidor Firebird *translitera* os dados de caractere para o charset da
//! conexão (definido no DPB) antes de enviá-los. Portanto os bytes no wire estão
//! no charset da conexão — não no charset declarado da coluna. Decodificamos
//! aqui de acordo com o charset da conexão; colunas `OCTETS` (binárias) são
//! tratadas à parte em `message.rs` e permanecem como bytes.
//!
//! Suportamos UTF-8 (padrão), ISO-8859-1 (Latin-1) e Windows-1252 nativamente.
//! Com a feature `charset-full`, charsets multibyte (SJIS, EUC-JP, GBK, Big5,
//! GB18030, EUC-KR) e vários single-byte adicionais (KOI8, ISO-8859-*,
//! Windows-125x) são suportados via `encoding_rs`. Qualquer nome não reconhecido
//! recai em UTF-8 com perdas (`from_utf8_lossy`).

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
    /// Um charset resolvido via `encoding_rs` (feature `charset-full`): cobre os
    /// multibyte (SJIS/EUC/GBK/Big5/…) e single-byte adicionais.
    #[cfg(feature = "charset-full")]
    Encoding(&'static encoding_rs::Encoding),
    /// Code page DOS/OEM single-byte (CP437/850/852/860/…): bytes `< 0x80` são
    /// ASCII; `0x80..=0xFF` seguem a tabela embutida. Sempre disponível.
    Dos(&'static [char; 128]),
    /// Charset não reconhecido: decodifica como UTF-8 com perdas.
    Unknown,
}

impl Charset {
    /// Resolve a partir do nome do charset da conexão (ex.: `"UTF8"`,
    /// `"WIN1252"`, `"ISO8859_1"`, `"SJIS_0208"`). A comparação ignora caixa e
    /// separadores (`-`, `_`). Os multibyte e single-byte extras só resolvem com
    /// a feature `charset-full`; sem ela viram [`Charset::Unknown`] (UTF-8 com
    /// perdas).
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
            other => match dos_table(other) {
                Some(table) => Charset::Dos(table),
                None => Self::resolve_extra(other),
            },
        }
    }

    /// Resolve nomes além dos embutidos. Com `charset-full`, mapeia o nome do
    /// charset do Firebird para um rótulo WHATWG e consulta o `encoding_rs`.
    #[cfg(feature = "charset-full")]
    fn resolve_extra(normalized: &str) -> Self {
        match whatwg_label(normalized) {
            Some(label) => match encoding_rs::Encoding::for_label(label.as_bytes()) {
                Some(enc) => Charset::Encoding(enc),
                None => Charset::Unknown,
            },
            None => Charset::Unknown,
        }
    }

    #[cfg(not(feature = "charset-full"))]
    fn resolve_extra(_normalized: &str) -> Self {
        Charset::Unknown
    }

    /// Decodifica bytes para `String` conforme o charset.
    pub fn decode(self, raw: &[u8]) -> String {
        match self {
            Charset::Utf8 | Charset::Unknown => String::from_utf8_lossy(raw).into_owned(),
            Charset::Latin1 => raw.iter().map(|&b| b as char).collect(),
            Charset::Win1252 => raw.iter().map(|&b| win1252_char(b)).collect(),
            #[cfg(feature = "charset-full")]
            Charset::Encoding(enc) => enc.decode(raw).0.into_owned(),
            Charset::Dos(table) => raw
                .iter()
                .map(|&b| {
                    if b < 0x80 {
                        b as char
                    } else {
                        table[(b - 0x80) as usize]
                    }
                })
                .collect(),
        }
    }

    /// Codifica uma `&str` para bytes conforme o charset (o inverso de
    /// [`Self::decode`]), para enviar parâmetros de texto ao servidor numa conexão
    /// não-UTF8. Para Latin-1/Win-1252, caracteres não representáveis viram `?`;
    /// para os charsets do `encoding_rs`, viram referências numéricas HTML
    /// (`&#N;`), conforme o comportamento da biblioteca.
    pub fn encode(self, s: &str) -> Vec<u8> {
        match self {
            Charset::Utf8 | Charset::Unknown => s.as_bytes().to_vec(),
            Charset::Latin1 => s
                .chars()
                .map(|c| if (c as u32) <= 0xFF { c as u8 } else { b'?' })
                .collect(),
            Charset::Win1252 => s.chars().map(win1252_byte).collect(),
            #[cfg(feature = "charset-full")]
            Charset::Encoding(enc) => enc.encode(s).0.into_owned(),
            Charset::Dos(table) => s
                .chars()
                .map(|c| {
                    if (c as u32) < 0x80 {
                        c as u8
                    } else {
                        // Busca reversa na tabela de 128 entradas (alta).
                        table
                            .iter()
                            .position(|&t| t == c)
                            .map_or(b'?', |i| (i + 0x80) as u8)
                    }
                })
                .collect(),
        }
    }
}

/// Resolve um nome de charset DOS/OEM do Firebird (já normalizado) para a tabela
/// de code page embutida. `None` para nomes não-DOS.
fn dos_table(n: &str) -> Option<&'static [char; 128]> {
    use crate::dos::*;
    Some(match n {
        "DOS437" => &CP437,
        "DOS737" => &CP737,
        "DOS775" => &CP775,
        "DOS850" => &CP850,
        "DOS852" => &CP852,
        "DOS855" => &CP855,
        "DOS857" => &CP857,
        "DOS858" => &CP858,
        "DOS860" => &CP860,
        "DOS861" => &CP861,
        "DOS862" => &CP862,
        "DOS863" => &CP863,
        "DOS864" => &CP864,
        "DOS865" => &CP865,
        "DOS866" => &CP866,
        "DOS869" => &CP869,
        _ => return None,
    })
}

/// Mapeia um nome de charset do Firebird (já normalizado: alfanumérico,
/// maiúsculo) para o rótulo WHATWG que o `encoding_rs` entende. Devolve `None`
/// para nomes sem suporte conhecido (que então recaem em UTF-8 com perdas).
#[cfg(feature = "charset-full")]
fn whatwg_label(n: &str) -> Option<&'static str> {
    // Famílias com parte numérica: ISO8859_N e WIN125x derivam o rótulo direto.
    if let Some(num) = n.strip_prefix("ISO8859") {
        // O Firebird vai de ISO8859_1 a _16 (sem _12). encoding_rs usa
        // "iso-8859-N" exceto o 1 (Latin-1, já tratado antes daqui).
        return match num {
            "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10" | "13" | "14" | "15" | "16" => {
                Some(match num {
                    "2" => "iso-8859-2",
                    "3" => "iso-8859-3",
                    "4" => "iso-8859-4",
                    "5" => "iso-8859-5",
                    "6" => "iso-8859-6",
                    "7" => "iso-8859-7",
                    "8" => "iso-8859-8",
                    "9" => "iso-8859-9", // alias de windows-1254 no WHATWG
                    "10" => "iso-8859-10",
                    "13" => "iso-8859-13",
                    "14" => "iso-8859-14",
                    "15" => "iso-8859-15",
                    _ => "iso-8859-16",
                })
            }
            _ => None,
        };
    }
    Some(match n {
        // Japonês.
        "SJIS0208" | "SJIS" | "SHIFTJIS" => "shift_jis",
        "EUCJ0208" | "EUCJP" => "euc-jp",
        // Coreano.
        "KSC5601" | "EUCKR" => "euc-kr",
        // Chinês.
        "GB2312" | "GBK" => "gbk",
        "GB18030" => "gb18030",
        "BIG5" => "big5",
        // Cirílico e outros single-byte.
        "KOI8R" => "koi8-r",
        "KOI8U" => "koi8-u",
        "TIS620" => "windows-874",
        "WIN1250" => "windows-1250",
        "WIN1251" => "windows-1251",
        "WIN1253" => "windows-1253",
        "WIN1254" => "windows-1254",
        "WIN1255" => "windows-1255",
        "WIN1256" => "windows-1256",
        "WIN1257" => "windows-1257",
        "WIN1258" => "windows-1258",
        _ => return None,
    })
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
        // Um nome que nunca é reconhecido, com ou sem a feature `charset-full`.
        assert_eq!(Charset::from_name("NOSUCHCHARSET"), Charset::Unknown);
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

    #[test]
    fn dos_code_pages_resolve_and_roundtrip() {
        // Disponíveis SEM a feature charset-full (são tabelas embutidas).
        assert!(matches!(Charset::from_name("DOS850"), Charset::Dos(_)));
        assert!(matches!(Charset::from_name("DOS437"), Charset::Dos(_)));
        // CP850: 0x82 = 'é', 0xA5 = 'Ñ'; ASCII passa direto.
        let cp850 = Charset::from_name("DOS850");
        assert_eq!(cp850.decode(&[0x41, 0x82, 0xA5]), "Aé\u{D1}");
        assert_eq!(cp850.encode("Aé\u{D1}"), vec![0x41, 0x82, 0xA5]);
        // CP860 (português): 0x84 = 'ã', 0x85 = 'à', 0x94 = 'õ'.
        let cp860 = Charset::from_name("DOS860");
        assert_eq!(cp860.decode(&[0x84, 0x85, 0x94]), "ãàõ");
        assert_eq!(cp860.encode("ãàõ"), vec![0x84, 0x85, 0x94]);
        // Caractere fora da code page vira '?'.
        assert_eq!(cp850.encode("€"), b"?");
    }

    #[cfg(not(feature = "charset-full"))]
    #[test]
    fn multibyte_without_feature_is_unknown() {
        // Sem a feature, SJIS/EUC não resolvem e recaem em UTF-8 com perdas.
        assert_eq!(Charset::from_name("SJIS_0208"), Charset::Unknown);
        assert_eq!(Charset::from_name("EUCJ_0208"), Charset::Unknown);
    }

    #[cfg(feature = "charset-full")]
    mod full {
        use super::*;

        #[test]
        fn resolves_multibyte_names() {
            // Os nomes do Firebird viram um Charset::Encoding concreto.
            for name in [
                "SJIS_0208",
                "EUCJ_0208",
                "GBK",
                "BIG_5",
                "WIN1251",
                "ISO8859_2",
            ] {
                assert!(
                    matches!(Charset::from_name(name), Charset::Encoding(_)),
                    "{name} não resolveu para encoding_rs"
                );
            }
        }

        #[test]
        fn shift_jis_roundtrip() {
            let sjis = Charset::from_name("SJIS_0208");
            // 日本語 em Shift-JIS.
            let bytes = sjis.encode("日本語");
            assert_eq!(bytes, vec![0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea]);
            assert_eq!(sjis.decode(&bytes), "日本語");
        }

        #[test]
        fn win1251_decode_cyrillic() {
            let cp = Charset::from_name("WIN1251");
            // 0xCF 0xF0 0xE8 0xE2 0xE5 0xF2 = "Привет" parcial; checa um caractere.
            assert_eq!(cp.decode(&[0xcf]), "П");
        }

        #[test]
        fn iso8859_15_euro() {
            // No ISO-8859-15, 0xA4 é o símbolo do euro (difere do 8859-1).
            assert_eq!(Charset::from_name("ISO8859_15").decode(&[0xA4]), "€");
        }
    }
}
