//! Linha de resultado com acesso posicional ou por nome de coluna.

use std::fmt;
use std::sync::Arc;

use crate::error::Error;
use crate::value::{ColumnMeta, FromValue, Value};

/// Uma linha buscada de um cursor.
///
/// Suporta acesso posicional (`row[0]`, igual a um `Vec<Value>`) e por nome de
/// coluna (`row["nome"]`, `row.get::<_, T>("nome")`), comparando nomes sem
/// diferenciar maiúsculas/minúsculas — identificadores não citados do Firebird
/// sempre voltam do servidor em maiúsculas, então `"nome"` casa com a coluna
/// `NOME` sem o chamador precisar saber disso.
///
/// [`Self::get`] devolve o tipo Rust pedido diretamente (como em
/// `tokio-postgres`/`oracle`), via [`FromValue`], inferido do contexto:
///
/// ```no_run
/// # use firebird_wire::{Connection, Row};
/// # fn f(row: &Row) -> firebird_wire::Result<()> {
/// let id: i64 = row.get(0)?;
/// let nome: &str = row.get("nome")?;      // por nome, sem diferenciar caixa
/// let apelido: Option<String> = row.get("apelido")?; // NULL -> None
/// # Ok(()) }
/// ```
///
/// Cada `Row` compartilha (via [`Arc`]) a mesma lista de metadados de colunas
/// do [`crate::Statement`] que a gerou: criar uma `Row` custa só o clone do
/// vetor de valores já decodificado mais um incremento de contagem de
/// referência, não uma cópia dos metadados. O lookup por nome é uma busca
/// linear sobre essa lista — para uma query típica (poucas dezenas de
/// colunas), isso é desprezível perto do custo de rede/decodificação. Em um
/// laço muito quente com milhões de linhas, resolva o índice uma vez fora do
/// laço com [`Row::column_index`] (ou [`crate::Statement::columns`]) e use
/// [`Row::get`]/indexação por posição (`usize`) dentro dele.
#[derive(Debug, Clone)]
pub struct Row {
    values: Vec<Value>,
    columns: Arc<[ColumnMeta]>,
}

/// Compara só os valores — duas linhas com os mesmos valores são iguais mesmo
/// vindo de `Statement`s diferentes (`ColumnMeta` não implementa `PartialEq`).
impl PartialEq for Row {
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values
    }
}

/// Uma forma de indicar qual coluna ler em [`Row::get`]: posição (`usize`,
/// 0-based) ou nome (`&str`, sem diferenciar maiúsculas/minúsculas).
pub trait RowIndex: fmt::Display {
    #[doc(hidden)]
    fn resolve(&self, row: &Row) -> Option<usize>;
}

impl RowIndex for usize {
    fn resolve(&self, row: &Row) -> Option<usize> {
        (*self < row.len()).then_some(*self)
    }
}

impl RowIndex for &str {
    fn resolve(&self, row: &Row) -> Option<usize> {
        row.column_index(self)
    }
}

impl Row {
    pub(crate) fn new(values: Vec<Value>, columns: Arc<[ColumnMeta]>) -> Self {
        Self { values, columns }
    }

    /// Número de colunas na linha.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Verdadeiro se a linha não tem colunas (statement sem lista de saída).
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Metadados das colunas desta linha (os mesmos de [`crate::Statement::columns`]).
    pub fn columns(&self) -> &[ColumnMeta] {
        &self.columns
    }

    /// Índice da coluna cujo nome (alias ou campo, via [`ColumnMeta::name`])
    /// bate com `name` sem diferenciar maiúsculas/minúsculas, ou `None` se
    /// nenhuma coluna tiver esse nome.
    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.columns
            .iter()
            .position(|c| c.name().eq_ignore_ascii_case(name))
    }

    /// Lê a coluna em `idx` (posição `usize` ou nome `&str`) já convertida
    /// para o tipo `T` pedido pelo chamador — normalmente inferido do `let`,
    /// como `let nome: &str = row.get("nome")?;`.
    ///
    /// Erra se `idx` não existir na linha (nome desconhecido ou posição fora
    /// do intervalo), ou se o valor guardado não bater com `T` — o que inclui
    /// `NULL` quando `T` não é um `Option`; peça `Option<T>` para aceitar
    /// `NULL` como `None`. Veja os tipos que implementam [`FromValue`].
    pub fn get<'a, I, T>(&'a self, idx: I) -> crate::Result<T>
    where
        I: RowIndex,
        T: FromValue<'a>,
    {
        let i = idx
            .resolve(self)
            .ok_or_else(|| Error::protocol(format!("coluna `{idx}` não existe nesta linha")))?;
        T::from_value(&self.values[i])
    }

    /// Os valores da linha como slice, na ordem das colunas.
    pub fn values(&self) -> &[Value] {
        &self.values
    }

    /// Consome a linha, devolvendo o vetor de valores puro.
    pub fn into_values(self) -> Vec<Value> {
        self.values
    }

    /// Itera sobre os valores da linha, na ordem das colunas.
    pub fn iter(&self) -> std::slice::Iter<'_, Value> {
        self.values.iter()
    }
}

impl std::ops::Index<usize> for Row {
    type Output = Value;

    fn index(&self, index: usize) -> &Value {
        &self.values[index]
    }
}

impl std::ops::Index<&str> for Row {
    type Output = Value;

    /// Igual a [`Self::get`]`::<_, &Value>`, mas entra em pânico se a coluna
    /// não existir (nunca por causa de `NULL`, que é um `Value` válido).
    fn index(&self, name: &str) -> &Value {
        self.column_index(name)
            .map(|i| &self.values[i])
            .unwrap_or_else(|| {
                let disponiveis: Vec<&str> = self.columns.iter().map(ColumnMeta::name).collect();
                panic!("coluna `{name}` não existe nesta linha (colunas: {disponiveis:?})")
            })
    }
}

impl<'a> IntoIterator for &'a Row {
    type Item = &'a Value;
    type IntoIter = std::slice::Iter<'a, Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

impl IntoIterator for Row {
    type Item = Value;
    type IntoIter = std::vec::IntoIter<Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cols() -> Arc<[ColumnMeta]> {
        Arc::from(vec![
            ColumnMeta {
                field: "ID".into(),
                ..Default::default()
            },
            ColumnMeta {
                field: "NOME".into(),
                alias: "NOME_CLIENTE".into(),
                ..Default::default()
            },
        ])
    }

    fn row() -> Row {
        Row::new(vec![Value::Int(1), Value::Text("Ana".into())], cols())
    }

    #[test]
    fn get_by_index_matches_vec_indexing() {
        let r = row();
        assert_eq!(r[0], Value::Int(1));
        assert_eq!(r.get::<_, i32>(0).unwrap(), 1);
        assert!(r.get::<_, i32>(9).is_err());
    }

    #[test]
    fn get_by_name_uses_alias_over_field() {
        let r = row();
        // A coluna 1 tem alias NOME_CLIENTE; o nome exposto é o alias, não o field.
        assert_eq!(r.get::<_, &str>("NOME_CLIENTE").unwrap(), "Ana");
        assert!(r.get::<_, &str>("NOME").is_err());
    }

    #[test]
    fn get_by_name_is_case_insensitive() {
        let r = row();
        assert_eq!(r["id"], Value::Int(1));
        assert_eq!(r["Id"], Value::Int(1));
        assert_eq!(r.get::<_, i64>("id").unwrap(), 1);
        assert_eq!(r.get::<_, String>("nome_cliente").unwrap(), "Ana");
    }

    #[test]
    fn get_maps_null_to_none_only_for_option() {
        let r = Row::new(vec![Value::Null], cols());
        assert_eq!(r.get::<_, Option<i32>>(0).unwrap(), None);
        assert!(r.get::<_, i32>(0).is_err());
    }

    #[test]
    fn get_errors_on_type_mismatch() {
        let r = row();
        assert!(r.get::<_, i64>("nome_cliente").is_err());
    }

    #[test]
    fn missing_name_returns_err() {
        let r = row();
        assert!(r.get::<_, &Value>("nao_existe").is_err());
        assert_eq!(r.column_index("nao_existe"), None);
    }

    #[test]
    #[should_panic(expected = "coluna `nao_existe` não existe")]
    fn indexing_by_missing_name_panics() {
        let r = row();
        let _ = r["nao_existe"];
    }

    #[test]
    fn clone_shares_column_metadata_via_arc_not_copy() {
        let r1 = row();
        let r2 = r1.clone();
        // Mesmo ponteiro de dados: clonar a Row não duplicou os ColumnMeta.
        assert_eq!(r1.columns().as_ptr(), r2.columns().as_ptr());
        assert_eq!(r1, r2);
    }

    #[test]
    fn two_rows_from_the_same_statement_share_the_arc() {
        let shared = cols();
        let r1 = Row::new(vec![Value::Int(1)], shared.clone());
        let r2 = Row::new(vec![Value::Int(2)], shared.clone());
        assert_eq!(r1.columns().as_ptr(), r2.columns().as_ptr());
    }
}
