# O que é este projeto? (explicação para leigos)

## Em uma frase

Este projeto é uma peça de software que ensina um programa escrito na linguagem
**Rust** a **conversar diretamente com um banco de dados Firebird** pela rede,
sem precisar de nenhum programa intermediário instalado no computador.

---

## Os conceitos, com analogias

### O que é um banco de dados?

Imagine um **arquivo gigante e muito organizado** — como um armário de fichas de
uma biblioteca antiga, mas eletrônico. Ele guarda informações em **tabelas**
(parecidas com planilhas): linhas e colunas. Por exemplo, uma tabela de
funcionários com colunas "número", "nome", "salário".

O **Firebird** é uma dessas "bibliotecas eletrônicas" — um programa servidor que
fica guardando os dados e respondendo a pedidos. Normalmente ele roda em outro
computador (um servidor), e os programas conversam com ele pela rede.

### O que é um "driver"?

Um **driver** é um **tradutor/intérprete**. O seu programa fala uma língua (Rust),
e o banco de dados Firebird fala outra (um "idioma" técnico próprio, feito de
sequências de bytes trafegando pela rede). O driver fica no meio e traduz os dois
lados: pega um pedido como *"me dê os nomes de todos os funcionários"* e o
converte na sequência exata de bytes que o Firebird entende — e depois traduz a
resposta de volta.

> A maioria dos drivers de Firebird depende de uma biblioteca externa chamada
> `fbclient` (um "tradutor" pronto que precisa ser instalado à parte). **Este
> projeto não precisa dela**: ele mesmo fala o idioma do Firebird do zero. Isso o
> torna mais leve, portátil e fácil de instalar.

### O que é o "wire protocol" (protocolo de comunicação)?

É o **idioma combinado** entre o driver e o servidor. "Wire" significa "fio/cabo":
são as regras de quais bytes vão pelo cabo de rede, em que ordem, e o que cada um
significa. É como um **protocolo diplomático**: primeiro um aperto de mãos
(apresentação), depois a identificação, e só então a conversa de verdade.

---

## Como uma conversa acontece (passo a passo)

Pense em **ir a um restaurante**:

1. **Conexão e "aperto de mãos" (handshake)** — você entra e o garçom vem até
   você. As duas partes combinam em que língua vão falar (qual versão do
   protocolo). → arquivo `connection.rs`

2. **Autenticação (provar quem você é)** — você mostra que tem reserva, sem gritar
   sua senha para o salão inteiro. O Firebird usa um método inteligente chamado
   **SRP**, em que o cliente prova que sabe a senha **sem nunca enviá-la** pela
   rede. → arquivo `auth/srp.rs`

3. **Criptografia (conversa em código secreto)** — opcionalmente, a partir daqui
   tudo o que é dito vira "código secreto" (cifra ARC4), para que ninguém
   bisbilhotando o cabo entenda nada. → arquivo `auth/wirecrypt.rs`

4. **Transação (abrir a comanda)** — antes de pedir ou alterar dados, abre-se uma
   **transação**. É como a comanda do restaurante: tudo o que você fizer fica
   reunido nela e, no fim, você **confirma tudo** (commit) ou **cancela tudo**
   (rollback), sem deixar nada pela metade. → arquivo `transaction.rs`

5. **Pedido (a consulta SQL)** — você faz o pedido: *"SELECT nome FROM
   funcionarios"*. O driver primeiro **prepara** o pedido (o servidor confere se a
   frase faz sentido e diz quais colunas virão), depois **executa**, e por fim
   **busca as linhas** da resposta, uma a uma. → arquivo `statement.rs`

6. **A resposta chega em "código"** — os dados voltam como bytes crus. O driver os
   **decodifica** de volta para valores normais (números, textos, datas). →
   arquivos `message.rs` e `value.rs`

7. **Encerrar** — confirma a comanda e vai embora educadamente (fecha a conexão).

---

## O que cada arquivo faz (mapa rápido)

| Arquivo | Papel no "restaurante" |
|---|---|
| `lib.rs` | A porta de entrada: lista tudo o que o projeto oferece. |
| `config.rs` | As preferências da reserva: endereço do servidor, usuário, senha. |
| `connection.rs` | O garçom: conduz o aperto de mãos, login e abertura da conexão. |
| `auth/srp.rs` | O segurança: prova sua identidade sem expor a senha. |
| `auth/wirecrypt.rs` | O "código secreto" que embaralha a conversa. |
| `transaction.rs` | A comanda: confirma ou cancela um conjunto de operações. |
| `statement.rs` | O ciclo do pedido: preparar → executar → buscar respostas. |
| `blr.rs` | Descreve ao servidor o "formato" das linhas (o cardápio das colunas). |
| `message.rs` | Empacota e desempacota as linhas de dados. |
| `value.rs` | Os tipos de valor: número, texto, data, etc. |
| `wire/` | A "gramática" do idioma: constantes, codificação de bytes (XDR) e o fluxo de pacotes. |
| `error.rs` | O tratamento de problemas: traduz erros do servidor em mensagens claras. |

---

## Por que isso é difícil (e interessante)?

O "idioma" do Firebird **não é documentado publicamente em detalhes**. Boa parte
deste projeto foi descoberta na marra: **espionando** (com ferramentas) a conversa
real entre o programa oficial do Firebird e o servidor, anotando exatamente quais
bytes aparecem, e reproduzindo esse comportamento. Essas anotações estão no
arquivo `PROTOCOL-NOTES.md`.

---

## Em que pé está o projeto?

- ✅ **Funciona:** conectar, autenticar (SRP), criptografar a conexão, abrir e
  fechar transações, preparar e executar consultas, e ler as linhas de resultado.
- 🛠️ **Em andamento / a verificar:** alguns detalhes finos do envio de
  parâmetros e a contagem exata de certos campos ainda precisam ser confirmados
  contra um servidor Firebird real. Recursos maiores planejados: BLOBs (dados
  grandes, como imagens) e DML em lote (inserir muitas linhas de uma vez).

> **Resumindo:** é um "tradutor universal" caseiro entre programas em Rust e o
> banco de dados Firebird — construído peça por peça, falando o idioma da máquina
> diretamente, sem depender de nada de terceiros.
