//! Handshake `Legacy_Auth` verificado contra um servidor de mentira.
//!
//! Um servidor real que ainda exija `Legacy_Auth` é justamente o que não se tem
//! à mão para testar (basta o DBA recriar o usuário com `USING PLUGIN Srp` e o
//! caminho desaparece). Então o servidor aqui é escrito à mão: ele responde o
//! `op_accept_data` sem desafio SRP — que é como o Firebird sinaliza "esse
//! usuário não existe no plugin que negociamos" — e depois pede a continuação
//! por `op_cont_auth`. O teste afirma os bytes exatos que o cliente devolve.
//!
//! O que ele protege, além do hash: que o cliente **responda** a essa rodada.
//! Um cliente que apenas consumisse o pacote e voltasse a ler ficaria parado
//! para sempre, sem erro — e é um travamento que nenhum teste com servidor real
//! pega, porque servidor real nenhum vai te ajudar a reproduzi-lo.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use firebird_wire::{ConnectConfig, Connection};

const SENHA: &str = "sip";
/// `crypt("sip", "9z")` sem o sal — conferido contra o `crypt(3)` do sistema.
const HASH_ESPERADO: &str = "0VCPQx87l2Y";

// ── leitura/escrita XDR mínima, do lado do servidor ──────────────────────────

fn ler_i32(s: &mut TcpStream) -> i32 {
    let mut b = [0u8; 4];
    s.read_exact(&mut b).expect("i32");
    i32::from_be_bytes(b)
}

fn ler_bytes(s: &mut TcpStream) -> Vec<u8> {
    let n = ler_i32(s) as usize;
    let mut v = vec![0u8; n];
    s.read_exact(&mut v).expect("bytes");
    let pad = (4 - (n % 4)) % 4;
    let mut p = vec![0u8; pad];
    s.read_exact(&mut p).expect("pad");
    v
}

fn por_i32(b: &mut Vec<u8>, v: i32) {
    b.extend_from_slice(&v.to_be_bytes());
}

fn por_bytes(b: &mut Vec<u8>, v: &[u8]) {
    por_i32(b, v.len() as i32);
    b.extend_from_slice(v);
    b.extend(std::iter::repeat_n(0u8, (4 - (v.len() % 4)) % 4));
}

/// Consome o `op_connect` do cliente e devolve a lista de plugins que ele
/// anunciou no bloco `p_cnct_user_id` (tag 10 = `CNCT_plugin_list`; a 8 é o
/// `CNCT_plugin_name`, o plugin que produziu os dados específicos).
fn ler_op_connect(s: &mut TcpStream) -> String {
    assert_eq!(ler_i32(s), 1, "esperava op_connect");
    ler_i32(s); // p_cnct_operation
    ler_i32(s); // CONNECT_VERSION
    ler_i32(s); // arch
    ler_bytes(s); // p_cnct_file
    let n_protos = ler_i32(s);
    let uid = ler_bytes(s); // p_cnct_user_id
    for _ in 0..n_protos {
        for _ in 0..5 {
            ler_i32(s);
        }
    }

    // O bloco é uma sequência tag/len/valor de um byte cada.
    let mut i = 0;
    let mut lista = String::new();
    while i + 1 < uid.len() {
        let tag = uid[i];
        let len = uid[i + 1] as usize;
        let val = &uid[i + 2..(i + 2 + len).min(uid.len())];
        if tag == 10 {
            lista = String::from_utf8_lossy(val).into_owned();
        }
        i += 2 + len;
    }
    lista
}

/// `op_accept_data` sem dados de desafio: é assim que o servidor diz "negociei
/// o plugin Srp, mas não tenho registro desse usuário nele".
fn enviar_accept_sem_desafio(s: &mut TcpStream) {
    let mut b = Vec::new();
    por_i32(&mut b, 94); // op_accept_data
    por_i32(&mut b, 0xffff_8013u32 as i32); // protocolo 19
    por_i32(&mut b, 1); // arch
    por_i32(&mut b, 3); // ptype
    por_bytes(&mut b, &[]); // p_acpt_data — vazio de propósito
    por_bytes(&mut b, b"Srp"); // p_acpt_plugin
    por_i32(&mut b, 0); // p_acpt_authenticated
    por_bytes(&mut b, &[]); // p_acpt_keys
    s.write_all(&b).unwrap();
}

fn enviar_cont_auth(s: &mut TcpStream, plugin: &str) {
    let mut b = Vec::new();
    por_i32(&mut b, 92); // op_cont_auth
    por_bytes(&mut b, &[]); // p_data
    por_bytes(&mut b, plugin.as_bytes()); // p_name
    por_bytes(&mut b, &[]); // p_list
    por_bytes(&mut b, &[]); // p_keys
    s.write_all(&b).unwrap();
}

fn enviar_response_ok(s: &mut TcpStream, handle: i32) {
    let mut b = Vec::new();
    por_i32(&mut b, 9); // op_response
    por_i32(&mut b, handle); // p_resp_object
    por_i32(&mut b, 0); // p_resp_blob_id (quad, alta)
    por_i32(&mut b, 0); // p_resp_blob_id (quad, baixa)
    por_bytes(&mut b, &[]); // p_resp_data
    por_i32(&mut b, 0); // isc_arg_end — vetor de status vazio = sucesso
    s.write_all(&b).unwrap();
}

/// O que o servidor de mentira observou durante o handshake.
struct Observado {
    lista_anunciada: String,
    plugin_respondido: String,
    dado_respondido: String,
    lista_no_cont_auth: String,
}

/// Sobe o servidor de mentira numa porta efêmera e devolve (porta, receptor).
/// `pedir` é o plugin que ele exigirá na rodada de continuação.
fn servidor(pedir: &'static str) -> (u16, mpsc::Receiver<Observado>) {
    let lis = TcpListener::bind("127.0.0.1:0").unwrap();
    let porta = lis.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut s, _) = lis.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

        let lista_anunciada = ler_op_connect(&mut s);
        enviar_accept_sem_desafio(&mut s);

        // op_attach: op | id do objeto | caminho | DPB
        assert_eq!(ler_i32(&mut s), 19, "esperava op_attach");
        ler_i32(&mut s);
        ler_bytes(&mut s);
        ler_bytes(&mut s);

        enviar_cont_auth(&mut s, pedir);

        // A resposta do cliente — o coração do teste.
        assert_eq!(ler_i32(&mut s), 92, "esperava op_cont_auth do cliente");
        let dado = ler_bytes(&mut s);
        let nome = ler_bytes(&mut s);
        let lista = ler_bytes(&mut s);
        ler_bytes(&mut s); // p_keys

        let _ = tx.send(Observado {
            lista_anunciada,
            plugin_respondido: String::from_utf8_lossy(&nome).into_owned(),
            dado_respondido: String::from_utf8_lossy(&dado).into_owned(),
            lista_no_cont_auth: String::from_utf8_lossy(&lista).into_owned(),
        });

        enviar_response_ok(&mut s, 1);
        // Segura o socket aberto: o `Connection::close` do cliente ainda vai
        // escrever nele, e um socket fechado viraria um erro sem relação.
        thread::sleep(Duration::from_secs(2));
    });

    (porta, rx)
}

fn config(porta: u16) -> ConnectConfig {
    ConnectConfig::new()
        .host("127.0.0.1")
        .port(porta)
        .database("/qualquer/banco.fdb")
        .user("FSCSIP")
        .password(SENHA)
        .connect_timeout(Duration::from_secs(10))
}

#[test]
fn responde_cont_auth_de_legacy_auth_com_o_hash_des() {
    let (porta, rx) = servidor("Legacy_Auth");
    let conn = Connection::connect(&config(porta));

    let obs = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("cliente não respondeu ao op_cont_auth — provável travamento");

    assert!(conn.is_ok(), "attach deveria concluir: {:?}", conn.err());
    assert_eq!(obs.plugin_respondido, "Legacy_Auth");
    assert_eq!(obs.dado_respondido, HASH_ESPERADO);
    assert!(
        obs.lista_anunciada.contains("Legacy_Auth"),
        "o plugin precisa ser anunciado no op_connect, veio {:?}",
        obs.lista_anunciada
    );
    assert!(obs.lista_no_cont_auth.contains("Legacy_Auth"));
}

#[test]
fn recusa_legacy_auth_quando_desligado_na_config() {
    let (porta, _rx) = servidor("Legacy_Auth");
    let msg = match Connection::connect(&config(porta).legacy_auth(false)) {
        Ok(_) => panic!("com legacy_auth(false) o attach tem que falhar"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("Legacy_Auth") && msg.contains("legacy_auth"),
        "erro deveria explicar a recusa, veio: {msg}"
    );
}

/// Um plugin que não sabemos falar tem que virar erro na hora. Antes de existir
/// este caminho, o cliente engolia o pacote e esperava para sempre.
#[test]
fn plugin_desconhecido_falha_em_vez_de_travar() {
    let (porta, _rx) = servidor("Win_Sspi");
    let msg = match Connection::connect(&config(porta)) {
        Ok(_) => panic!("plugin não implementado tem que falhar, não travar"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("Win_Sspi"),
        "o erro precisa nomear o plugin pedido, veio: {msg}"
    );
}
