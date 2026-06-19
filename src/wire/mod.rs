//! Blocos de construção de baixo nível do protocolo de comunicação (wire protocol): constantes, o codec XDR e o
//! fluxo (stream) de pacotes enquadrado usado para conversar com um servidor Firebird.

pub mod consts;
pub mod response;
pub mod stream;
pub mod xdr;
