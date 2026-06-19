//! Autenticação e criptografia do wire: o cliente SRP e as cifras de fluxo usadas
//! durante o handshake de conexão.

pub mod srp;
pub mod wirecrypt;

pub use srp::{SrpClient, SrpHash};
pub use wirecrypt::{Rc4, WireCryptPlugin};
