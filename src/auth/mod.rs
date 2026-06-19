//! Authentication and wire encryption: the SRP client and stream ciphers used
//! during the connection handshake.

pub mod srp;
pub mod wirecrypt;

pub use srp::{SrpClient, SrpHash};
pub use wirecrypt::{Rc4, WireCryptPlugin};
