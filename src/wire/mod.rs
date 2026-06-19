//! Low-level wire-protocol building blocks: constants, the XDR codec, and the
//! framed packet stream used to talk to a Firebird server.

pub mod consts;
pub mod response;
pub mod stream;
pub mod xdr;
