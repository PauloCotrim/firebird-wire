//! Generic response reading: `op_response` plus the trailing status vector.

use crate::error::{DatabaseError, Error, Result, StatusArg, StatusVector};
use crate::wire::consts::{arg, op};
use crate::wire::stream::{op_name, FbStream};

/// A parsed `op_response` packet (`P_RESP`).
#[derive(Debug, Clone)]
pub struct Response {
    /// Object id / handle returned by the operation (`p_resp_object`).
    pub handle: i32,
    /// Blob id (`p_resp_blob_id`), meaningful only for blob ops.
    pub blob_id: u64,
    /// Variable data payload (`p_resp_data`).
    pub data: Vec<u8>,
    /// The status vector; may carry warnings even on success.
    pub status: StatusVector,
}

impl Response {
    /// Turn an error-bearing status vector into [`Error::Database`]; otherwise
    /// yield the response (warnings are retained in `status`).
    pub fn into_result(self) -> Result<Response> {
        if self.status.is_error() {
            return Err(Error::Database(DatabaseError::new(self.status)));
        }
        Ok(self)
    }
}

/// Read the next operation code, transparently skipping keep-alive `op_dummy`
/// and `op_void` packets.
pub async fn read_op(stream: &mut FbStream) -> Result<i32> {
    loop {
        let code = stream.read_i32().await?;
        if code == op::DUMMY || code == op::VOID {
            continue;
        }
        return Ok(code);
    }
}

/// Read a status vector field by field from the async stream.
pub async fn read_status_vector(stream: &mut FbStream) -> Result<StatusVector> {
    let mut args = Vec::new();
    let mut sql_state = None;

    loop {
        let tag = stream.read_i32().await?;
        match tag {
            t if t == arg::END => break,
            t if t == arg::GDS => args.push(StatusArg::Gds(stream.read_i32().await?)),
            t if t == arg::WARNING => args.push(StatusArg::Warning(stream.read_i32().await?)),
            t if t == arg::NUMBER => args.push(StatusArg::Number(stream.read_i32().await?)),
            t if t == arg::STRING || t == arg::CSTRING => {
                let s = String::from_utf8_lossy(&stream.read_bytes().await?).into_owned();
                args.push(StatusArg::Str(s));
            }
            t if t == arg::INTERPRETED => {
                let s = String::from_utf8_lossy(&stream.read_bytes().await?).into_owned();
                args.push(StatusArg::Interpreted(s));
            }
            t if t == arg::SQL_STATE => {
                sql_state = Some(String::from_utf8_lossy(&stream.read_bytes().await?).into_owned());
            }
            other => {
                let _ = stream.read_i32().await?;
                args.push(StatusArg::Number(other));
            }
        }
    }

    Ok(StatusVector { args, sql_state })
}

/// Read the `P_RESP` body that follows an already-consumed `op_response` code.
pub async fn read_response_body(stream: &mut FbStream) -> Result<Response> {
    let handle = stream.read_i32().await?;
    let blob_id = stream.read_quad().await?;
    let data = stream.read_bytes().await?;
    let status = read_status_vector(stream).await?;
    Ok(Response { handle, blob_id, data, status })
}

/// Read the next packet, requiring it to be an `op_response`, and convert any
/// error status into [`Error::Database`].
pub async fn read_response(stream: &mut FbStream) -> Result<Response> {
    let code = read_op(stream).await?;
    if code != op::RESPONSE {
        return Err(Error::protocol(format!(
            "expected op_response, got {} ({code})",
            op_name(code)
        )));
    }
    read_response_body(stream).await?.into_result()
}
