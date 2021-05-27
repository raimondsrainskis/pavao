//! # error
//!
//! this modules exposes the SMB2 Error

/**
 * MIT License
 *
 * pavao - Copyright (C) 2021 Christian Visintin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
// locals
use super::{Decode, Error, ErrorCode, SmbResult};
use crate::utils::buffer::align_8_bytes_boundary;
// deps
use bytes::Buf;
use std::convert::TryFrom;
use std::path::PathBuf;

/// ## ErrorResponse
///
/// Error response in the SMB2 protocol
#[derive(Debug)]
pub struct ErrorResponse {
    struct_size: u16,
    ctx_count: u8,
    // rfu 8
    byte_count: u32,
    error_data: Vec<ErrorContext>,
}

impl ErrorResponse {
    pub fn decode(buff: &mut dyn Buf, error_code: ErrorCode) -> SmbResult<Self> {
        if buff.remaining() < 8 {
            // Min len
            return Err(Error::InvalidSyntax);
        }
        let struct_size: u16 = buff.get_u16();
        let ctx_count: u8 = buff.get_u8();
        buff.advance(1); // RFU
        let byte_count: u32 = buff.get_u32();
        // Verify length for error_data
        if buff.remaining() < byte_count as usize {
            return Err(Error::InvalidSyntax);
        }
        // Collect error data
        let mut error_data: Vec<ErrorContext> = Vec::with_capacity(ctx_count as usize);
        for _ in 0..ctx_count {
            error_data.push(ErrorContext::decode(buff, error_code)?);
            // 8-byte padding
            align_8_bytes_boundary(buff);
        }
        Ok(ErrorResponse {
            struct_size,
            ctx_count,
            byte_count,
            error_data,
        })
    }
}

/// ## ErrorContext
///
/// Error context as expected by the `ErrorResponse`
#[derive(Debug)]
pub struct ErrorContext {
    data_length: u32,
    error_id: ErrorId,
    data: Vec<ErrorContextData>,
}

impl ErrorContext {
    pub fn decode(buff: &mut dyn Buf, error_code: ErrorCode) -> SmbResult<Self> {
        if buff.remaining() < 8 {
            return Err(Error::InvalidSyntax);
        }
        let data_length: u32 = buff.get_u32();
        let error_id: ErrorId = match ErrorId::try_from(buff.get_u32()) {
            Ok(id) => id,
            Err(_) => return Err(Error::InvalidSyntax),
        };
    }
}

/// ## ErrorId
///
/// An identifier for the error context.
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq, Eq)]
pub enum ErrorId {
    Smb2ErrorIdDefault = 0x00000000,
    Smb2ErrorIdShareRedirect = 0x72645253,
}

impl TryFrom<u32> for ErrorId {
    type Error = &'static str;

    fn try_from(status: u32) -> Result<Self, Self::Error> {
        match num::FromPrimitive::from_u32(status) {
            Some(err) => Ok(err),
            None => Err("Unknown error id"),
        }
    }
}

/// ## ErrorContextData
///
/// Error data formatted as specified in smb2
#[derive(Debug)]
pub enum ErrorContextData {
    SymbolicLink(SymbolicLinkError),
    ShareRedirect(ShareRedirectError),
    BufferTooSmall(u32),
}

impl Decode for ErrorContextData {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {}
}

/// ## SymbolicLinkError
///
/// The Symbolic Link Error Response is used to indicate that a symbolic link was encountered on create;
/// it describes the target path that the client MUST use if it requires to follow the symbolic link.
#[derive(Debug)]
pub struct SymbolicLinkError {
    symlink_length: u32,
    symlink_error_tag: u32,
    reparse_tag: u32,
    reparse_length: u16,
    unparsed_path_length: u16,
    substitute_name_length: u16,
    print_name_offset: u16,
    print_name_length: u16,
    flags: SymblocLinkErrorFlags,
    path_buffer: PathBuf,
}

bitflags! {
    /// ## SymblocLinkErrorFlags
    ///
    /// Describes symbolic link error flags
    struct SymblocLinkErrorFlags: u32 {
        const ABSOLUTE = 0x00000000;
        const SYMLINK_IS_RELATIVE = 0x00000001;
    }
}

impl Decode for SymbolicLinkError {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {}
}

/// ## ShareRedirectError
///
/// Servers which negotiate SMB 3.1.1 or higher can return this error context to a client in response to a
/// tree connect request with the SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER bit set in the
/// Flags field of the SMB2 TREE_CONNECT request.
#[derive(Debug)]
pub struct ShareRedirectError {
    struct_size: u32,
    notification_type: u32,
    resource_name_offset: u32,
    resource_name_length: u32,
    // rfu
    target_type: u16,
    ip_addr_count: u32,
    ip_addr_move_list: Vec<MoveDstIpAddr>,
    resource_name: String,
}

impl Decode for ShareRedirectError {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {}
}

/// ## MoveDstIpAddr
///
/// The MOVE_DST_IPADDR structure is used in Share Redirect Error Context Response to indicate the
/// destination IP address.
#[derive(Debug)]
pub struct MoveDstIpAddr {
    type_: MoveDstIpAddrType,
    // rfu
    addr: String,
}

bitflags! {
    /// ## MoveDstIpAddrType
    ///
    /// Type of ip address type
    struct MoveDstIpAddrType: u32 {
        const V4 = 0x00000001;
        const V6 = 0x00000002;
    }
}

impl Decode for MoveDstIpAddr {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {}
}

#[cfg(test)]
mod test {
    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn test_smb2_messages_error_errorid() {
        assert_eq!(
            ErrorId::try_from(0x00000000).ok().unwrap(),
            ErrorId::Smb2ErrorIdDefault
        );
        assert_eq!(
            ErrorId::try_from(0x72645253).ok().unwrap(),
            ErrorId::Smb2ErrorIdShareRedirect
        );
        assert_eq!(
            ErrorId::try_from(0xf0f0f0f0).err().unwrap(),
            "Unknown error id"
        );
    }
}
