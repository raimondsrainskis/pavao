//! # smb2
//!
//! exposes the client for SMB2/3

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
// sub modules
pub mod builder;
pub mod errors;
pub(crate) mod messages;
pub(crate) mod types;

// expose
pub use builder::ClientBuilder;
pub use errors::{Error, ErrorCode};

// internal
use crate::socket::Socket;
use types::Guid;

// libs
use std::convert::TryFrom;

// types
pub type SmbResult<T> = Result<T, Error>;

/// ## Client
///
/// SMB2/3 client. This is the only struct the client must use in order to connect with the remote server
#[derive(Debug)]
pub struct Client {
    pub(crate) socket: Socket,
    pub(crate) timeout: Option<usize>,
    pub(crate) smb_version: DialectRevision,
    pub(crate) guid: Guid,
    pub(crate) async_id: u64,
    pub(crate) message_id: u64,
    pub(crate) session_id: u64,
    // session sizes
    pub(crate) max_transact_size: usize,
    pub(crate) max_read_size: usize,
    pub(crate) max_write_size: usize,
}

/// ## DialectRevision
///
/// Describes the negotiated protocol version
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum DialectRevision {
    V202 = 0x0202,
    V210 = 0x0210,
    V300 = 0x0300,
    V302 = 0x0302,
    V311 = 0x0311,
}

impl TryFrom<u16> for DialectRevision {
    type Error = &'static str;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0202 => Ok(DialectRevision::V202),
            0x0210 => Ok(DialectRevision::V210),
            0x0300 => Ok(DialectRevision::V300),
            0x0302 => Ok(DialectRevision::V302),
            0x0311 => Ok(DialectRevision::V311),
            _ => Err("invalid Dialect Revision"),
        }
    }
}
