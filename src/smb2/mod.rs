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

// expose
pub use builder::ClientBuilder;
pub use errors::{Error, ErrorCode};

// internal
use crate::socket::Socket;

// types
pub type SmbResult<T> = Result<T, Error>;

/// ## Client
///
/// SMB2/3 client. This is the only struct the client must use in order to connect with the remote server
#[derive(Debug)]
pub struct Client {
    pub(crate) socket: Socket,
    pub(crate) timeout: Option<usize>,
    pub(crate) smb_version: ProtocolVersion,
    pub(crate) async_id: u64,
    pub(crate) message_id: u64,
    pub(crate) session_id: u64,
}

/// ## ProtocolVersion
///
/// Describes the negotiated protocol version
#[derive(Debug)]
pub(crate) enum ProtocolVersion {
    V202 = 0x0202,
    V210 = 0x0210,
    V300 = 0x0300,
    V302 = 0x0302,
    V311 = 0x0311,
}
