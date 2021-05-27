//! # messages
//!
//! this modules is internal and contains all the commands and responses designed in the SMB2 protocol
//! in addition it provides the encoder and the decoder

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
// modules
mod error;
mod header;
// locals
use super::ErrorCode;
use super::{Client, SmbResult};
use error::ErrorResponse;
use header::Header;
// deps
use bytes::{Buf, BufMut, Bytes, BytesMut};

// traits

/// ## Command
///
/// The Command trait describes the methods a command must implement
pub trait Command: Encode {
    /// ### get_command_Id
    ///
    /// Returns the command ID
    fn get_command_id(&self) -> u16;
}

/// ## Encode
///
/// The encode traits must be implemented by all the commands and requires to implement a method which encodes the command into
/// a buffer
pub trait Encode {
    /// ### encode
    ///
    /// Encode the command
    fn encode(&self) -> Bytes;
}

// encoder

/// ## Encoder
///
/// The encoder, as the name suggests, encode a message
#[derive(Debug)]
pub struct Encoder;

impl Default for Encoder {
    fn default() -> Self {
        Encoder {}
    }
}

impl Encoder {
    /// ### encode
    ///
    /// Encode a message
    pub async fn encode(&self, command: &dyn Command, client: &Client) -> Bytes {
        // Create header
        let header: Bytes = Header::new(client, command.get_command_id()).encode();
        Bytes::new() // TODO: replace
    }
}

// decoder

/// ## Decode
///
/// The Decode trait must be implemented by all the data types which must be decoded, since received as response from the server
pub trait Decode: Sized {
    /// ### decode
    ///
    /// Try to decode buff into `Self`
    fn decode(buff: &dyn Buf) -> SmbResult<Self>;
}

/// ## Response
///
/// Represents a SMB2 response
#[derive(Debug)]
pub struct Response {
    header: Header,
    error: Option<ErrorResponse>,
    data: Bytes,
}

/// ## Decoder
///
/// The decoder, as the name suggests, is used to decode messages
#[derive(Debug)]
pub struct Decoder;

impl Default for Decoder {
    fn default() -> Self {
        Decoder {}
    }
}

impl Decoder {
    /// ### decode
    ///
    /// Decode incoming buffer
    pub async fn decode(&self, buff: &dyn Buf) -> SmbResult<Response> {}
}
