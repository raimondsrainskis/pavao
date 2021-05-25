//! # command
//!
//! this modules is internal and contains all the commands designed in the SMB2 protocol
//! in addition it provides the `Encode` trait

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
extern crate bytes;

// locals
use super::Client;
// deps
use bytes::{BufMut, Bytes, BytesMut};
/// ## Encode
///
/// The encode traits must be implemented by all the commands and requires to implement a method which encodes the command into
/// a buffer
pub trait Encode {
    /// ### encode
    ///
    /// Encode the command
    fn encode(&self) -> Bytes;

    /// ### get_command_Id
    ///
    /// Returns the command ID
    fn get_command_id(&self) -> u16;
}

/// ## Encoder
///
/// The encoder, as the name suggests, encode a message
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
    pub async fn encode(&self, command: &dyn Encode, client: &Client) -> Bytes {}

    /// ### encode_header
    async fn encode_header(&self, command: &dyn Encode, client: &Client) -> Bytes {
        let mut header: BytesMut = BytesMut::with_capacity(64);
        header.put_u32(0x424D54FE); // Protocol ID
        header.put_u16(64); // Structure size
        header.put_u16(0); // Credit charge
        header.put_u32(0); // Status
        header.put_u16(command.get_command_id()); // Command
        header.put_u16(0); // Credit request
                           // TODO: flags --> header.put_u32(client.get_flags());
        header.put_u32(0); // next command
                           // TODO: generate UUID
                           // TODO: async id
                           // TODO: session id
                           // TODO: signature
        header.freeze()
    }
}
