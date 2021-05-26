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
// locals
use super::Client;
use super::ErrorCode;
// deps
use bytes::{BufMut, Bytes, BytesMut};

// traits

/// ## Command
///
/// The Command trait describes the methods a command must implement
trait Command: Encode {
    /// ### get_command_Id
    ///
    /// Returns the command ID
    fn get_command_id(&self) -> u16;
}

/// ## Encode
///
/// The encode traits must be implemented by all the commands and requires to implement a method which encodes the command into
/// a buffer
trait Encode {
    /// ### encode
    ///
    /// Encode the command
    fn encode(&self) -> Bytes;
}

// encoder

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
    pub async fn encode(&self, command: &dyn Command, client: &Client) -> Bytes {
        // Create header
        let header: Bytes = Header::new(client, command.get_command_id()).encode();
        Bytes::new() // TODO: replace
    }
}

// header

/// ## Header
///
/// Message header
struct Header {
    protocol_id: u32,
    struct_size: u16,
    credit_charge: u16,
    status: ErrorCode,
    command_id: u16,
    credit_request: u16,
    flags: u32, // FIXME: is Flags
    next_command: u32,
    message_id: String, // FIXME: verify (maybe u64)
    async_id: String,   // FIXME: verify (maybe u64)
    session_id: String, // FIXME: verify (maybe u64)
    signature: String,  // FIXME: verify (maybe u128)
}

impl Header {
    /// ### new
    ///
    /// Instantiates a new `Header`
    pub fn new(client: &Client, command_id: u16) -> Self {
        Header {
            protocol_id: 0x424D54FE,
            struct_size: 64,
            credit_charge: 0,
            status: ErrorCode::Success,
            command_id,
            credit_request: 0,
            flags: 0, // FIXME:
            next_command: 0,
            message_id: String::new(), // FIXME:
            async_id: String::new(),   // FIXME:
            session_id: String::new(), // FIXME:
            signature: String::new(),  // FIXME:
        }
    }
}

impl Encode for Header {
    fn encode(&self) -> Bytes {
        let mut header: BytesMut = BytesMut::with_capacity(64);
        header.put_u32(self.protocol_id); // Protocol ID
        header.put_u16(self.struct_size); // Structure size
        header.put_u16(self.credit_charge); // Credit charge
        header.put_u32(From::from(self.status)); // Status
        header.put_u16(self.command_id); // Command
        header.put_u16(self.credit_request); // Credit request
                                             // TODO: flags --> header.put_u32(client.get_flags());
        header.put_u32(self.next_command); // next command
                                           // TODO: generate UUID
                                           // TODO: async id
                                           // TODO: session id
                                           // TODO: signature
        header.freeze()
    }
}
