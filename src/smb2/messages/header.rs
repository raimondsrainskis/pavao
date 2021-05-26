//! # header
//!
//! this modules defines the smb2 protocol header

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
use super::{Client, Encode, ErrorCode};
use bytes::{BufMut, Bytes, BytesMut};

bitflags! {
    /// ## Flags
    ///
    /// Describes header flags
    struct Flags: u32 {
        const FLAGS_SERVER_TO_REDIR = 0x00000001;
        const FLAGS_ASYNC_COMMAND = 0x00000002;
        const FLAGS_RELATED_OPERATIONS = 0x00000004;
        const FLAGS_SIGNED = 0x00000008;
        const FLAGS_PRIORITY_MASK = 0x00000070;
        const FLAGS_DFS_OPERATIONS = 0x10000000;
        const FLAGS_REPLAY_OPERATION = 0x20000000;
    }
}

/// ## Header
///
/// Message header
pub struct Header {
    protocol_id: u32,
    struct_size: u16,
    credit_charge: u16,
    status: ErrorCode,
    command_id: u16,
    credit_request: u16,
    flags: Flags,
    next_command: u32,
    message_id: u64,
    async_id: u64,
    session_id: u64,
    signature: String,
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
            flags: Flags::empty(), // FIXME:
            next_command: 0,
            message_id: client.message_id,
            async_id: client.async_id,
            session_id: client.session_id,
            signature: String::new(), // FIXME:
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
        header.put_u32(self.flags.bits());
        header.put_u32(self.next_command); // next command
        header.put_u64(self.message_id);
        header.put_u64(self.async_id);
        header.put_u64(self.session_id);
        // TODO: signature
        header.freeze()
    }
}
