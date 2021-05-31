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
use super::{Client, CommandId, Decode, Encode, Error, ErrorCode, SmbResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryFrom;

bitflags! {
    /// ## Flags
    ///
    /// Describes header flags
    struct Flags: u32 {
        const SERVER_TO_REDIR = 0x00000001;
        const ASYNC_COMMAND = 0x00000002;
        const RELATED_OPERATIONS = 0x00000004;
        const SIGNED = 0x00000008;
        const PRIORITY_MASK = 0x00000070;
        const DFS_OPERATIONS = 0x10000000;
        const REPLAY_OPERATION = 0x20000000;
    }
}

/// ## AsyncHeader
///
/// Message header for async messages
#[derive(Debug)]
pub(crate) struct AsyncHeader {
    protocol_id: u32,
    struct_size: u16,
    credit_charge: u16,
    pub status: ErrorCode,
    pub command_id: CommandId,
    credit_request: u16,
    flags: Flags,
    next_command: u32,
    pub message_id: u64,
    pub async_id: u64,
    pub session_id: u64,
    pub signature: Vec<u8>, // 16 bytes
}

impl AsyncHeader {
    /// ### new
    ///
    /// Instantiates a new `AsyncHeader`
    pub fn new(client: &Client, command_id: CommandId) -> Self {
        Self {
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
            signature: Vec::with_capacity(16), // FIXME:
        }
    }
}

impl Encode for AsyncHeader {
    fn encode(&self) -> Bytes {
        let mut header: BytesMut = BytesMut::with_capacity(64);
        header.put_u32(self.protocol_id);
        header.put_u16(self.struct_size);
        header.put_u16(self.credit_charge);
        header.put_u32(From::from(self.status));
        header.put_u16(From::from(self.command_id));
        header.put_u16(self.credit_request);
        header.put_u32(self.flags.bits());
        header.put_u32(self.next_command);
        header.put_u64(self.message_id);
        header.put_u64(self.async_id);
        header.put_u64(self.session_id);
        header.put(self.signature.as_ref());
        header.freeze()
    }
}

impl Decode for AsyncHeader {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {
        if buff.remaining() < 64 {
            return Err(Error::InvalidSyntax);
        }
        let protocol_id: u32 = buff.get_u32();
        let struct_size: u16 = buff.get_u16();
        let credit_charge: u16 = buff.get_u16();
        let status: ErrorCode = ErrorCode::from(buff.get_u32());
        let command_id: CommandId =
            CommandId::try_from(buff.get_u16()).map_err(|_| Error::UnknownCommand)?;
        let credit_request: u16 = buff.get_u16();
        let flags: Flags = Flags::from_bits(buff.get_u32()).unwrap_or_else(Flags::empty);
        let next_command: u32 = buff.get_u32();
        let message_id: u64 = buff.get_u64();
        let async_id: u64 = buff.get_u64();
        let session_id: u64 = buff.get_u64();
        let mut signature: Vec<u8> = vec![0; 16];
        buff.copy_to_slice(signature.as_mut_slice());
        Ok(Self {
            protocol_id,
            struct_size,
            credit_charge,
            status,
            command_id,
            credit_request,
            flags,
            next_command,
            message_id,
            async_id,
            session_id,
            signature,
        })
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use bytes::Bytes;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_smb2_messages_header_new() {
        // TODO: implement
    }

    #[test]
    fn test_smb2_messages_header_encode() {
        let header: AsyncHeader = AsyncHeader {
            protocol_id: 0x424D54FE,
            struct_size: 64,
            credit_charge: 0,
            status: ErrorCode::WrongVolume,
            command_id: CommandId::Echo,
            credit_request: 0,
            flags: Flags::ASYNC_COMMAND,
            next_command: 0,
            message_id: 0xcafebabe,
            async_id: 0xdeadbeef,
            session_id: 0xcafed00d,
            signature: vec![0xff; 16],
        };
        let mut bytes: Bytes = header.encode();
        assert_eq!(bytes.get_u32(), 0x424D54FE);
        assert_eq!(bytes.get_u16(), 64);
        assert_eq!(bytes.get_u16(), 0);
        assert_eq!(
            ErrorCode::try_from(bytes.get_u32()).ok().unwrap(),
            ErrorCode::WrongVolume
        );
        assert_eq!(
            CommandId::try_from(bytes.get_u16()).ok().unwrap(),
            CommandId::Echo
        );
        assert_eq!(bytes.get_u16(), 0);
        assert_eq!(
            Flags::from_bits(bytes.get_u32()).unwrap(),
            Flags::ASYNC_COMMAND
        );
        assert_eq!(bytes.get_u32(), 0);
        assert_eq!(bytes.get_u64(), 0xcafebabe);
        assert_eq!(bytes.get_u64(), 0xdeadbeef);
        assert_eq!(bytes.get_u64(), 0xcafed00d);
        let mut signature: Vec<u8> = vec![0x00; 16];
        bytes.copy_to_slice(signature.as_mut_slice());
        assert_eq!(signature, vec![0xff; 16]);
    }

    #[test]
    fn test_smb2_messages_header_decode() {
        let mut buff: Bytes = Bytes::from(vec![
            0x42, 0x4D, 0x54, 0xFE, // protocol_id
            0x00, 64, // struct size
            0x00, 0x00, // Credit charge
            0x80, 0x00, 0x00, 0x2d, // stopped on symlink
            0x00, 0x0d, // echo
            0x00, 0x00, // credit req
            0x00, 0x00, 0x00, 0x02, // Async
            0x00, 0x00, 0x00, 0x00, // next cmd
            0x00, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe, // msg id
            0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, // async id
            0x00, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xd0, 0x0d, // sess id
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, // signature
        ]);
        let header: AsyncHeader = AsyncHeader::decode(&mut buff).ok().unwrap();
        assert_eq!(header.protocol_id, 0x424d54fe);
        assert_eq!(header.struct_size, 64);
        assert_eq!(header.credit_charge, 0);
        assert_eq!(header.status, ErrorCode::StoppedOnSymlink);
        assert_eq!(header.command_id, CommandId::Echo);
        assert_eq!(header.credit_request, 0);
        assert_eq!(header.flags, Flags::ASYNC_COMMAND);
        assert_eq!(header.next_command, 0);
        assert_eq!(header.message_id, 0xcafebabe);
        assert_eq!(header.async_id, 0xdeadbeef);
        assert_eq!(header.session_id, 0xcafed00d);
        assert_eq!(header.signature, vec![0xff; 16]);
        // Bad size
        let mut buff: Bytes = Bytes::from(vec![
            0x42, 0x4D, 0x54, 0xFE, // protocol_id
            0x00, 64, // struct size
            0x00, 0x00, // Credit charge
            0xff, 0xff, // signature
        ]);
        assert!(AsyncHeader::decode(&mut buff).is_err());
        // Bad command
        let mut buff: Bytes = Bytes::from(vec![
            0x42, 0x4D, 0x54, 0xFE, // protocol_id
            0x00, 64, // struct size
            0x00, 0x00, // Credit charge
            0x80, 0x00, 0x00, 0x2d, // stopped on symlink
            0xca, 0xfe, // bad bad bad
            0x00, 0x00, // credit req
            0x00, 0x00, 0x00, 0x02, // Async
            0x00, 0x00, 0x00, 0x00, // next cmd
            0xca, 0xfe, 0xba, 0xbe, // msg id
            0xde, 0xad, 0xbe, 0xef, // async id
            0xca, 0xfe, 0xd0, 0x0d, // sess id
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, // signature
        ]);
        assert!(AsyncHeader::decode(&mut buff).is_err());
    }
}
