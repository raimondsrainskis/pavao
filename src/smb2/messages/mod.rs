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
pub(crate) mod echo;
pub(crate) mod error;
pub(crate) mod header;
pub(crate) mod logoff;
pub(crate) mod negotiate;
// locals
use super::{Client, SmbResult};
use super::{Error, ErrorCode};
use error::ErrorResponse;
use header::AsyncHeader;
// deps
use bytes::{Buf, Bytes, BytesMut};
use std::convert::TryFrom;

// types

/// ## CommandId
///
/// Represent the id of each command
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[repr(u16)]
pub(crate) enum CommandId {
    Negotiate = 0x0000,
    SessionSetup = 0x0001,
    Logoff = 0x0002,
    TreeConnect = 0x0003,
    TreeDisconnect = 0x0004,
    Create = 0x0005,
    Close = 0x0006,
    Flush = 0x0007,
    Read = 0x0008,
    Write = 0x009,
    Lock = 0x000a,
    Ioctl = 0x000b,
    Cancel = 0x000c,
    Echo = 0x000d,
    QueryDirectory = 0x000e,
    ChangeNotify = 0x000f,
    QueryInfo = 0x0010,
    SetInfo = 0x0011,
    OpLockBreak = 0x0012,
}

impl TryFrom<u16> for CommandId {
    type Error = &'static str;

    fn try_from(cmd: u16) -> Result<Self, Self::Error> {
        match num::FromPrimitive::from_u16(cmd) {
            Some(err) => Ok(err),
            None => Err("Unknown command"),
        }
    }
}

impl From<CommandId> for u16 {
    fn from(code: CommandId) -> u16 {
        code as u16
    }
}

// traits

/// ## Command
///
/// The Command trait describes the methods a command must implement
pub(crate) trait Command: Encode {
    /// ### command_id
    ///
    /// Returns the command ID
    fn command_id(&self) -> CommandId;
}

/// ## Encode
///
/// The encode traits must be implemented by all the commands and requires to implement a method which encodes the command into
/// a buffer
pub(crate) trait Encode {
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
pub(crate) struct Encoder;

impl Default for Encoder {
    fn default() -> Self {
        Encoder {}
    }
}

impl Encoder {
    /// ### encode
    ///
    /// Encode a message
    pub async fn encode(&self, client: &Client, command: &dyn Command) -> Bytes {
        // Encode header
        let header: Bytes = AsyncHeader::new(client, command.command_id()).encode();
        // Encode command
        let command: Bytes = command.encode();
        // Encode buffer
        let bufsize: usize = header.remaining() + command.remaining();
        let mut buff: BytesMut = BytesMut::with_capacity(bufsize);
        buff.extend_from_slice(&header);
        buff.extend_from_slice(&command);
        // FIXME: not sure it's that simple
        buff.freeze()
    }
}

// decoder

/// ## Decode
///
/// The Decode trait must be implemented by all the data types which must be decoded, since received as response from the server
pub(crate) trait Decode: Sized {
    /// ### decode
    ///
    /// Try to decode buff into `Self`
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self>;
}

/// ## Response
///
/// Represents a SMB2 response
#[derive(Debug)]
pub(crate) struct Response {
    header: AsyncHeader,
    data: ResponseData,
}

/// ## ResponseData
///
/// Data associated to response
#[derive(Debug)]
pub(crate) enum ResponseData {
    Ok(Bytes), // NOTE: Remaining bytes; must be decoded by calling method
    Err(ErrorResponse),
}

/// ## Decoder
///
/// The decoder, as the name suggests, is used to decode messages
#[derive(Debug)]
pub(crate) struct Decoder;

impl Default for Decoder {
    fn default() -> Self {
        Decoder {}
    }
}

impl Decoder {
    /// ### decode
    ///
    /// Decode incoming buffer
    pub async fn decode(&self, buff: &mut dyn Buf) -> SmbResult<Response> {
        let header: AsyncHeader = AsyncHeader::decode(buff)?;
        // Decode data
        let data: ResponseData = match header.status {
            ErrorCode::Success => ResponseData::Ok(buff.copy_to_bytes(buff.remaining())),
            status => ResponseData::Err(ErrorResponse::decode(buff, status)?),
        };
        Ok(Response { header, data })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn test_smb2_messages_command_id() {
        assert_eq!(
            CommandId::try_from(0x0000).ok().unwrap(),
            CommandId::Negotiate
        );
        assert_eq!(
            CommandId::try_from(0x0001).ok().unwrap(),
            CommandId::SessionSetup
        );
        assert_eq!(CommandId::try_from(0x0002).ok().unwrap(), CommandId::Logoff);
        assert_eq!(
            CommandId::try_from(0x0003).ok().unwrap(),
            CommandId::TreeConnect
        );
        assert_eq!(
            CommandId::try_from(0x0004).ok().unwrap(),
            CommandId::TreeDisconnect
        );
        assert_eq!(CommandId::try_from(0x0005).ok().unwrap(), CommandId::Create);
        assert_eq!(CommandId::try_from(0x0006).ok().unwrap(), CommandId::Close);
        assert_eq!(CommandId::try_from(0x0007).ok().unwrap(), CommandId::Flush);
        assert_eq!(CommandId::try_from(0x0008).ok().unwrap(), CommandId::Read);
        assert_eq!(CommandId::try_from(0x0009).ok().unwrap(), CommandId::Write);
        assert_eq!(CommandId::try_from(0x000a).ok().unwrap(), CommandId::Lock);
        assert_eq!(CommandId::try_from(0x000b).ok().unwrap(), CommandId::Ioctl);
        assert_eq!(CommandId::try_from(0x000c).ok().unwrap(), CommandId::Cancel);
        assert_eq!(CommandId::try_from(0x000d).ok().unwrap(), CommandId::Echo);
        assert_eq!(
            CommandId::try_from(0x000e).ok().unwrap(),
            CommandId::QueryDirectory
        );
        assert_eq!(
            CommandId::try_from(0x000f).ok().unwrap(),
            CommandId::ChangeNotify
        );
        assert_eq!(
            CommandId::try_from(0x0010).ok().unwrap(),
            CommandId::QueryInfo
        );
        assert_eq!(
            CommandId::try_from(0x0011).ok().unwrap(),
            CommandId::SetInfo
        );
        assert_eq!(
            CommandId::try_from(0x0012).ok().unwrap(),
            CommandId::OpLockBreak
        );
        // Error
        assert!(CommandId::try_from(0xcafe).is_err());
        // To u16
        let num: u16 = From::from(CommandId::Close);
        assert_eq!(num, 0x0006);
    }

    // TODO: encode / decode
}
