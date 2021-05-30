//! # negotiate
//!
//! this modules exposes the data types for the Negotiate command

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
use super::{Command, CommandId, Decode, Encode, Error, SmbResult};
use crate::smb2::types::Guid;
use crate::smb2::ProtocolVersion;
// deps
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// ## NegotiateRequest
///
/// Represents a Negotiate
#[derive(Debug)]
pub struct NegotiateRequest {
    struct_size: u16,
    dialect_count: u16,
    security_mode: SecurityMode,
    capabilities: Smbv3Capabilities,
    client_guid: Guid,   // 16 bytes
    context_offset: u32, // 0x311 only
    context_count: u16,  // 0x311 only + 2 bytes rfu
    start_time: u64,     // always 0; not for 0x311
    dialects: Vec<ProtocolVersion>,
    ctx_list: Vec<NegotiateContext>, // List of negotiate context (length match context_count; 0x311 only)
}

/// ## SecurityMode
///
/// Describes the security mode in negotiation
#[derive(Copy, Clone, Debug)]
#[repr(u16)]
enum SecurityMode {
    Enabled = 0x0001,
    Required = 0x0002,
}

bitflags! {
    /// ## Smbv3Capabilities
    ///
    /// Describes the smb3 capabilities in negotiation
    pub struct Smbv3Capabilities: u32 {
        const DFS = 0x00000001; // Distributed file system
        const LEASING = 0x00000002;
        const LARGE_MTU = 0x00000004;
        const MULTI_CHANNEL = 0x00000008;
        const PERSISTENT_HANDLES = 0x00000010;
        const DIRECTORY_LEASING = 0x00000020;
        const ENCRYPTION = 0x00000040;
    }
}

impl Encode for NegotiateRequest {
    fn encode(&self) -> Bytes {
        // Buff len is: 36 (base) + 2 bytes for each dialect; length for context will be added later
        let mut buff: BytesMut = BytesMut::with_capacity(36 + (self.dialect_count as usize * 2));
        buff.put_u16(self.struct_size);
        buff.put_u16(self.dialect_count);
        buff.put_u16(self.security_mode as u16);
        buff.put_u16(0x0000); // RFU
        buff.put_u32(self.capabilities.bits());
        buff.put(self.client_guid.data());
        match self.dialects.contains(&ProtocolVersion::V311) {
            false => buff.put_u64(self.start_time),
            true => {
                buff.put_u32(self.context_offset);
                buff.put_u16(self.context_count);
                buff.put_u16(0x0000); // RFU
            }
        }
        // Put dialects
        self.dialects.iter().for_each(|x| buff.put_u16(*x as u16));
        // TODO: put context
        buff.freeze()
    }
}

impl Command for NegotiateRequest {
    fn command_id(&self) -> CommandId {
        CommandId::Negotiate
    }
}

/// ## NegotiateContext
///
/// Represents a negotiate context for SMB 311
#[derive(Debug)]
struct NegotiateContext {
    type_: ContextType,
    data_len: u16,
    data: NegotiateContextData,
}

/// ## ContextType
///
/// Defines the negotiate context type
#[derive(Debug)]
#[repr(u16)]
enum ContextType {
    PreauthIntegrityCapabilities = 0x0001,
    EncryptionCapabilities = 0x0002,
    CompressionCapabilities = 0x0003,
    NetnameNegotiateContextId = 0x0005,
    TransportCapabilities = 0x0006,
    RdmaTransformCapabilities = 0x0007,
    SigninCapabilities = 0x0008,
}

/// ## NegotiateContextData
///
/// Represents the data the context data can contain
#[derive(Debug)]
enum NegotiateContextData {
    PreauthIntegrityCapabilities,
    EncryptionCapabilities,
    CompressionCapabilities,
    NetnameNegotiateContextId,
    TransportCapabilities,
    RdmaTransformCapabilities,
    SigninCapabilities,
}
