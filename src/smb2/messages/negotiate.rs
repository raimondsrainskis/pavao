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
use crate::smb2::types::{Cipher, Guid, HashAlgorithm, HashOptions, Salt, SigningAlgorithm};
use crate::smb2::ProtocolVersion;
// deps
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// ## NegotiateRequest
///
/// Represents a Negotiate
#[derive(Debug)]
pub struct NegotiateRequest {
    struct_size: u16,
    security_mode: SecurityMode,
    capabilities: Smbv3Capabilities,
    client_guid: Guid,   // 16 bytes
    context_offset: u32, // 0x311 only
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
        //const DFS = 0x00000001; // Distributed file system
        // const LEASING = 0x00000002;
        // const LARGE_MTU = 0x00000004; NOT SUPPORTED
        const MULTI_CHANNEL = 0x00000008; // CHECK: supported?
        const PERSISTENT_HANDLES = 0x00000010; // CHECK: supported?
        // const DIRECTORY_LEASING = 0x00000020; NOT SUPPORTED
        const ENCRYPTION = 0x00000040;
    }
}

/*
impl NegotiateRequest {
    /// ### new
    ///
    /// Create a new NegotiateRequest
    pub fn new(dialects: Vec<ProtocolVersion>, guid: Guid, hash: HashOptions, ciphers: Vec<Ciphers>, signatures: Vec<SigningAlgorithm>) -> Self {
        // TODO:
    }
}
*/

impl Encode for NegotiateRequest {
    fn encode(&self) -> Bytes {
        // Encode contexts
        let contexts_buffers: Vec<Bytes> = self.ctx_list.iter().map(|x| x.encode()).collect();
        // Calc contexts size
        let contexts_size: usize = contexts_buffers.iter().map(|x| x.len()).sum();
        // Buff len is: 36 (base) + 2 bytes for each dialect; length for context is variable
        let mut buff: BytesMut =
            BytesMut::with_capacity(36 + (self.dialects.len() * 2) + contexts_size);
        buff.put_u16(self.struct_size);
        buff.put_u16(self.dialects.len() as u16);
        buff.put_u16(self.security_mode as u16);
        buff.put_u16(0x0000); // RFU
        buff.put_u32(self.capabilities.bits());
        buff.put(self.client_guid.data());
        match self.dialects.contains(&ProtocolVersion::V311) {
            false => buff.put_u64(self.start_time),
            true => {
                buff.put_u32(self.context_offset);
                buff.put_u16(contexts_buffers.len() as u16);
                buff.put_u16(0x0000); // RFU
            }
        }
        // Put dialects
        self.dialects.iter().for_each(|x| buff.put_u16(*x as u16));
        // put contexts
        contexts_buffers
            .iter()
            .for_each(|x| buff.extend_from_slice(x));
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
enum NegotiateContext {
    PreauthIntegrityCapabilities(PreauthIntegrityCapabilitiesData),
    EncryptionCapabilities(EncryptionCapabilitiesData),
    CompressionCapabilities(CompressionCapabilitiesData),
    NetnameNegotiateContextId(String),
    TransportCapabilities(TransportCapabilitiesData),
    SigningCapabilities(SigningCapabilitiesData),
}

impl Encode for NegotiateContext {
    fn encode(&self) -> Bytes {
        // Encode data
        let buff_data: Bytes = match self {
            NegotiateContext::CompressionCapabilities(data) => data.encode(),
            NegotiateContext::EncryptionCapabilities(data) => data.encode(),
            NegotiateContext::NetnameNegotiateContextId(data) => {
                NegotiateContext::encode_context_id(&data)
            }
            NegotiateContext::PreauthIntegrityCapabilities(data) => data.encode(),
            NegotiateContext::SigningCapabilities(data) => data.encode(),
            NegotiateContext::TransportCapabilities(data) => data.encode(),
        };
        let data_len: usize = buff_data.len();
        let buf_size: usize = data_len + 8;
        let mut buff: BytesMut = BytesMut::with_capacity(buf_size);
        buff.put_u16(self.get_context_type());
        buff.put_u16(data_len as u16);
        buff.put_u32(0x00);
        buff.extend_from_slice(&buff_data);
        buff.freeze()
    }
}

impl NegotiateContext {
    pub fn get_context_type(&self) -> u16 {
        match self {
            NegotiateContext::PreauthIntegrityCapabilities(_) => 0x0001,
            NegotiateContext::EncryptionCapabilities(_) => 0x0002,
            NegotiateContext::CompressionCapabilities(_) => 0x0003,
            NegotiateContext::NetnameNegotiateContextId(_) => 0x0005,
            NegotiateContext::TransportCapabilities(_) => 0x0006,
            NegotiateContext::SigningCapabilities(_) => 0x0008,
        }
    }

    fn encode_context_id(ctx_id: &str) -> Bytes {
        let ctx_id: &[u8] = ctx_id.as_bytes();
        let mut buff: BytesMut = BytesMut::with_capacity(ctx_id.len());
        buff.put(ctx_id);
        buff.freeze()
    }
}

/// ## PreauthIntegrityCapabilitiesData
///
/// Data associated to PreauthIntegrityCapabilities
#[derive(Debug)]
struct PreauthIntegrityCapabilitiesData {
    hash_algorithms: Vec<HashAlgorithm>,
    salt: Salt,
}

impl Encode for PreauthIntegrityCapabilitiesData {
    fn encode(&self) -> Bytes {
        let buff_size: usize =
            (self.hash_algorithms.len() as usize * 2) + (self.salt.data().len() as usize) + 4;
        let mut buff: BytesMut = BytesMut::with_capacity(buff_size);
        buff.put_u16(self.hash_algorithms.len() as u16);
        buff.put_u16(self.salt.data().len() as u16);
        // Put algos
        self.hash_algorithms
            .iter()
            .for_each(|x| buff.put_u16(*x as u16));
        // Put salt
        buff.put(self.salt.data());
        buff.freeze()
    }
}

/// ## EncryptionCapabilitiesData
///
/// Data associated to EncryptionCapabilities
#[derive(Debug)]
struct EncryptionCapabilitiesData {
    ciphers: Vec<Cipher>,
}

impl Encode for EncryptionCapabilitiesData {
    fn encode(&self) -> Bytes {
        let buf_size: usize = 2 + (2 * self.ciphers.len() as usize);
        let mut buff: BytesMut = BytesMut::with_capacity(buf_size);
        buff.put_u16(self.ciphers.len() as u16);
        self.ciphers.iter().for_each(|x| buff.put_u16(*x as u16));
        buff.freeze()
    }
}

/// ## CompressionCapabilitiesData
///
/// Data associated to CompressionCapabilities; pavao doesn't support compression
#[derive(Debug)]
struct CompressionCapabilitiesData;

impl Encode for CompressionCapabilitiesData {
    fn encode(&self) -> Bytes {
        let buff: &[u8] = &[
            0x00, 0x00, // Count
            0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x00, // Flags
        ];
        Bytes::from(buff)
    }
}

/// ## CompressionCapabilitiesData
///
/// Data associated to TransportCapabilities
#[derive(Debug)]
struct TransportCapabilitiesData;

impl Encode for TransportCapabilitiesData {
    fn encode(&self) -> Bytes {
        let buff: &[u8] = &[0x00, 0x00, 0x00, 0x01];
        Bytes::from(buff)
    }
}

/// ## SigningCapabilitiesData
///
/// Data associated to SigningCapabilities
#[derive(Debug)]
struct SigningCapabilitiesData {
    algorithms: Vec<SigningAlgorithm>,
}

impl Encode for SigningCapabilitiesData {
    fn encode(&self) -> Bytes {
        let buf_size: usize = (self.algorithms.len() * 2) + 2;
        let mut buff: BytesMut = BytesMut::with_capacity(buf_size);
        buff.put_u16(self.algorithms.len() as u16);
        self.algorithms.iter().for_each(|x| buff.put_u16(*x as u16));
        buff.freeze()
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn test_smb2_messages_negotiate_preauth_integrity_capabilities_data() {
        let salt: Salt = Salt::new();
        let mut expected: Vec<u8> = vec![
            0x00, 0x01, // type
            0x00, 0x26, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0x00, 0x01, 0x00, 0x20, 0x00, 0x01,
        ];
        salt.data().iter().for_each(|x| expected.push(*x));
        let data: NegotiateContext =
            NegotiateContext::PreauthIntegrityCapabilities(PreauthIntegrityCapabilitiesData {
                hash_algorithms: vec![HashAlgorithm::Sha512],
                salt,
            });
        assert_eq!(data.encode().to_vec(), expected.as_slice());
    }

    #[test]
    fn test_smb2_messages_negotiate_encryption_capabilities_data() {
        let data: NegotiateContext =
            NegotiateContext::EncryptionCapabilities(EncryptionCapabilitiesData {
                ciphers: vec![
                    Cipher::Aes128Ccm,
                    Cipher::Aes128Gcm,
                    Cipher::Aes256Ccm,
                    Cipher::Aes256Gcm,
                ],
            });
        assert_eq!(
            data.encode().to_vec(),
            vec![
                0x00, 0x02, // type
                0x00, 0x0a, // length
                0x00, 0x00, 0x00, 0x00, // RFU
                0x00, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04 // capabilities
            ]
        );
    }

    #[test]
    fn test_smb2_messages_negotiate_compression_capabilities_data() {
        let data: NegotiateContext =
            NegotiateContext::CompressionCapabilities(CompressionCapabilitiesData {});
        assert_eq!(
            data.encode().to_vec(),
            vec![
                0x00, 0x03, // type
                0x00, 0x08, // length
                0x00, 0x00, 0x00, 0x00, // RFU
                0x00, 0x00, // Count
                0x00, 0x00, // Padding
                0x00, 0x00, 0x00, 0x00, // Flags
            ]
        );
    }

    #[test]
    fn test_smb2_messages_negotiate_transport_capabilities_data() {
        let data: NegotiateContext =
            NegotiateContext::TransportCapabilities(TransportCapabilitiesData {});
        assert_eq!(
            data.encode().to_vec(),
            vec![
                0x00, 0x06, // type
                0x00, 0x04, // length
                0x00, 0x00, 0x00, 0x00, // RFU
                0x00, 0x00, 0x00, 0x01 // Capabilities
            ]
        );
    }

    #[test]
    fn test_smb2_messages_negotiate_context_id() {
        let data: NegotiateContext =
            NegotiateContext::NetnameNegotiateContextId(String::from("CIAO"));
        assert_eq!(
            data.encode().to_vec(),
            vec![
                0x00, 0x05, // type
                0x00, 0x04, // length
                0x00, 0x00, 0x00, 0x00, // RFU
                0x43, 0x49, 0x41, 0x4F // name
            ]
        );
    }

    #[test]
    fn test_smb2_messages_negotiate_signing_capabilities_data() {
        let data: NegotiateContext =
            NegotiateContext::SigningCapabilities(SigningCapabilitiesData {
                algorithms: vec![
                    SigningAlgorithm::AesCmac,
                    SigningAlgorithm::HmacSha256,
                    SigningAlgorithm::AesGmac,
                ],
            });
        assert_eq!(
            data.encode().to_vec(),
            vec![
                0x00, 0x08, // type
                0x00, 0x08, // length
                0x00, 0x00, 0x00, 0x00, // RFU
                0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 // algos
            ]
        );
    }

    // TODO: test NegotiateRequest (new + encode)
}
