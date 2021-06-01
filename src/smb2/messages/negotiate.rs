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
use crate::smb2::types::{Cipher, Guid, HashAlgorithm, HashOptions, SigningAlgorithm};
use crate::smb2::ProtocolVersion;
use crate::utils::pad_to_32_bit;
// deps
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// ## NegotiateRequest
///
/// Represents a Negotiate
#[derive(Debug)]
pub(crate) struct NegotiateRequest {
    struct_size: u16,
    security_mode: SecurityMode,
    capabilities: Smbv3Capabilities,
    client_guid: Guid, // 16 bytes
    // context_offset: u32, // 0x311 only
    start_time: u64, // always 0; not for 0x311
    dialects: Vec<ProtocolVersion>,
    ctx_list: Vec<NegotiateContext>, // List of negotiate context (length match context_count; 0x311 only)
}

/// ## SecurityMode
///
/// Describes the security mode in negotiation
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
        // const DFS = 0x00000001; // Distributed file system
        // const LEASING = 0x00000002;
        // const LARGE_MTU = 0x00000004; NOT SUPPORTED
        // const MULTI_CHANNEL = 0x00000008; // NOT SUPPORTED
        // const PERSISTENT_HANDLES = 0x00000010; // NOT SUPPORTED
        // const DIRECTORY_LEASING = 0x00000020; NOT SUPPORTED
        const ENCRYPTION = 0x00000040;
    }
}

impl NegotiateRequest {
    /// ### new
    ///
    /// Create a new NegotiateRequest
    pub fn new(
        dialects: Vec<ProtocolVersion>,
        guid: Guid,
        hash: HashOptions,
        ciphers: Vec<Cipher>,
        signatures: Vec<SigningAlgorithm>,
    ) -> Self {
        let security_mode: SecurityMode = match signatures.len() {
            0 => SecurityMode::Enabled,
            _ => SecurityMode::Required,
        };
        // Prepare capabilities
        let capabilities: Smbv3Capabilities = Smbv3Capabilities::ENCRYPTION;
        // Prepare contexts list
        let ctx_list: Vec<NegotiateContext> = match dialects.contains(&ProtocolVersion::V311) {
            false => vec![],
            true => {
                vec![
                    NegotiateContext::PreauthIntegrity(PreauthIntegrityData {
                        hash_algorithms: hash.algorithms().to_vec(),
                        salt: hash.salt().to_vec(),
                    }),
                    NegotiateContext::Encryption(EncryptionData { ciphers }),
                    NegotiateContext::Signing(SigningData {
                        algorithms: signatures,
                    }),
                ]
            }
        };
        Self {
            struct_size: 36,
            security_mode,
            capabilities,
            client_guid: guid,
            start_time: 0x00,
            dialects,
            ctx_list,
        }
    }
}

impl Encode for NegotiateRequest {
    fn encode(&self) -> Bytes {
        // Encode contexts
        let contexts_buffers: Vec<Bytes> = self.ctx_list.iter().map(|x| x.encode()).collect();
        // Calc contexts size
        let contexts_size: usize = contexts_buffers.iter().map(|x| x.len()).sum();
        // Buff len is: 36 (base) + 2 bytes for each dialect; length for context is variable
        let buf_size: usize = 36 + (self.dialects.len() * 2);
        let (mut buf_size, mut padding): (usize, usize) = {
            let val: usize = pad_to_32_bit(buf_size);
            (val, val - buf_size)
        };
        // Align to 64 bit boundaries
        if contexts_size > 0 && buf_size & 0x04 != 0 {
            buf_size += 4;
            padding += 4;
        }
        let mut buff: BytesMut = BytesMut::with_capacity(buf_size + contexts_size);
        buff.put_u16(self.struct_size);
        buff.put_u16(self.dialects.len() as u16);
        buff.put_u16(self.security_mode as u16);
        buff.put_u16(0x0000); // RFU
        buff.put_u32(self.capabilities.bits());
        buff.put(self.client_guid.data());
        match self.dialects.contains(&ProtocolVersion::V311) {
            false => buff.put_u64(self.start_time),
            true => {
                let context_offset: u32 = (buf_size + padding + 64) as u32;
                buff.put_u32(context_offset); // Offset from header start
                buff.put_u16(contexts_buffers.len() as u16);
                buff.put_u16(0x0000); // RFU
            }
        }
        // Put dialects
        self.dialects.iter().for_each(|x| buff.put_u16(*x as u16));
        // Add padding
        if !contexts_buffers.is_empty() {
            (0..padding).for_each(|_| buff.put_u8(0x00));
        }
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
    PreauthIntegrity(PreauthIntegrityData),
    Encryption(EncryptionData),
    Signing(SigningData),
}

impl Encode for NegotiateContext {
    fn encode(&self) -> Bytes {
        // Encode data
        let buff_data: Bytes = match self {
            NegotiateContext::Encryption(data) => data.encode(),
            NegotiateContext::PreauthIntegrity(data) => data.encode(),
            NegotiateContext::Signing(data) => data.encode(),
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
            NegotiateContext::PreauthIntegrity(_) => 0x0001,
            NegotiateContext::Encryption(_) => 0x0002,
            NegotiateContext::Signing(_) => 0x0008,
        }
    }

    fn encode_context_id(ctx_id: &str) -> Bytes {
        let ctx_id: &[u8] = ctx_id.as_bytes();
        let mut buff: BytesMut = BytesMut::with_capacity(ctx_id.len());
        buff.put(ctx_id);
        buff.freeze()
    }
}

/// ## PreauthIntegrityData
///
/// Data associated to PreauthIntegrity
#[derive(Debug)]
struct PreauthIntegrityData {
    hash_algorithms: Vec<HashAlgorithm>,
    salt: Vec<u8>,
}

impl Encode for PreauthIntegrityData {
    fn encode(&self) -> Bytes {
        let buff_size: usize =
            (self.hash_algorithms.len() as usize * 2) + (self.salt.len() as usize) + 4;
        let mut buff: BytesMut = BytesMut::with_capacity(buff_size);
        buff.put_u16(self.hash_algorithms.len() as u16);
        buff.put_u16(self.salt.len() as u16);
        // Put algos
        self.hash_algorithms
            .iter()
            .for_each(|x| buff.put_u16(*x as u16));
        // Put salt
        buff.put(self.salt.as_slice());
        buff.freeze()
    }
}

/// ## EncryptionData
///
/// Data associated to Encryption
#[derive(Debug)]
struct EncryptionData {
    ciphers: Vec<Cipher>,
}

impl Encode for EncryptionData {
    fn encode(&self) -> Bytes {
        let buf_size: usize = 2 + (2 * self.ciphers.len() as usize);
        let mut buff: BytesMut = BytesMut::with_capacity(buf_size);
        buff.put_u16(self.ciphers.len() as u16);
        self.ciphers.iter().for_each(|x| buff.put_u16(*x as u16));
        buff.freeze()
    }
}

/// ## SigningData
///
/// Data associated to Signing
#[derive(Debug)]
struct SigningData {
    algorithms: Vec<SigningAlgorithm>,
}

impl Encode for SigningData {
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
    use crate::smb2::types::Salt;

    use pretty_assertions::assert_eq;
    use std::convert::TryFrom;

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
        let data: NegotiateContext = NegotiateContext::PreauthIntegrity(PreauthIntegrityData {
            hash_algorithms: vec![HashAlgorithm::Sha512],
            salt: salt.data().to_vec(),
        });
        assert_eq!(data.encode().to_vec(), expected.as_slice());
    }

    #[test]
    fn test_smb2_messages_negotiate_encryption_capabilities_data() {
        let data: NegotiateContext = NegotiateContext::Encryption(EncryptionData {
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
    fn test_smb2_messages_negotiate_signing_capabilities_data() {
        let data: NegotiateContext = NegotiateContext::Signing(SigningData {
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

    #[test]
    fn test_smb2_messages_negotiate_request() {
        let guid_data: Vec<u8> = vec![
            0xca, 0xfe, 0xba, 0xbe, 0x15, 0xde, 0xad, 0xa1, 0x1a, 0x10, 0x03, 0xba, 0x71, 0x0f,
            0xed, 0x00,
        ];
        let guid: Guid = Guid::try_from(guid_data.clone()).ok().unwrap();
        // With v3.11 + all
        let mut options: HashOptions = HashOptions::new();
        options.add_algorithm(HashAlgorithm::Sha512);
        let salt: Vec<u8> = options.salt().to_vec();
        let request: NegotiateRequest = NegotiateRequest::new(
            vec![
                ProtocolVersion::V300,
                ProtocolVersion::V302,
                ProtocolVersion::V311,
            ],
            guid,
            options,
            vec![Cipher::Aes256Gcm],
            vec![SigningAlgorithm::HmacSha256],
        );
        assert_eq!(
            request
                .capabilities
                .intersects(Smbv3Capabilities::ENCRYPTION),
            true
        );
        assert_eq!(request.ctx_list.len(), 3);
        assert_eq!(request.dialects.len(), 3);
        assert_eq!(request.security_mode, SecurityMode::Required);
        // Encode
        let data: Bytes = request.encode();
        // Build expected
        let mut expected: Vec<u8> = vec![
            0x00, 36, // Struct size
            0x00, 0x03, // dialects count
            0x00, 0x02, // Required security mode
            0x00, 0x00, // RFU
            0x00, 0x00, 0x00, 0x40, // Capabilities
            0xca, 0xfe, 0xba, 0xbe, 0x15, 0xde, 0xad, 0xa1, 0x1a, 0x10, 0x03, 0xba, 0x71, 0x0f,
            0xed, 0x00, // GUID
            0x00, 0x00, 0x00, 0x76, // 118 from header
            0x00, 0x03, // Always 3 if smbv3.11
            0x00, 0x00, // RFU2
            0x03, 0x00, // 3.00
            0x03, 0x02, // 3.02
            0x03, 0x11, // 3.11
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding (6)
            // -- pre auth
            0x00, 0x01, // type
            0x00, 0x26, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0x00, 0x01, 0x00, 0x20, 0x00, 0x01,
        ];
        salt.iter().for_each(|x| expected.push(*x));
        // Extend expected
        expected.extend(&vec![
            //  -- encryption
            0x00, 0x02, // type
            0x00, 0x04, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0x00, 0x01, 0x00, 0x04, // Ciphers
            // -- signing context
            0x00, 0x08, // type
            0x00, 0x04, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0x00, 0x01, 0x00, 0x00, // HMAC sha 256
        ]);
        assert_eq!(data.to_vec(), expected);
        // SMB2 without signatures
        let guid: Guid = Guid::try_from(guid_data.clone()).ok().unwrap();
        let options: HashOptions = HashOptions::new();
        let request: NegotiateRequest = NegotiateRequest::new(
            vec![ProtocolVersion::V202, ProtocolVersion::V210],
            guid,
            options,
            vec![],
            vec![],
        );
        assert_eq!(
            request
                .capabilities
                .intersects(Smbv3Capabilities::ENCRYPTION),
            true
        );
        assert_eq!(request.ctx_list.len(), 0);
        assert_eq!(request.dialects.len(), 2);
        assert_eq!(request.security_mode, SecurityMode::Enabled);
        // Encode
        let data: Bytes = request.encode();
        // Build expected
        let expected: Vec<u8> = vec![
            0x00, 36, // Struct size
            0x00, 0x02, // dialects count
            0x00, 0x01, // Enabled security mode
            0x00, 0x00, // RFU
            0x00, 0x00, 0x00, 0x40, // Capabilities
            0xca, 0xfe, 0xba, 0xbe, 0x15, 0xde, 0xad, 0xa1, 0x1a, 0x10, 0x03, 0xba, 0x71, 0x0f,
            0xed, 0x00, // GUID
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client time
            0x02, 0x02, // 2.02
            0x02, 0x10, // 2.10
        ];
        assert_eq!(data.to_vec(), expected);
    }

    // TODO: test decode
}
