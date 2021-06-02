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
use crate::smb2::DialectRevision;
use crate::utils::pad_to_32_bit;
// deps
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryFrom;

/// ## NegotiateRequest
///
/// Represents a Negotiate request
#[derive(Debug)]
pub(crate) struct NegotiateRequest {
    struct_size: u16,
    security_mode: SecurityMode,
    capabilities: Smbv3Capabilities,
    client_guid: Guid, // 16 bytes
    // context_offset: u32, // 0x311 only
    start_time: u64, // always 0; not for 0x311
    dialects: Vec<DialectRevision>,
    ctx_list: Vec<NegotiateContext>, // List of negotiate context (length match context_count; 0x311 only)
}

/// ## NegotiateResponse
///
/// Represents a Negotiate response
#[derive(Debug)]
pub(crate) struct NegotiateResponse {
    struct_size: u16,
    security_mode: SecurityMode,
    dialect_revision: DialectRevision,
    // ctx_count: u16
    server_guid: Guid,
    capabilities: Smbv3Capabilities,
    max_transact_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    system_time: u64,
    server_start_time: u64,
    // security_buf_offset: u16,
    // security_buf_length: u16,
    // context_offset: u32,
    ctx_list: Vec<NegotiateContext>,
}

/// ## SecurityMode
///
/// Describes the security mode in negotiation
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum SecurityMode {
    Enabled = 0x0001,
    Required = 0x0002,
}

impl TryFrom<u16> for SecurityMode {
    type Error = &'static str;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0001 => Ok(SecurityMode::Enabled),
            0x0002 => Ok(SecurityMode::Required),
            _ => Err("Invalid SecurityMode"),
        }
    }
}

bitflags! {
    /// ## Smbv3Capabilities
    ///
    /// Describes the smb3 capabilities in negotiation
    struct Smbv3Capabilities: u32 {
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
        dialects: Vec<DialectRevision>,
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
        let ctx_list: Vec<NegotiateContext> = match dialects.contains(&DialectRevision::V311) {
            false => vec![],
            true => {
                vec![
                    NegotiateContext::PreauthIntegrity(PreauthIntegrityData {
                        hash_algorithms: hash.algorithms().to_vec(),
                        salt: hash.salt().clone(),
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
        match self.dialects.contains(&DialectRevision::V311) {
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

impl NegotiateResponse {
    /// ### dialect_revision
    ///
    /// Returns agreed dialect revision
    pub fn dialect_revision(&self) -> DialectRevision {
        self.dialect_revision
    }

    /// ### support_encryption
    ///
    /// Returns whether from returned capabilities server
    /// supports encryption
    pub fn support_encryption(&self) -> bool {
        self.capabilities.intersects(Smbv3Capabilities::ENCRYPTION)
    }

    /// ### max_transact_size
    ///
    /// Returns max transaction size
    pub fn max_transact_size(self) -> usize {
        self.max_transact_size as usize
    }

    /// ### max_read_size
    ///
    /// Returns max read size
    pub fn max_read_size(&self) -> usize {
        self.max_read_size as usize
    }

    /// ### max_write_size
    ///
    /// Returns max write size
    pub fn max_write_size(&self) -> usize {
        self.max_write_size as usize
    }

    /// ### get_hash_algorithm
    ///
    /// Get agreed hash algorithm, if any
    pub fn get_hash_algorithm(&self) -> Option<HashAlgorithm> {
        // Filter contexsts
        let ctx: Option<&NegotiateContext> = self
            .ctx_list
            .iter()
            .filter(|x| x.is_pre_auth_context())
            .next();
        match ctx {
            Some(NegotiateContext::PreauthIntegrity(ctx)) => ctx.hash_algorithms.get(0).copied(),
            _ => None,
        }
    }

    /// ### get_hash_algorithm
    ///
    /// Get agreed hash algorithm, if any
    pub fn get_salt(&self) -> Option<Salt> {
        // Filter contexsts
        let ctx: Option<&NegotiateContext> = self
            .ctx_list
            .iter()
            .filter(|x| x.is_pre_auth_context())
            .next();
        match ctx {
            Some(NegotiateContext::PreauthIntegrity(ctx)) => Some(ctx.salt.clone()),
            _ => None,
        }
    }

    /// ### get_cipher
    ///
    /// Get agreed cipher for encryption, if any
    pub fn get_cipher(&self) -> Option<Cipher> {
        // Filter contexsts
        let ctx: Option<&NegotiateContext> = self
            .ctx_list
            .iter()
            .filter(|x| x.is_encryption_context())
            .next();
        match ctx {
            Some(NegotiateContext::Encryption(ctx)) => ctx.ciphers.get(0).copied(),
            _ => None,
        }
    }

    /// ### get_cipher
    ///
    /// Get agreed cipher for encryption, if any
    pub fn get_signing_algorithm(&self) -> Option<SigningAlgorithm> {
        // Filter contexsts
        let ctx: Option<&NegotiateContext> = self
            .ctx_list
            .iter()
            .filter(|x| x.is_signing_context())
            .next();
        match ctx {
            Some(NegotiateContext::Signing(ctx)) => ctx.algorithms.get(0).copied(),
            _ => None,
        }
    }
}

impl Decode for NegotiateResponse {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {
        if buff.remaining() < 65 {
            return Err(Error::InvalidSyntax);
        }
        let struct_size: u16 = buff.get_u16();
        let security_mode: SecurityMode =
            SecurityMode::try_from(buff.get_u16()).map_err(|_| Error::InvalidSyntax)?;
        let dialect_revision: DialectRevision =
            DialectRevision::try_from(buff.get_u16()).map_err(|_| Error::InvalidSyntax)?;
        let context_count: u16 = buff.get_u16();
        let mut server_guid: Vec<u8> = vec![0; 16];
        buff.copy_to_slice(server_guid.as_mut_slice());
        let server_guid: Guid = Guid::try_from(server_guid).map_err(|_| Error::InvalidSyntax)?;
        let capabilities: Smbv3Capabilities = match Smbv3Capabilities::from_bits(buff.get_u32()) {
            Some(c) => c,
            None => return Err(Error::InvalidSyntax),
        };
        let max_transact_size: u32 = buff.get_u32();
        let max_read_size: u32 = buff.get_u32();
        let max_write_size: u32 = buff.get_u32();
        let system_time: u64 = buff.get_u64();
        let server_start_time: u64 = buff.get_u64();
        let security_buffer_offset: u16 = buff.get_u16();
        let security_buffer_len: u16 = buff.get_u16();
        let ctx_offset: u32 = buff.get_u32();
        let offset: usize = security_buffer_offset as usize - 64 - 64;
        buff.advance(offset);
        let mut security_buffer: Vec<u8> = vec![0; security_buffer_len as usize];
        buff.copy_to_slice(security_buffer.as_mut_slice());
        // Prepare context list
        let ctx_list: Vec<NegotiateContext> = match dialect_revision {
            DialectRevision::V311 => {
                let mut accumulator: usize =
                    security_buffer_offset as usize - 64 + security_buffer_len as usize;
                let diff: usize = (ctx_offset as usize - 64) - accumulator;
                // Pad to 8
                buff.advance(diff);
                accumulator += diff;
                // Decode all contexts
                let mut ctx_list: Vec<NegotiateContext> =
                    Vec::with_capacity(context_count as usize);
                for _ in 0..context_count {
                    let before: usize = buff.remaining();
                    ctx_list.push(NegotiateContext::decode(buff)?);
                    // 8-byte align
                    accumulator += before - buff.remaining();
                    let steps: usize = 8 - (accumulator % 8);
                    if steps != 8 && buff.remaining() >= steps {
                        buff.advance(steps);
                    }
                }
                ctx_list
            }
            _ => vec![],
        };
        Ok(NegotiateResponse {
            struct_size,
            security_mode,
            dialect_revision,
            server_guid,
            capabilities,
            max_transact_size,
            max_read_size,
            max_write_size,
            system_time,
            server_start_time,
            ctx_list,
        })
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
    Ignore,
}

impl Encode for NegotiateContext {
    fn encode(&self) -> Bytes {
        // Encode data
        let buff_data: Bytes = match self {
            NegotiateContext::Encryption(data) => data.encode(),
            NegotiateContext::PreauthIntegrity(data) => data.encode(),
            NegotiateContext::Signing(data) => data.encode(),
            NegotiateContext::Ignore => panic!("Trying to encode an Ignore negotiate context!!!"),
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

impl Decode for NegotiateContext {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {
        if buff.remaining() < 8 {
            return Err(Error::InvalidSyntax);
        }
        let context_type: u16 = buff.get_u16();
        let data_len: usize = buff.get_u16() as usize;
        // RFU
        buff.advance(4);
        // Verify buff remaining
        if buff.remaining() < data_len {
            return Err(Error::InvalidSyntax);
        }
        // Decode context
        match context_type {
            0x0001 => Ok(NegotiateContext::PreauthIntegrity(
                PreauthIntegrityData::decode(buff)?,
            )),
            0x0002 => Ok(NegotiateContext::Encryption(EncryptionData::decode(buff)?)),
            0x0008 => Ok(NegotiateContext::Signing(SigningData::decode(buff)?)),
            0x0003 | 0x0005 | 0x0006 | 0x0007 => {
                // Advance by length
                buff.advance(data_len);
                Ok(NegotiateContext::Ignore)
            }
            _ => Err(Error::InvalidSyntax), // Invalid type
        }
    }
}

impl NegotiateContext {
    pub fn get_context_type(&self) -> u16 {
        match self {
            NegotiateContext::PreauthIntegrity(_) => 0x0001,
            NegotiateContext::Encryption(_) => 0x0002,
            NegotiateContext::Signing(_) => 0x0008,
            NegotiateContext::Ignore => panic!("Trying to encode an Ignore context!!!"),
        }
    }

    fn encode_context_id(ctx_id: &str) -> Bytes {
        let ctx_id: &[u8] = ctx_id.as_bytes();
        let mut buff: BytesMut = BytesMut::with_capacity(ctx_id.len());
        buff.put(ctx_id);
        buff.freeze()
    }

    pub fn is_pre_auth_context(&self) -> bool {
        match self {
            NegotiateContext::PreauthIntegrity(_) => true,
            _ => false,
        }
    }

    pub fn is_encryption_context(&self) -> bool {
        match self {
            NegotiateContext::Encryption(_) => true,
            _ => false,
        }
    }

    pub fn is_signing_context(&self) -> bool {
        match self {
            NegotiateContext::Signing(_) => true,
            _ => false,
        }
    }
}

/// ## PreauthIntegrityData
///
/// Data associated to PreauthIntegrity
#[derive(Debug)]
struct PreauthIntegrityData {
    hash_algorithms: Vec<HashAlgorithm>,
    salt: Salt,
}

impl Encode for PreauthIntegrityData {
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

impl Decode for PreauthIntegrityData {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {
        let hash_count: usize = buff.get_u16() as usize;
        let salt_len: usize = buff.get_u16() as usize;
        // Get algos
        if buff.remaining() < hash_count {
            return Err(Error::InvalidSyntax);
        }
        let mut hash_algorithms: Vec<HashAlgorithm> = Vec::with_capacity(hash_count);
        for _ in 0..hash_count {
            hash_algorithms
                .push(HashAlgorithm::try_from(buff.get_u16()).map_err(|_| Error::InvalidSyntax)?);
        }
        // Read salt
        if buff.remaining() < salt_len {
            return Err(Error::InvalidSyntax);
        }
        let mut salt: Vec<u8> = vec![0; salt_len];
        buff.copy_to_slice(salt.as_mut_slice());
        let salt: Salt = Salt::from(salt);
        Ok(Self {
            hash_algorithms,
            salt,
        })
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

impl Decode for EncryptionData {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {
        if buff.remaining() < 4 {
            return Err(Error::InvalidSyntax);
        }
        buff.advance(2); // cipher length
                         // Get cipher
        let cipher: Cipher = Cipher::try_from(buff.get_u16()).map_err(|_| Error::InvalidSyntax)?;
        Ok(EncryptionData {
            ciphers: vec![cipher],
        })
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

impl Decode for SigningData {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {
        if buff.remaining() < 4 {
            return Err(Error::InvalidSyntax);
        }
        buff.advance(2); // Length
        let algo: SigningAlgorithm =
            SigningAlgorithm::try_from(buff.get_u16()).map_err(|_| Error::InvalidSyntax)?;
        Ok(SigningData {
            algorithms: vec![algo],
        })
    }
}

#[cfg(test)]
mod test {

    use super::*;

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
            salt,
        });
        assert_eq!(data.encode().to_vec(), expected.as_slice());
        // Decode
        let mut buffer: Bytes = Bytes::from(vec![
            0x00, 0x01, // type
            0x00, 0x0a, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0x00, 0x01, 0x00, 0x04, // Length
            0x00, 0x01, // Hash signature
            0xca, 0xfe, 0xba, 0xbe, // Salt
        ]);
        let data: NegotiateContext = NegotiateContext::decode(&mut buffer).ok().unwrap();
        if let NegotiateContext::PreauthIntegrity(data) = data {
            assert_eq!(data.hash_algorithms[0], HashAlgorithm::Sha512);
            assert_eq!(data.salt.data().to_vec(), vec![0xca, 0xfe, 0xba, 0xbe]);
        } else {
            panic!("Bad context");
        }
        // Bad decode
        let mut buffer: Bytes = Bytes::from(vec![
            0x00, 0x01, // type
            0x00, 0x0e, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0x00, 0x01, 0x00, 0x08, // Length
            0x00, 0x01, // Hash signature
        ]);
        assert!(NegotiateContext::decode(&mut buffer).is_err());
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
        // Decode
        let mut buffer: Bytes = Bytes::from(vec![
            0x00, 0x02, // type
            0x00, 0x04, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0x00, 0x01, 0x00, 0x04, // Ciphers
        ]);
        let data: NegotiateContext = NegotiateContext::decode(&mut buffer).ok().unwrap();
        if let NegotiateContext::Encryption(data) = data {
            assert_eq!(data.ciphers[0], Cipher::Aes256Gcm);
        } else {
            panic!("Bad context");
        }
        // Bad decode
        let mut buffer: Bytes = Bytes::from(vec![
            0x00, 0x02, // type
            0x00, 0x0e, // length
            0x00, 0x00, 0x00, 0x00, // RFU
        ]);
        assert!(NegotiateContext::decode(&mut buffer).is_err());
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
        // Decode
        let mut buffer: Bytes = Bytes::from(vec![
            0x00, 0x08, // type
            0x00, 0x04, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0x00, 0x01, 0x00, 0x00, // Algos
        ]);
        let data: NegotiateContext = NegotiateContext::decode(&mut buffer).ok().unwrap();
        if let NegotiateContext::Signing(data) = data {
            assert_eq!(data.algorithms[0], SigningAlgorithm::HmacSha256);
        } else {
            panic!("Bad context");
        }
        // Bad decode
        let mut buffer: Bytes = Bytes::from(vec![
            0x00, 0x08, // type
            0x00, 0x0e, // length
            0x00, 0x00, 0x00, 0x00, // RFU
        ]);
        assert!(NegotiateContext::decode(&mut buffer).is_err());
    }

    #[test]
    fn test_smb2_messages_negotiate_other_contexts() {
        let mut buffer: Bytes = Bytes::from(vec![
            0x00, 0x06, // type
            0x00, 0x04, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0xca, 0xfe, 0xba, 0xbe,
        ]);
        let data: NegotiateContext = NegotiateContext::decode(&mut buffer).ok().unwrap();
        match data {
            NegotiateContext::Ignore => {}
            _ => panic!("Is not ignore"),
        }
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
        let salt: Vec<u8> = options.salt().data().to_vec();
        let request: NegotiateRequest = NegotiateRequest::new(
            vec![
                DialectRevision::V300,
                DialectRevision::V302,
                DialectRevision::V311,
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
            vec![DialectRevision::V202, DialectRevision::V210],
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

    #[test]
    fn test_smb2_messages_negotiate_response() {
        // Data with smb v3.11
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 65, // Struct size
            0x00, 0x02, // security moded
            0x03, 0x11, // dialect revision
            0x00, 0x04, // context count
            0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, // server guid
            0x00, 0x00, 0x00, 0x40, // capabilities
            0xff, 0xff, 0xff, 0xff, // transact size
            0xff, 0xff, 0xff, 0xff, // read size
            0xff, 0xff, 0xff, 0xff, // write size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // system time
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // start time
            0x00, 0x86, // 134 buffer offset
            0x00, 0x08, // buffer length
            0x00, 0x00, 0x00, 0x90, // context offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding security buffer
            0xca, 0xfe, 0xba, 0xbe, 0x15, 0xde, 0xad, 0x00, // buffer
            0x00, 0x00, // Padding
            // -- pre auth
            0x00, 0x01, // type
            0x00, 0x0a, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0x00, 0x01, 0x00, 0x04, // Length
            0x00, 0x01, // Hash signature
            0xca, 0xfe, 0xba, 0xbe, // Salt
            // -- padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (6)
            // -- encryption
            0x00, 0x02, // type
            0x00, 0x04, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0x00, 0x01, 0x00, 0x04, // Ciphers
            // -- padding
            0x00, 0x00, // padding (2)
            // -- signatures
            0x00, 0x08, // type
            0x00, 0x04, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0x00, 0x01, 0x00, 0x00, // Algos
            // -- padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (6)
            // -- other context
            0x00, 0x05, // types
            0x00, 0x04, // length
            0x00, 0x00, 0x00, 0x00, // RFU
            0xca, 0xfe, 0xba, 0xbe,
        ]);
        let response: NegotiateResponse = NegotiateResponse::decode(&mut buff).ok().unwrap();
        // Verify response
        assert_eq!(response.dialect_revision(), DialectRevision::V311);
        assert_eq!(response.get_cipher().unwrap(), Cipher::Aes256Gcm);
        assert_eq!(
            response.get_hash_algorithm().unwrap(),
            HashAlgorithm::Sha512
        );
        assert_eq!(
            response.get_salt().unwrap().data().to_vec(),
            vec![0xca, 0xfe, 0xba, 0xbe]
        );
        assert_eq!(
            response.get_signing_algorithm().unwrap(),
            SigningAlgorithm::HmacSha256
        );
        assert_eq!(response.support_encryption(), true);
        assert_eq!(response.max_read_size(), 0xffffffff);
        assert_eq!(response.max_write_size(), 0xffffffff);
        assert_eq!(response.max_transact_size(), 0xffffffff);
        // without v3.11
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 65, // Struct size
            0x00, 0x01, // security moded
            0x02, 0x02, // dialect revision
            0x00, 0x04, // context count
            0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, // server guid
            0x00, 0x00, 0x00, 0x00, // capabilities
            0xff, 0xff, 0xff, 0xff, // transact size
            0xff, 0xff, 0xff, 0xff, // read size
            0xff, 0xff, 0xff, 0xff, // write size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // system time
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // start time
            0x00, 0x86, // 134 buffer offset
            0x00, 0x08, // buffer length
            0x00, 0x00, 0x00, 0x00, // context offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding security buffer
            0xca, 0xfe, 0xba, 0xbe, 0x15, 0xde, 0xad, 0x00, // buffer
        ]);
        let response: NegotiateResponse = NegotiateResponse::decode(&mut buff).ok().unwrap();
        // Verify response
        assert_eq!(response.dialect_revision(), DialectRevision::V202);
        assert_eq!(response.get_cipher(), None);
        assert_eq!(response.get_hash_algorithm(), None);
        assert!(response.get_salt().is_none());
        assert_eq!(response.get_signing_algorithm(), None);
        assert_eq!(response.support_encryption(), false);
        assert_eq!(response.max_read_size(), 0xffffffff);
        assert_eq!(response.max_write_size(), 0xffffffff);
        assert_eq!(response.max_transact_size(), 0xffffffff);
    }
}
