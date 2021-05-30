//! # error
//!
//! this modules exposes the SMB2 Error

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
use super::{Decode, Error, ErrorCode, SmbResult};
// deps
use bytes::Buf;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// ## ErrorResponse
///
/// Error response in the SMB2 protocol
#[derive(Debug)]
pub struct ErrorResponse {
    struct_size: u16,
    ctx_count: u8,
    // rfu 8
    byte_count: u32,
    pub error_data: Vec<ErrorContext>,
}

impl ErrorResponse {
    pub fn decode(buff: &mut dyn Buf, error_code: ErrorCode) -> SmbResult<Self> {
        if buff.remaining() < 8 {
            // Min len
            return Err(Error::InvalidSyntax);
        }
        let struct_size: u16 = buff.get_u16();
        let ctx_count: u8 = buff.get_u8();
        buff.advance(1); // RFU
        let byte_count: u32 = buff.get_u32();
        // Verify length for error_data
        if buff.remaining() < byte_count as usize {
            return Err(Error::InvalidSyntax);
        }
        // Collect error data
        let mut accumulator: usize = 8;
        let mut error_data: Vec<ErrorContext> = Vec::with_capacity(ctx_count as usize);
        for _ in 0..ctx_count {
            let before: usize = buff.remaining();
            error_data.push(ErrorContext::decode(buff, error_code)?);
            // 8-byte align
            accumulator += before - buff.remaining();
            if accumulator % 8 != 0 {
                buff.advance(accumulator % 8);
            }
        }
        Ok(ErrorResponse {
            struct_size,
            ctx_count,
            byte_count,
            error_data,
        })
    }
}

/// ## ErrorContext
///
/// Error context as expected by the `ErrorResponse`
#[derive(Debug)]
pub struct ErrorContext {
    data_length: u32,
    pub error_id: ErrorId,
    pub data: ErrorContextData,
}

impl ErrorContext {
    pub fn decode(buff: &mut dyn Buf, error_code: ErrorCode) -> SmbResult<Self> {
        if buff.remaining() < 8 {
            return Err(Error::InvalidSyntax);
        }
        let data_length: u32 = buff.get_u32();
        let error_id: ErrorId = match ErrorId::try_from(buff.get_u32()) {
            Ok(id) => id,
            Err(_) => return Err(Error::InvalidSyntax),
        };
        if buff.remaining() < data_length as usize {
            return Err(Error::InvalidSyntax);
        }
        let data: ErrorContextData = ErrorContextData::decode(buff, error_code)?;
        Ok(ErrorContext {
            data_length,
            error_id,
            data,
        })
    }
}

/// ## ErrorId
///
/// An identifier for the error context.
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorId {
    Default = 0x00000000,
    ShareRedirect = 0x72645253,
}

impl TryFrom<u32> for ErrorId {
    type Error = &'static str;

    fn try_from(status: u32) -> Result<Self, Self::Error> {
        match num::FromPrimitive::from_u32(status) {
            Some(err) => Ok(err),
            None => Err("Unknown error id"),
        }
    }
}

/// ## ErrorContextData
///
/// Error data formatted as specified in smb2
#[derive(Debug)]
pub enum ErrorContextData {
    SymbolicLink(SymbolicLinkError),
    ShareRedirect(ShareRedirectError),
    BufferTooSmall(u32),
}

impl ErrorContextData {
    pub fn decode(buff: &mut dyn Buf, error_code: ErrorCode) -> SmbResult<Self> {
        match error_code {
            ErrorCode::StoppedOnSymlink => Ok(Self::SymbolicLink(SymbolicLinkError::decode(buff)?)),
            ErrorCode::BadNetworkName => Ok(Self::ShareRedirect(ShareRedirectError::decode(buff)?)),
            ErrorCode::BufferTooSmall => Self::decode_buffer_too_small(buff),
            _ => Err(Error::InvalidSyntax),
        }
    }

    fn decode_buffer_too_small(buff: &mut dyn Buf) -> SmbResult<Self> {
        match buff.remaining() >= 4 {
            true => Ok(Self::BufferTooSmall(buff.get_u32())),
            false => Err(Error::InvalidSyntax),
        }
    }
}

/// ## SymbolicLinkError
///
/// The Symbolic Link Error Response is used to indicate that a symbolic link was encountered on create;
/// it describes the target path that the client MUST use if it requires to follow the symbolic link.
#[derive(Debug)]
pub struct SymbolicLinkError {
    symlink_length: u32,
    symlink_error_tag: u32,
    reparse_tag: u32,
    reparse_length: u16,
    unparsed_path_length: u16,
    substitute_name_offset: u16,
    substitute_name_length: u16,
    print_name_offset: u16,
    print_name_length: u16,
    pub flags: SymbolicLinkErrorFlags,
    pub substitute_name: String,
    pub print_name: String,
}

bitflags! {
    /// ## SymbolicLinkErrorFlags
    ///
    /// Describes symbolic link error flags
    pub struct SymbolicLinkErrorFlags: u32 {
        const ABSOLUTE = 0x00000000;
        const RELATIVE = 0x00000001;
    }
}

impl Decode for SymbolicLinkError {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {
        if buff.remaining() < 28 {
            return Err(Error::InvalidSyntax);
        }
        let symlink_length: u32 = buff.get_u32();
        if buff.remaining() < symlink_length as usize {
            return Err(Error::InvalidSyntax);
        }
        let symlink_error_tag: u32 = buff.get_u32();
        let reparse_tag: u32 = buff.get_u32();
        let reparse_length: u16 = buff.get_u16();
        let unparsed_path_length: u16 = buff.get_u16();
        let substitute_name_offset: u16 = buff.get_u16();
        let substitute_name_length: u16 = buff.get_u16();
        let print_name_offset: u16 = buff.get_u16();
        let print_name_length: u16 = buff.get_u16();
        let flags: SymbolicLinkErrorFlags = match SymbolicLinkErrorFlags::from_bits(buff.get_u32())
        {
            Some(f) => f,
            None => SymbolicLinkErrorFlags::empty(),
        };
        let (substitute_name, print_name): (String, String) = match substitute_name_offset
            < print_name_offset
        {
            false => {
                let diff: usize =
                    (substitute_name_offset - print_name_offset - print_name_length) as usize;
                // Advance
                buff.advance(print_name_offset as usize);
                let mut name_buff: Vec<u8> = vec![0; print_name_length as usize];
                buff.copy_to_slice(name_buff.as_mut_slice());
                let print_name: String = match std::str::from_utf8(name_buff.as_ref()) {
                    Ok(s) => s.to_string(),
                    Err(_) => String::new(),
                };
                buff.advance(diff);
                let mut name_buff: Vec<u8> = vec![0; substitute_name_length as usize];
                buff.copy_to_slice(name_buff.as_mut_slice());
                let substitute_name: String = match std::str::from_utf8(name_buff.as_ref()) {
                    Ok(s) => s.to_string(),
                    Err(_) => String::new(),
                };
                (substitute_name, print_name)
            }
            true => {
                let diff: usize =
                    (print_name_offset - substitute_name_offset - substitute_name_length) as usize;
                // advance
                buff.advance(substitute_name_offset as usize);
                let mut name_buff: Vec<u8> = vec![0; substitute_name_length as usize];
                buff.copy_to_slice(name_buff.as_mut_slice());
                let substitute_name: String = match std::str::from_utf8(name_buff.as_ref()) {
                    Ok(s) => s.to_string(),
                    Err(_) => String::new(),
                };
                buff.advance(diff);
                let mut name_buff: Vec<u8> = vec![0; print_name_length as usize];
                buff.copy_to_slice(name_buff.as_mut_slice());
                let print_name: String = match std::str::from_utf8(name_buff.as_ref()) {
                    Ok(s) => s.to_string(),
                    Err(_) => String::new(),
                };

                (substitute_name, print_name)
            }
        };
        Ok(SymbolicLinkError {
            symlink_length,
            symlink_error_tag,
            reparse_tag,
            reparse_length,
            unparsed_path_length,
            substitute_name_offset,
            substitute_name_length,
            print_name_offset,
            print_name_length,
            flags,
            substitute_name,
            print_name,
        })
    }
}

/// ## ShareRedirectError
///
/// Servers which negotiate SMB 3.1.1 or higher can return this error context to a client in response to a
/// tree connect request with the SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER bit set in the
/// Flags field of the SMB2 TREE_CONNECT request.
#[derive(Debug)]
pub struct ShareRedirectError {
    struct_size: u32,
    notification_type: u32,
    resource_name_offset: u32,
    resource_name_length: u32,
    // rfu
    target_type: u16,
    ip_addr_count: u32,
    pub ip_addr_move_list: Vec<MoveDstIpAddr>,
    pub resource_name: String,
}

impl Decode for ShareRedirectError {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {
        if buff.remaining() < 48 {
            return Err(Error::InvalidSyntax);
        }
        let struct_size: u32 = buff.get_u32();
        let notification_type: u32 = buff.get_u32();
        let resource_name_offset: u32 = buff.get_u32();
        let resource_name_length: u32 = buff.get_u32();
        buff.advance(2); // RFU
        let target_type: u16 = buff.get_u16();
        let ip_addr_count: u32 = buff.get_u32();
        if buff.remaining() < (ip_addr_count * 24) as usize {
            return Err(Error::InvalidSyntax);
        }
        let mut ip_addr_move_list: Vec<MoveDstIpAddr> = Vec::with_capacity(ip_addr_count as usize);
        for _ in 0..ip_addr_count {
            ip_addr_move_list.push(MoveDstIpAddr::decode(buff)?);
        }
        // Advance to offset
        let offset: usize = (resource_name_offset as usize) - ((ip_addr_count as usize * 24) + 24);
        if buff.remaining() < offset + (resource_name_length as usize) {
            return Err(Error::InvalidSyntax);
        }
        buff.advance(offset);
        let mut name_buff: Vec<u8> = vec![0; resource_name_length as usize];
        buff.copy_to_slice(name_buff.as_mut_slice());
        let resource_name: String = match std::str::from_utf8(name_buff.as_ref()) {
            Ok(s) => s.to_string(),
            Err(_) => String::new(),
        };
        Ok(ShareRedirectError {
            struct_size,
            notification_type,
            resource_name_offset,
            resource_name_length,
            target_type,
            ip_addr_count,
            ip_addr_move_list,
            resource_name,
        })
    }
}

/// ## MoveDstIpAddr
///
/// The MOVE_DST_IPADDR structure is used in Share Redirect Error Context Response to indicate the
/// destination IP address.
#[derive(Debug)]
pub struct MoveDstIpAddr {
    pub type_: MoveDstIpAddrType,
    // rfu
    pub addr: IpAddr,
}

bitflags! {
    /// ## MoveDstIpAddrType
    ///
    /// Type of ip address type
    pub struct MoveDstIpAddrType: u32 {
        const V4 = 0x00000001;
        const V6 = 0x00000002;
    }
}

impl Decode for MoveDstIpAddr {
    fn decode(buff: &mut dyn Buf) -> SmbResult<Self> {
        if buff.remaining() < 24 {
            return Err(Error::InvalidSyntax);
        }
        let type_: MoveDstIpAddrType = match MoveDstIpAddrType::from_bits(buff.get_u32()) {
            Some(f) => f,
            None => return Err(Error::InvalidSyntax),
        };
        buff.advance(4); // RFU
        let addr: IpAddr = match type_ {
            MoveDstIpAddrType::V4 => {
                let addr: Ipv4Addr =
                    Ipv4Addr::new(buff.get_u8(), buff.get_u8(), buff.get_u8(), buff.get_u8());
                buff.advance(12); // Empty
                IpAddr::V4(addr)
            }
            MoveDstIpAddrType::V6 => IpAddr::V6(Ipv6Addr::new(
                buff.get_u16(),
                buff.get_u16(),
                buff.get_u16(),
                buff.get_u16(),
                buff.get_u16(),
                buff.get_u16(),
                buff.get_u16(),
                buff.get_u16(),
            )),
            _ => return Err(Error::InvalidSyntax),
        };
        Ok(MoveDstIpAddr { type_, addr })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use bytes::Bytes;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_smb2_messages_error_errorid() {
        assert_eq!(
            ErrorId::try_from(0x00000000).ok().unwrap(),
            ErrorId::Default
        );
        assert_eq!(
            ErrorId::try_from(0x72645253).ok().unwrap(),
            ErrorId::ShareRedirect
        );
        assert_eq!(
            ErrorId::try_from(0xf0f0f0f0).err().unwrap(),
            "Unknown error id"
        );
    }

    #[test]
    fn test_smb2_messages_error_move_dst_addr() {
        // V4
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0xfe, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]); // Ipv4 => 192.168.1.254
        let decoded: MoveDstIpAddr = MoveDstIpAddr::decode(&mut buff).ok().unwrap();
        assert_eq!(decoded.type_, MoveDstIpAddrType::V4);
        assert_eq!(decoded.addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)));
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3,
            0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        ]); // Ipv6 => 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        let decoded: MoveDstIpAddr = MoveDstIpAddr::decode(&mut buff).ok().unwrap();
        assert_eq!(decoded.type_, MoveDstIpAddrType::V6);
        assert_eq!(
            decoded.addr,
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x370, 0x7334
            ))
        );
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3,
            0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        ]);
        assert!(MoveDstIpAddr::decode(&mut buff).is_err());
        let mut buff: Bytes = Bytes::from(vec![0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00]);
        assert!(MoveDstIpAddr::decode(&mut buff).is_err());
    }

    #[test]
    fn test_smb2_messages_error_redirect_error() {
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 48, // struct size
            0x00, 0x00, 0x00, 0x03, // Notification type
            0, 0, 0, 76, // Resource name offset
            0, 0, 0, 0x04, // Resource name length
            0x00, 0x00, // RFU
            0x00, 0x00, // Target type
            0x00, 0x00, 0x00, 0x02, // IP addr count
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3,
            0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, // Ipv6
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0xfe, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv4
            0x00, 0x00, 0x00, 0x00, // Offset 4
            0x43, 0x49, 0x41, 0x4F, // CIAO
        ]);
        let decoded: ShareRedirectError = ShareRedirectError::decode(&mut buff).ok().unwrap();
        assert_eq!(decoded.ip_addr_count, 2);
        assert_eq!(decoded.ip_addr_move_list.len(), 2);
        assert_eq!(decoded.notification_type, 3);
        assert_eq!(decoded.resource_name.as_str(), "CIAO");
        assert_eq!(decoded.resource_name_length, 4);
        assert_eq!(decoded.resource_name_offset, 76);
        assert_eq!(decoded.struct_size, 48);
        assert_eq!(decoded.target_type, 0);
        // bad size 48
        let mut buff: Bytes = Bytes::from(vec![48]);
        assert!(ShareRedirectError::decode(&mut buff).is_err());
        // bad size addr
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 48, 0x00, 0x00, 0x00, 3, 0, 0, 0, 100, 0, 0, 0, 4, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, // Header
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3,
            0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, // Ipv6
            0x00, 0x00, 0x00, 0x00, // Offset 4
            0x43, 0x73, 0x65, 0x79, // CIAO
        ]);
        assert!(ShareRedirectError::decode(&mut buff).is_err());
        // Bad size - name
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 48, 0x00, 0x00, 0x00, 3, 0, 0, 0, 100, 0, 0, 0, 4, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, // Header
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3,
            0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, // Ipv6
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0xfe, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv4
            0x00, 0x00, 0x00, 0x00, // Offset 4
            0x43, 0x73,
        ]);
        assert!(ShareRedirectError::decode(&mut buff).is_err());
    }

    #[test]
    fn test_smb2_messages_error_symbolic_link() {
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 0x23, // Symlink length (38 - 4)
            0x4c, 0x4d, 0x59, 0x53, // Tag
            0xa0, 0x00, 0x00, 0x0c, // Reparse tag
            0x00, 0x21, // reparse length
            0x00, 0xa0, // upl
            0x00, 0x00, // sno
            0x00, 0x04, // snl
            0x00, 0x06, // pno
            0x00, 0x05, // pnl
            0x00, 0x00, 0x00, 0x00, // Flags
            0x43, 0x49, 0x41, 0x4F, // substitute (CIAO)
            0x00, 0x00, // offset
            0x4F, 0x41, 0x49, 0x43, 0x43, // print (OAICC)
        ]);
        let decoded: SymbolicLinkError = SymbolicLinkError::decode(&mut buff).ok().unwrap();
        assert_eq!(decoded.flags, SymbolicLinkErrorFlags::ABSOLUTE);
        assert_eq!(decoded.print_name.as_str(), "OAICC");
        assert_eq!(decoded.print_name_length, 5);
        assert_eq!(decoded.print_name_offset, 6);
        assert_eq!(decoded.reparse_length, 0x21);
        assert_eq!(decoded.reparse_tag, 0xA000000C);
        assert_eq!(decoded.substitute_name.as_str(), "CIAO");
        assert_eq!(decoded.substitute_name_length, 4);
        assert_eq!(decoded.substitute_name_offset, 0);
        assert_eq!(decoded.symlink_error_tag, 0x4C4D5953);
        assert_eq!(decoded.symlink_length, 0x23);
        // Variant
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 0x23, // Symlink length (38 - 4)
            0x4c, 0x4d, 0x59, 0x53, // Tag
            0xa0, 0x00, 0x00, 0x0c, // Reparse tag
            0x00, 0x21, // reparse length
            0x00, 0xa0, // upl
            0x00, 0x06, // sno
            0x00, 0x05, // snl
            0x00, 0x00, // pno
            0x00, 0x04, // pnl
            0x00, 0x00, 0x00, 0x00, // Flags
            0x43, 0x49, 0x41, 0x4F, // print (CIAO)
            0x00, 0x00, // offset
            0x4F, 0x41, 0x49, 0x43, 0x43, // sub (OAIC)
        ]);
        let decoded: SymbolicLinkError = SymbolicLinkError::decode(&mut buff).ok().unwrap();
        assert_eq!(decoded.flags, SymbolicLinkErrorFlags::ABSOLUTE);
        assert_eq!(decoded.print_name.as_str(), "CIAO");
        assert_eq!(decoded.print_name_length, 4);
        assert_eq!(decoded.print_name_offset, 0);
        assert_eq!(decoded.reparse_length, 0x21);
        assert_eq!(decoded.reparse_tag, 0xA000000C);
        assert_eq!(decoded.substitute_name.as_str(), "OAICC");
        assert_eq!(decoded.substitute_name_length, 5);
        assert_eq!(decoded.substitute_name_offset, 6);
        assert_eq!(decoded.symlink_error_tag, 0x4C4D5953);
        assert_eq!(decoded.symlink_length, 0x23);
    }

    #[test]
    fn test_smb2_messages_error_context_data() {
        // Symbolic Link
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 0x23, // Symlink length (38 - 4)
            0x4c, 0x4d, 0x59, 0x53, // Tag
            0xa0, 0x00, 0x00, 0x0c, // Reparse tag
            0x00, 0x21, // reparse length
            0x00, 0xa0, // upl
            0x00, 0x00, // sno
            0x00, 0x04, // snl
            0x00, 0x06, // pno
            0x00, 0x05, // pnl
            0x00, 0x00, 0x00, 0x00, // Flags
            0x43, 0x49, 0x41, 0x4F, // substitute (CIAO)
            0x00, 0x00, // offset
            0x4F, 0x41, 0x49, 0x43, 0x43, // print (OAICC)
        ]);
        let decoded: ErrorContextData =
            ErrorContextData::decode(&mut buff, ErrorCode::StoppedOnSymlink)
                .ok()
                .unwrap();
        if let ErrorContextData::SymbolicLink(decoded) = decoded {
            assert_eq!(decoded.flags, SymbolicLinkErrorFlags::ABSOLUTE);
            assert_eq!(decoded.print_name.as_str(), "OAICC");
            assert_eq!(decoded.print_name_length, 5);
            assert_eq!(decoded.print_name_offset, 6);
            assert_eq!(decoded.reparse_length, 0x21);
            assert_eq!(decoded.reparse_tag, 0xA000000C);
            assert_eq!(decoded.substitute_name.as_str(), "CIAO");
            assert_eq!(decoded.substitute_name_length, 4);
            assert_eq!(decoded.substitute_name_offset, 0);
            assert_eq!(decoded.symlink_error_tag, 0x4C4D5953);
            assert_eq!(decoded.symlink_length, 0x23);
        } else {
            panic!("Expected SymbolicLink");
        }
        // Share Redirect
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 48, // struct size
            0x00, 0x00, 0x00, 0x03, // Notification type
            0, 0, 0, 76, // Resource name offset
            0, 0, 0, 0x04, // Resource name length
            0x00, 0x00, // RFU
            0x00, 0x00, // Target type
            0x00, 0x00, 0x00, 0x02, // IP addr count
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3,
            0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, // Ipv6
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0xfe, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv4
            0x00, 0x00, 0x00, 0x00, // Offset 4
            0x43, 0x49, 0x41, 0x4F, // CIAO
        ]);
        let decoded: ErrorContextData =
            ErrorContextData::decode(&mut buff, ErrorCode::BadNetworkName)
                .ok()
                .unwrap();
        if let ErrorContextData::ShareRedirect(decoded) = decoded {
            assert_eq!(decoded.ip_addr_count, 2);
            assert_eq!(decoded.ip_addr_move_list.len(), 2);
            assert_eq!(decoded.notification_type, 3);
            assert_eq!(decoded.resource_name.as_str(), "CIAO");
            assert_eq!(decoded.resource_name_length, 4);
            assert_eq!(decoded.resource_name_offset, 76);
            assert_eq!(decoded.struct_size, 48);
            assert_eq!(decoded.target_type, 0);
        } else {
            panic!("Expected ShareRedirect");
        }
        // Buff length
        let mut buff: Bytes = Bytes::from(vec![0x00, 0x00, 0x01, 0x00]);
        let decoded: ErrorContextData =
            ErrorContextData::decode(&mut buff, ErrorCode::BufferTooSmall)
                .ok()
                .unwrap();
        if let ErrorContextData::BufferTooSmall(buflen) = decoded {
            assert_eq!(buflen, 256);
        } else {
            panic!("Expected BufferTooSmall");
        }
        let mut buff: Bytes = Bytes::from(vec![0x00, 0x00, 0x00, 0x00]);
        assert!(ErrorContextData::decode(&mut buff, ErrorCode::AccountExpired).is_err());
    }

    #[test]
    fn test_smb2_messages_error_context() {
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 0x04, // data len
            0x00, 0x00, 0x00, 0x00, // error id
            0x00, 0x00, 0xff, 0xff, // buffer too small
        ]);
        let decoded: ErrorContext = ErrorContext::decode(&mut buff, ErrorCode::BufferTooSmall)
            .ok()
            .unwrap();
        assert_eq!(decoded.data_length, 4);
        assert_eq!(decoded.error_id, ErrorId::Default);
        if let ErrorContextData::BufferTooSmall(buflen) = decoded.data {
            assert_eq!(buflen, 65535);
        } else {
            panic!("Expected BufferTooSmall");
        }
        // Bad
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 0xff, // data len
            0x00, 0x00, 0x00, 0x00, // error id
            0x00, 0x00, 0xff, 0xff, // buffer too small
        ]);
        assert!(ErrorContext::decode(&mut buff, ErrorCode::BufferTooSmall).is_err());
        // Bad len
        let mut buff: Bytes = Bytes::from(vec![0x00, 0x00, 0x00]);
        assert!(ErrorContext::decode(&mut buff, ErrorCode::BufferTooSmall).is_err());
    }
    #[test]
    fn test_smb2_messages_error_response() {
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x09, // struct size
            0x02, // context count
            0x00, // RFU
            0x00, 0x00, 0x00, 0x1c, // Byte count
            // Context 1
            0x00, 0x00, 0x00, 0x04, // data len
            0x00, 0x00, 0x00, 0x00, // error id
            0x00, 0x00, 0xff, 0xff, // buffer too small
            // ---
            0x00, 0x00, 0x00, 0x00, // Align to 8 bytes
            // Context 2
            0x00, 0x00, 0x00, 0x04, // data len
            0x00, 0x00, 0x00, 0x00, // error id
            0x00, 0x00, 0x00, 0xff, // buffer too small
        ]);
        let decoded: ErrorResponse = ErrorResponse::decode(&mut buff, ErrorCode::BufferTooSmall)
            .ok()
            .unwrap();
        assert_eq!(decoded.byte_count, 28);
        assert_eq!(decoded.ctx_count, 2);
        assert_eq!(decoded.error_data.len(), 2);
        assert_eq!(decoded.struct_size, 9);
        // Empty context case
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x09, // struct size
            0x00, // context count
            0x00, // RFU
            0x00, 0x00, 0x00, 0x00, // Byte count
        ]);
        let decoded: ErrorResponse = ErrorResponse::decode(&mut buff, ErrorCode::BufferTooSmall)
            .ok()
            .unwrap();
        assert_eq!(decoded.byte_count, 0);
        assert_eq!(decoded.ctx_count, 0);
        assert_eq!(decoded.error_data.len(), 0);
        assert_eq!(decoded.struct_size, 9);
        // Bad size
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x09, // struct size
            0x02, // context count
            0x00, // RFU
            0x00, 0x00, 0x00, 0x00, // Byte count
        ]);
        assert!(ErrorResponse::decode(&mut buff, ErrorCode::BufferTooSmall).is_err());
        // Bad size
        let mut buff: Bytes = Bytes::from(vec![
            0x00, 0x09, // struct size
            0x02, // context count
            0x00, // RFU
        ]);
        assert!(ErrorResponse::decode(&mut buff, ErrorCode::BufferTooSmall).is_err());
    }
}
