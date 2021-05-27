//! # buffer
//!
//! buffer utils module

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
use bytes::Buf;

/// align_8_bytes_boundary
///
/// Align a buffer to next 8 bytes boundary
pub fn align_8_bytes_boundary(buff: &mut dyn Buf) {
    let offset: usize = buff.remaining() % 8;
    if offset > 0 {
        buff.advance(8 - offset);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_utils_buffer_align_8_bytes_boundary() {
        let mut buf: Bytes = Bytes::from(vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0xde, 0xad, 0xca, 0xfe, 0xba, 0xbe,
        ]);
        align_8_bytes_boundary(&mut buf);
        let mut remaining: Vec<u8> = vec![0, 8];
        buf.copy_to_slice(remaining.as_mut_slice());
        assert_eq!(
            remaining,
            vec![0x04, 0x05, 0xde, 0xad, 0xca, 0xfe, 0xba, 0xbe,]
        );
        // Check already aligned
        let mut buf: Bytes = Bytes::from(vec![0x00, 0x00, 0xde, 0xad, 0xca, 0xfe, 0xba, 0xbe]);
        align_8_bytes_boundary(&mut buf);
        let mut remaining: Vec<u8> = vec![0, 8];
        buf.copy_to_slice(remaining.as_mut_slice());
        assert_eq!(
            remaining,
            vec![0x00, 0x00, 0xde, 0xad, 0xca, 0xfe, 0xba, 0xbe,]
        );
    }
}
