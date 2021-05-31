//! # utils
//!
//! utils module

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

/// ### pad_to_32_bit
///
/// Calculate length as if data were padded to 32 bit on the left
pub fn pad_to_32_bit(len: usize) -> usize {
    (len + 0x03) & 0xfffffffc
}

/// ### pad_to_64_bit
///
/// Calculate length as if data were padded to 64 bit on the left
pub fn pad_to_64_bit(len: usize) -> usize {
    (len + 0x07) & 0xfffffff8
}

#[cfg(test)]
mod test {
    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn test_utils_pad_to_32_bit() {
        assert_eq!(pad_to_32_bit(36), 36);
        assert_eq!(pad_to_32_bit(38), 40);
        assert_eq!(pad_to_32_bit(40), 40);
        assert_eq!(pad_to_32_bit(42), 44);
    }

    #[test]
    fn test_utils_pad_to_64_bit() {
        assert_eq!(pad_to_64_bit(32), 32);
        assert_eq!(pad_to_64_bit(38), 40);
        assert_eq!(pad_to_64_bit(40), 40);
        assert_eq!(pad_to_64_bit(42), 48);
    }
}
