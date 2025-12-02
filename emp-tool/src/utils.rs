//! Useful utils used in the libraries

use std::path::Path;
use std::time::Instant;

use crate::block::Block;

/// Pack a bit vector into a byte vecotr.
#[inline(always)]
pub fn pack_bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let nbytes = (bits.len() - 1) / 8 + 1;
    let mut bytes = vec![0; nbytes];
    for i in 0..nbytes {
        for j in 0..8 {
            if 8 * i + j >= bits.len() {
                break;
            }
            bytes[i] |= (bits[8 * i + j] as u8) << j;
        }
    }
    bytes
}

/// Unpack a byte vector to a bit vector with length size.
#[inline(always)]
pub fn unpack_bytes_to_bits(bytes: &[u8], size: usize) -> Vec<bool> {
    let mut bits = Vec::<bool>::new();
    for (i, byte) in bytes.iter().enumerate() {
        for j in 0..8 {
            if 8 * i + j >= size {
                break;
            }
            bits.push(((byte >> j) & 1) != 0);
        }
    }
    bits
}

#[test]
fn pack_unpack_test() {
    let n = 10;
    let mut bits = vec![false; n];
    for x in bits.iter_mut() {
        *x = rand::random();
    }
    let bytes = pack_bits_to_bytes(&bits);
    let _bits = unpack_bytes_to_bits(&bytes, n);
    assert_eq!(bits, _bits);
}

/// Convert a slice of booleans (little-endian bits) into a `u128`.
#[inline(always)]
pub fn bools_to_u128(bits: &[bool]) -> u128 {
    let mut acc = 0u128;
    let len = bits.len().min(128);
    for i in 0..len {
        if bits[i] {
            acc |= 1u128 << i;
        }
    }
    acc
}

/// Convert an integer into a vector of booleans (little-endian bits) of length `len`.
#[inline(always)]
pub fn int_to_bools(mut value: u128, len: usize) -> Vec<bool> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push((value & 1) == 1);
        value >>= 1;
    }
    out
}

/// Convert a 128-bit block from/to boolean vectors (little-endian per 64-bit limb).
#[inline(always)]
pub fn bools_to_block(bits: &[bool]) -> Block {
    assert!(bits.len() >= 128, "expected at least 128 bits");
    let low = bools_to_u128(&bits[..64]) as u64;
    let high = bools_to_u128(&bits[64..128]) as u64;
    Block::from([low, high])
}

/// Convert a block into a vector of 128 booleans (little-endian per 64-bit limb).
#[inline(always)]
pub fn block_to_bools(block: Block) -> Vec<bool> {
    let limbs: [u64; 2] = block.into();
    let mut out = int_to_bools(limbs[0] as u128, 64);
    out.extend(int_to_bools(limbs[1] as u128, 64));
    out
}

/// Check if a path exists and is a file.
#[inline(always)]
pub fn file_exists<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();
    path.is_file()
}

/// Start a monotonic timer.
#[inline(always)]
pub fn clock_start() -> Instant {
    Instant::now()
}

/// Microseconds elapsed since a start instant.
#[inline(always)]
pub fn time_from(start: Instant) -> u128 {
    start.elapsed().as_micros()
}

#[cfg(test)]
mod conv_tests {
    use super::*;

    #[test]
    fn bool_block_roundtrip() {
        let mut bits = vec![false; 128];
        for (i, b) in bits.iter_mut().enumerate() {
            *b = (i % 3) == 0;
        }
        let blk = bools_to_block(&bits);
        let back = block_to_bools(blk);
        assert_eq!(bits, back);
    }

    #[test]
    fn int_bool_roundtrip() {
        let val = 0xdead_beef_cafe_f00du128;
        let bits = int_to_bools(val, 128);
        let recovered = bools_to_u128(&bits);
        assert_eq!(val, recovered);
    }

    #[test]
    fn timer_nonzero() {
        let start = clock_start();
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(time_from(start) > 0);
    }

    #[test]
    fn file_exists_smoke() {
        let path = std::env::temp_dir().join("emp_tool_file_exists.tmp");
        std::fs::write(&path, b"x").unwrap();
        assert!(file_exists(&path));
        let _ = std::fs::remove_file(path);
    }
}
