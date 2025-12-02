//! Comparison gadgets.

use crate::core::{circuit::Circuit, wire::Wire};
use crate::gadgets::bit;

/// Compute equality over two bit-vectors (little-endian).
pub fn eq(c: &mut Circuit, a: &[Wire], b: &[Wire]) -> Wire {
    assert_eq!(a.len(), b.len());
    let mut acc = c.public_wire(true);
    for (&ai, &bi) in a.iter().zip(b.iter()) {
        let x = bit::xor(c, ai, bi);
        let nx = bit::not(c, x);
        acc = bit::and(c, acc, nx);
    }
    acc
}
