//! Integer gadgets; currently a thin wrapper for ripple-carry addition.

use crate::core::{circuit::Circuit, wire::Wire};
use crate::gadgets::bit;

/// Ripple-carry add two equal-length little-endian bit-vectors.
pub fn add(c: &mut Circuit, a: &[Wire], b: &[Wire]) -> (Vec<Wire>, Wire) {
    assert_eq!(a.len(), b.len());
    let mut carry = c.public_wire(false);
    let mut out = Vec::with_capacity(a.len());
    for (&ai, &bi) in a.iter().zip(b.iter()) {
        let t = bit::xor(c, ai, bi);
        let sum = bit::xor(c, t, carry);
        let t2 = bit::and(c, t, carry);
        let t3 = bit::and(c, ai, bi);
        carry = bit::xor(c, t2, t3);
        out.push(sum);
    }
    (out, carry)
}
