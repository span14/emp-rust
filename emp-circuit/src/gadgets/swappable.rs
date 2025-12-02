//! Conditional swap gadgets.

use crate::core::{circuit::Circuit, wire::Wire};
use crate::gadgets::bit;

/// Conditionally swap two wires if `sel` is true, returning (low, high).
pub fn swap_if(c: &mut Circuit, sel: Wire, a: Wire, b: Wire) -> (Wire, Wire) {
    let diff = bit::xor(c, a, b);
    let masked = bit::and(c, diff, sel);
    let a_out = bit::xor(c, a, masked);
    let b_out = bit::xor(c, b, masked);
    (a_out, b_out)
}
