//! Basic bit-level gadgets built on the core circuit builder.

use crate::core::{circuit::Circuit, wire::Wire};

/// XOR two wires using the circuit builder.
pub fn xor(c: &mut Circuit, a: Wire, b: Wire) -> Wire {
    c.xor(a, b)
}

/// AND two wires using the circuit builder.
pub fn and(c: &mut Circuit, a: Wire, b: Wire) -> Wire {
    c.and(a, b)
}

/// NOT a wire using the circuit builder.
pub fn not(c: &mut Circuit, a: Wire) -> Wire {
    c.not(a)
}
