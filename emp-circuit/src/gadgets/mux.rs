//! Multiplexer gadget.

use crate::core::{circuit::Circuit, wire::Wire};
use crate::gadgets::bit;

/// Return `a` if `sel` is false, `b` if `sel` is true.
pub fn mux(c: &mut Circuit, sel: Wire, a: Wire, b: Wire) -> Wire {
    let diff = bit::xor(c, a, b);
    let masked = bit::and(c, diff, sel);
    bit::xor(c, a, masked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::execution::PlainEvaluator;

    #[test]
    fn mux_selects() {
        let mut c = Circuit::new();
        let sel = c.public_wire(false);
        let a = c.public_wire(true);
        let b = c.public_wire(false);
        let out = mux(&mut c, sel, a, b);
        let mut ev = PlainEvaluator::new();
        let vals = ev.evaluate(&c, &[]);
        assert_eq!(vals.get(&out.id()), Some(&true));
    }
}
