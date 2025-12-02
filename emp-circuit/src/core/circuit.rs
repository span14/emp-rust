//! A simple Boolean circuit container with a builder-style API.

use super::{gate::Gate, gate::GateKind, wire::Wire};

/// A Boolean circuit represented as a list of gates and wire allocation state.
#[derive(Default, Debug, Clone)]
pub struct Circuit {
    gates: Vec<Gate>,
    next_wire: usize,
}

impl Circuit {
    /// Create an empty circuit.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh private wire.
    pub fn fresh_wire(&mut self) -> Wire {
        let w = Wire::new(self.next_wire);
        self.next_wire += 1;
        w
    }

    /// Allocate a public wire fixed to `value`.
    pub fn public_wire(&mut self, value: bool) -> Wire {
        let w = Wire::public(self.next_wire, value);
        self.next_wire += 1;
        w
    }

    /// Append an AND gate and return its output wire.
    pub fn and(&mut self, a: Wire, b: Wire) -> Wire {
        let out = self.fresh_wire();
        self.gates.push(Gate::and(a, b, out));
        out
    }

    /// Append an XOR gate and return its output wire.
    pub fn xor(&mut self, a: Wire, b: Wire) -> Wire {
        let out = self.fresh_wire();
        self.gates.push(Gate::xor(a, b, out));
        out
    }

    /// Append a NOT gate and return its output wire.
    pub fn not(&mut self, a: Wire) -> Wire {
        let out = self.fresh_wire();
        self.gates.push(Gate::not(a, out));
        out
    }

    /// Total number of allocated wires.
    pub fn wire_count(&self) -> usize {
        self.next_wire
    }

    /// Iterate over gates.
    pub fn gates(&self) -> &[Gate] {
        &self.gates
    }

    /// Internal helper to append a pre-built gate (used by parsers).
    pub(crate) fn push_gate(&mut self, gate: Gate) {
        self.add_gate_internal(gate);
    }

    pub(crate) fn add_gate_internal(&mut self, gate: Gate) {
        self.next_wire = self.next_wire.max(gate.output().id() + 1);
        self.gates.push(gate);
    }
}

/// Compute a simple statistics summary for a circuit.
pub fn gate_counts(circuit: &Circuit) -> (usize, usize, usize) {
    let mut ands = 0;
    let mut xors = 0;
    let mut nots = 0;
    for g in circuit.gates() {
        match g.kind() {
            GateKind::And => ands += 1,
            GateKind::Xor => xors += 1,
            GateKind::Not => nots += 1,
        }
    }
    (ands, xors, nots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_basic_circuit() {
        let mut c = Circuit::new();
        let a = c.fresh_wire();
        let b = c.fresh_wire();
        let _ = c.and(a, b);
        let _ = c.xor(a, b);
        let _ = c.not(a);
        let (ands, xors, nots) = gate_counts(&c);
        assert_eq!((ands, xors, nots), (1, 1, 1));
        assert_eq!(c.wire_count(), 5);
    }
}
