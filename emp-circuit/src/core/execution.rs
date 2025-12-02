//! Execution traits and a plain Boolean evaluator.

use std::collections::HashMap;

use super::{circuit::Circuit, gate::GateKind, wire::Wire};

/// Trait matching the EMP-style circuit execution interface.
pub trait CircuitExecution {
    /// Compute AND of two labels.
    fn and_gate(&mut self, in1: Wire, in2: Wire) -> Wire;
    /// Compute XOR of two labels.
    fn xor_gate(&mut self, in1: Wire, in2: Wire) -> Wire;
    /// Compute NOT of a label.
    fn not_gate(&mut self, input: Wire) -> Wire;
    /// Return a public label.
    fn public_label(&mut self, value: bool) -> Wire;
    /// Number of AND gates executed, if tracked.
    fn num_and(&self) -> u64 {
        0
    }
}

/// Plain Boolean evaluator for debugging and tests.
#[derive(Default)]
pub struct PlainEvaluator {
    env: HashMap<usize, bool>,
    ands: u64,
}

impl PlainEvaluator {
    /// Create an empty evaluator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluate a circuit given input assignments for the first `inputs.len()` wires.
    pub fn evaluate(&mut self, circuit: &Circuit, inputs: &[bool]) -> HashMap<usize, bool> {
        for (i, b) in inputs.iter().enumerate() {
            self.env.insert(i, *b);
        }
        for gate in circuit.gates() {
            match gate.kind() {
                GateKind::And => {
                    let a = self.lookup(gate.inputs()[0]);
                    let b = self.lookup(gate.inputs()[1]);
                    let out = a & b;
                    self.env.insert(gate.output().id(), out);
                    self.ands += 1;
                }
                GateKind::Xor => {
                    let a = self.lookup(gate.inputs()[0]);
                    let b = self.lookup(gate.inputs()[1]);
                    let out = a ^ b;
                    self.env.insert(gate.output().id(), out);
                }
                GateKind::Not => {
                    let a = self.lookup(gate.inputs()[0]);
                    self.env.insert(gate.output().id(), !a);
                }
            }
        }
        self.env.clone()
    }

    fn lookup(&self, w: Wire) -> bool {
        if let Some(v) = w.public_value() {
            return v;
        }
        *self
            .env
            .get(&w.id())
            .unwrap_or_else(|| panic!("missing value for wire {}", w.id()))
    }
}

impl CircuitExecution for PlainEvaluator {
    fn and_gate(&mut self, in1: Wire, in2: Wire) -> Wire {
        let out = Wire::new(usize::MAX); // Placeholder; not used in evaluator stepping.
        let _ = (in1, in2); // silence unused warnings
        out
    }

    fn xor_gate(&mut self, in1: Wire, in2: Wire) -> Wire {
        let out = Wire::new(usize::MAX);
        let _ = (in1, in2);
        out
    }

    fn not_gate(&mut self, input: Wire) -> Wire {
        let out = Wire::new(usize::MAX);
        let _ = input;
        out
    }

    fn public_label(&mut self, value: bool) -> Wire {
        Wire::public(usize::MAX, value)
    }

    fn num_and(&self) -> u64 {
        self.ands
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::circuit::Circuit;

    #[test]
    fn eval_simple_circuit() {
        let mut c = Circuit::new();
        let a = c.fresh_wire();
        let b = c.fresh_wire();
        let t = c.xor(a, b);
        let one = c.public_wire(true);
        let _ = c.and(t, one);

        let mut ev = PlainEvaluator::new();
        let vals = ev.evaluate(&c, &[true, false]);
        // xor => true, then and with true => true
        let last = c.gates().last().unwrap().output().id();
        assert_eq!(vals.get(&last), Some(&true));
        assert_eq!(ev.num_and(), 1);
    }
}
