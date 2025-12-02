//! Gate representation used by circuits.

use super::wire::Wire;

/// Supported gate kinds in Boolean circuits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateKind {
    /// Logical AND gate.
    And,
    /// Logical XOR gate.
    Xor,
    /// Logical NOT gate.
    Not,
}

/// A gate with input wires and a single output wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gate {
    kind: GateKind,
    inputs: Vec<Wire>,
    output: Wire,
}

impl Gate {
    /// Create an AND gate.
    pub fn and(a: Wire, b: Wire, out: Wire) -> Self {
        Self {
            kind: GateKind::And,
            inputs: vec![a, b],
            output: out,
        }
    }

    /// Create an XOR gate.
    pub fn xor(a: Wire, b: Wire, out: Wire) -> Self {
        Self {
            kind: GateKind::Xor,
            inputs: vec![a, b],
            output: out,
        }
    }

    /// Create a NOT gate.
    pub fn not(a: Wire, out: Wire) -> Self {
        Self {
            kind: GateKind::Not,
            inputs: vec![a],
            output: out,
        }
    }

    /// Access the gate kind.
    pub fn kind(&self) -> GateKind {
        self.kind
    }

    /// Access the input wires.
    pub fn inputs(&self) -> &[Wire] {
        &self.inputs
    }

    /// Access the output wire.
    pub fn output(&self) -> Wire {
        self.output
    }
}
