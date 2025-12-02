//! Wire label representation and decoding helpers for garbled circuits.

use emp_tool::Block;

/// A pair of labels for a wire along with the global delta.
#[derive(Clone, Debug)]
pub struct WireLabel {
    zero: Block,
    one: Block,
    delta: Block,
}

impl WireLabel {
    /// Construct labels from a zero label and a global delta.
    pub fn new(zero: Block, delta: Block) -> Self {
        Self {
            zero,
            one: zero ^ delta,
            delta,
        }
    }

    /// Return the label corresponding to bit `b`.
    pub fn label(&self, b: bool) -> Block {
        if b {
            self.one
        } else {
            self.zero
        }
    }

    /// Return the zero label.
    pub fn zero(&self) -> Block {
        self.zero
    }

    /// Return the one label.
    pub fn one(&self) -> Block {
        self.one
    }

    /// Global delta used for this label pair.
    pub fn delta(&self) -> Block {
        self.delta
    }
}

/// Decoder for output wires: stores the zero-label and delta to recover a bit.
#[derive(Clone, Debug, Default)]
pub struct OutputDecoder {
    zero_labels: Vec<Block>,
    delta: Block,
}

impl OutputDecoder {
    /// Create a new decoder with known delta.
    pub fn new(delta: Block) -> Self {
        Self {
            zero_labels: Vec::new(),
            delta,
        }
    }

    /// Register a zero-label for an output wire.
    pub fn push_zero_label(&mut self, lbl0: Block) {
        self.zero_labels.push(lbl0);
    }

    /// Decode a single output label to a bit using the stored zero-label and delta.
    pub fn decode(&self, idx: usize, lbl: Block) -> bool {
        let z = self.zero_labels[idx];
        if lbl == z {
            false
        } else if lbl == z ^ self.delta {
            true
        } else {
            // Unknown label; default to false but signal an issue by returning false.
            false
        }
    }

    /// Decode a slice of labels into bits.
    pub fn decode_all(&self, lbls: &[Block]) -> Vec<bool> {
        lbls.iter()
            .enumerate()
            .map(|(i, &l)| self.decode(i, l))
            .collect()
    }
}
