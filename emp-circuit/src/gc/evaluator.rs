//! Half-gate evaluator that consumes garbled tables and outputs labels.

use crate::core::circuit::Circuit;
use crate::core::protocol_runtime::{
    CircuitExecution as RuntimeCircuitExecution, ProtocolExecution as RuntimeProtocolExecution,
};
use crate::core::wire::Wire;
use crate::gc::halfgate::{halfgates_eval, HalfGateEva};
use crate::gc::label::OutputDecoder;
use crate::gc::party::Party;
use emp_tool::{Block, IOChannel};

/// Evaluator side for half-gate garbling.
pub struct HalfGateEvaluator<IO: IOChannel> {
    pub(crate) eva: HalfGateEva<IO>,
    pub(crate) wire_labels: Vec<Block>,
    pub(crate) next_input: usize,
}

impl<IO: IOChannel> HalfGateEvaluator<IO> {
    /// Initialize with an IO channel.
    pub fn new(io: IO) -> Self {
        Self {
            eva: HalfGateEva::new(io),
            wire_labels: Vec::new(),
            next_input: 0,
        }
    }

    /// Receive labels for evaluator-owned input wires.
    pub fn feed(&mut self, party: Party, wire_indices: &[usize]) {
        match party {
            Party::Evaluator => {
                let need = wire_indices.iter().max().map(|x| x + 1).unwrap_or(0);
                if self.wire_labels.len() < need {
                    self.wire_labels.resize(need, Block::ZERO);
                }
                for &idx in wire_indices {
                    let lbl = self.eva.io.recv_block().unwrap();
                    self.wire_labels[idx] = lbl;
                }
            }
            Party::Garbler => {
                // Garbler-owned labels should be received via `receive_garbler_inputs`.
            }
        }
    }

    /// Evaluate all gates in the circuit, consuming garbled tables from the channel.
    pub fn evaluate(&mut self, circuit: &Circuit) {
        if self.wire_labels.len() < circuit.wire_count() {
            self.wire_labels.resize(circuit.wire_count(), Block::ZERO);
        }
        for g in circuit.gates() {
            match g.kind() {
                crate::core::gate::GateKind::And => {
                    let a_pub = g.inputs()[0].public_value();
                    let b_pub = g.inputs()[1].public_value();
                    if a_pub == Some(false) || b_pub == Some(false) {
                        self.wire_labels[g.output().id()] = self.eva.public_label(false);
                    } else if a_pub == Some(true) && b_pub == Some(true) {
                        self.wire_labels[g.output().id()] = self.eva.public_label(true);
                    } else if a_pub == Some(true) {
                        let b = self.label_for_wire(g.inputs()[1]);
                        self.wire_labels[g.output().id()] = b;
                    } else if b_pub == Some(true) {
                        let a = self.label_for_wire(g.inputs()[0]);
                        self.wire_labels[g.output().id()] = a;
                    } else {
                        let table = {
                            let tbl = self.eva.io.recv_block_vec(2).unwrap();
                            [tbl[0], tbl[1]]
                        };
                        let a = self.label_for_wire(g.inputs()[0]);
                        let b = self.label_for_wire(g.inputs()[1]);
                        let out = halfgates_eval(a, b, &table, &mut self.eva.mitccrh);
                        self.wire_labels[g.output().id()] = out;
                    }
                }
                crate::core::gate::GateKind::Xor => {
                    let a = self.label_for_wire(g.inputs()[0]);
                    let b = self.label_for_wire(g.inputs()[1]);
                    self.wire_labels[g.output().id()] = a ^ b;
                }
                crate::core::gate::GateKind::Not => {
                    let a = self.label_for_wire(g.inputs()[0]);
                    self.wire_labels[g.output().id()] = self.eva.not_gate(a);
                }
            }
        }
    }

    /// Send output labels back to the garbler and decode them locally using a decoder.
    pub fn reveal(&mut self, output_indices: &[usize], decoder: &OutputDecoder) -> Vec<bool> {
        let mut lbls = Vec::with_capacity(output_indices.len());
        for &idx in output_indices {
            let lbl = self.wire_labels[idx];
            self.eva.io.send_block(&lbl).unwrap();
            lbls.push(lbl);
        }
        decoder.decode_all(&lbls)
    }

    /// Access underlying IO (mainly for tests).
    pub fn io_mut(&mut self) -> &mut IO {
        &mut self.eva.io
    }

    /// Set a wire label directly (for garbler-owned inputs delivered via other means).
    pub fn set_wire_label(&mut self, idx: usize, lbl: Block) {
        if self.wire_labels.len() <= idx {
            self.wire_labels.resize(idx + 1, Block::ZERO);
        }
        self.wire_labels[idx] = lbl;
    }

    /// Send selected output labels back to the garbler.
    pub fn send_outputs(&mut self, outputs: &[usize]) -> Vec<Block> {
        let mut out_lbls = Vec::with_capacity(outputs.len());
        for &idx in outputs {
            let lbl = self.wire_labels[idx];
            self.eva.io.send_block(&lbl).unwrap();
            out_lbls.push(lbl);
        }
        out_lbls
    }

    /// Receive garbler-owned input labels from the channel.
    pub fn receive_garbler_inputs(&mut self, wire_indices: &[usize]) {
        let need = wire_indices.iter().max().map(|x| x + 1).unwrap_or(0);
        if self.wire_labels.len() < need {
            self.wire_labels.resize(need, Block::ZERO);
        }
        for &idx in wire_indices {
            let lbl = self.eva.io.recv_block().unwrap();
            self.wire_labels[idx] = lbl;
        }
    }

    /// Get the label for a wire, handling public constants.
    fn label_for_wire(&mut self, wire: Wire) -> Block {
        if let Some(val) = wire.public_value() {
            return self.eva.public_label(val);
        }
        self.wire_labels[wire.id()]
    }
}

impl<IO: IOChannel> RuntimeProtocolExecution for HalfGateEvaluator<IO> {
    fn feed(&mut self, _party: Party, bits: &[bool]) -> Vec<Block> {
        let start = self.next_input;
        let end = start + bits.len();
        self.next_input = end;
        if self.wire_labels.len() < end {
            self.wire_labels.resize(end, Block::ZERO);
        }
        let mut lbls = Vec::with_capacity(bits.len());
        for idx in start..end {
            let lbl = self.eva.io.recv_block().unwrap();
            self.wire_labels[idx] = lbl;
            lbls.push(lbl);
        }
        lbls
    }

    fn reveal(&mut self, party: Party, labels: &[Block]) -> Vec<bool> {
        match party {
            Party::Garbler => {
                for lbl in labels {
                    self.eva.io.send_block(lbl).unwrap();
                }
                Vec::new()
            }
            Party::Evaluator => labels.iter().map(|_| false).collect(),
        }
    }
}

impl<IO: IOChannel> RuntimeCircuitExecution for HalfGateEvaluator<IO> {
    fn and_gate(&mut self, a: Block, b: Block) -> Block {
        let tbl = self.eva.io.recv_block_vec(2).unwrap();
        let table = [tbl[0], tbl[1]];
        halfgates_eval(a, b, &table, &mut self.eva.mitccrh)
    }

    fn xor_gate(&mut self, a: Block, b: Block) -> Block {
        a ^ b
    }

    fn not_gate(&mut self, a: Block) -> Block {
        self.eva.not_gate(a)
    }

    fn public_label(&self, b: bool) -> Block {
        self.eva.public_label(b)
    }
}
