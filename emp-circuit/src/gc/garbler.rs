//! Half-gate garbler that drives a `Circuit` using `HalfGateGen`.

use crate::core::circuit::Circuit;
use crate::core::protocol_runtime::{
    CircuitExecution as RuntimeCircuitExecution, ProtocolExecution as RuntimeProtocolExecution,
};
use crate::gc::halfgate::{halfgates_garble, HalfGateGen};
use crate::gc::input_map::InputMap;
use crate::gc::label::{OutputDecoder, WireLabel};
use crate::gc::party::Party;
use emp_tool::{prg::Prg, Block, IOChannel};
use crate::core::wire::Wire;

/// Garbler that owns all wire labels and drives the half-gate protocol.
pub struct HalfGateGarbler<IO: IOChannel> {
    pub(crate) gen: HalfGateGen<IO>,
    pub(crate) zero_labels: Vec<Block>,
    pub(crate) delta: Block,
    /// Tracked zero-label for each wire as garbling progresses.
    pub(crate) wire_zero: Vec<Block>,
    pub(crate) decoder: OutputDecoder,
    pub(crate) next_input: usize,
}

impl<IO: IOChannel> HalfGateGarbler<IO> {
    /// Initialize with an IO channel and allocate labels for `wire_count` wires.
    pub fn new(io: IO, wire_count: usize) -> Self {
        let gen = HalfGateGen::new(io);
        let mut prg = Prg::new();
        let delta = gen.delta();
        let mut zero_labels = Vec::with_capacity(wire_count);
        for _ in 0..wire_count {
            zero_labels.push(prg.random_block());
        }
        Self {
            gen,
            zero_labels,
            delta,
            wire_zero: vec![Block::ZERO; wire_count],
            decoder: OutputDecoder::new(delta),
            next_input: 0,
        }
    }

    /// Get a `WireLabel` for a specific wire.
    pub fn wire_label(&self, idx: usize) -> WireLabel {
        WireLabel::new(self.zero_labels[idx], self.delta)
    }

    /// Assign input labels for a party; sends labels to evaluator when needed.
    pub fn feed(&mut self, party: Party, wire_indices: &[usize], bits: &[bool]) {
        assert_eq!(wire_indices.len(), bits.len());
        for (&idx, &bit) in wire_indices.iter().zip(bits.iter()) {
            let lbl = self.wire_label(idx).label(bit);
            self.wire_zero[idx] = self.wire_label(idx).zero();
            if matches!(party, Party::Evaluator) {
                // Only evaluator-owned inputs are sent here.
                self.gen.send_block(&lbl).unwrap();
            }
        }
    }

    /// Convenience: feed both parties based on an `InputMap` and their bit slices.
    pub fn feed_from_map(&mut self, map: &InputMap, alice_bits: &[bool], bob_bits: &[bool]) {
        let alice_indices = map.indices(Party::Garbler);
        let bob_indices = map.indices(Party::Evaluator);
        assert_eq!(alice_bits.len(), alice_indices.len());
        assert_eq!(bob_bits.len(), bob_indices.len());
        self.feed(Party::Garbler, &alice_indices, alice_bits);
        self.feed(Party::Evaluator, &bob_indices, bob_bits);
    }

    /// Send garbler-owned labels to the evaluator explicitly (for evaluator-side execution).
    pub fn send_garbler_inputs(&mut self, wire_indices: &[usize], bits: &[bool]) {
        assert_eq!(wire_indices.len(), bits.len());
        for (&idx, &bit) in wire_indices.iter().zip(bits.iter()) {
            let lbl = self.wire_label(idx).label(bit);
            self.gen.send_block(&lbl).unwrap();
        }
    }

    /// Garble gates in the circuit using current wire labels.
    pub fn garble(&mut self, circuit: &Circuit) {
        for g in circuit.gates() {
            match g.kind() {
                crate::core::gate::GateKind::And => {
                    let a_pub = g.inputs()[0].public_value();
                    let b_pub = g.inputs()[1].public_value();
                    if a_pub == Some(false) || b_pub == Some(false) {
                        self.wire_zero[g.output().id()] = self.gen.public_label(false);
                    } else if a_pub == Some(true) && b_pub == Some(true) {
                        self.wire_zero[g.output().id()] = self.gen.public_label(false);
                    } else if a_pub == Some(true) {
                        self.wire_zero[g.output().id()] = self.zero_for_wire(g.inputs()[1]);
                    } else if b_pub == Some(true) {
                        self.wire_zero[g.output().id()] = self.zero_for_wire(g.inputs()[0]);
                    } else {
                        let la0 = self.zero_for_wire(g.inputs()[0]);
                        let lb0 = self.zero_for_wire(g.inputs()[1]);
                        let la1 = la0 ^ self.delta;
                        let lb1 = lb0 ^ self.delta;
                        let mut table = [Block::ZERO; 2];
                        let w0 = halfgates_garble(
                            la0,
                            la1,
                            lb0,
                            lb1,
                            self.delta,
                            &mut table,
                            &mut self.gen.mitccrh,
                        );
                        self.gen.send_block_vec(&table).unwrap();
                        self.wire_zero[g.output().id()] = w0;
                    }
                }
                crate::core::gate::GateKind::Xor => {
                    let a0 = self.zero_for_wire(g.inputs()[0]);
                    let b0 = self.zero_for_wire(g.inputs()[1]);
                    self.wire_zero[g.output().id()] = a0 ^ b0;
                }
                crate::core::gate::GateKind::Not => {
                    let a0 = self.zero_for_wire(g.inputs()[0]);
                    self.wire_zero[g.output().id()] = a0 ^ self.delta;
                }
            }
        }
    }

    /// Mark outputs to be decoded later (stores zero labels).
    pub fn set_outputs(&mut self, outputs: &[usize]) {
        for &idx in outputs {
            let z = self.zero_label(idx);
            self.decoder.push_zero_label(z);
        }
    }

    /// Receive evaluator's output labels and decode to bits.
    pub fn reveal(&mut self, outputs: &[usize]) -> Vec<bool> {
        let mut lbls = Vec::with_capacity(outputs.len());
        for _ in outputs {
            lbls.push(self.gen.recv_block().unwrap());
        }
        self.decoder.decode_all(&lbls)
    }

    /// Expose the decoder for external use (e.g., evaluator-side decode).
    pub fn decoder(&self) -> &OutputDecoder {
        &self.decoder
    }

    /// Get the current zero-label for a wire (prefers garbled value if set).
    pub fn zero_label(&self, idx: usize) -> Block {
        if idx < self.wire_zero.len() && self.wire_zero[idx] != Block::ZERO {
            self.wire_zero[idx]
        } else {
            self.wire_label(idx).zero()
        }
    }

    /// Retrieve the zero-label for a wire, respecting public constants.
    fn zero_for_wire(&mut self, wire: Wire) -> Block {
        if let Some(value) = wire.public_value() {
            let z = self.gen.public_label(false);
            self.wire_zero[wire.id()] = z;
            // Track decoder zero-label for public wires only if they become outputs later.
            if value {
                // nothing else; zero-label still corresponds to false.
            }
            return z;
        }
        if self.wire_zero[wire.id()] == Block::ZERO {
            self.wire_zero[wire.id()] = self.wire_label(wire.id()).zero();
        }
        self.wire_zero[wire.id()]
    }
}

impl<IO: IOChannel> RuntimeProtocolExecution for HalfGateGarbler<IO> {
    fn feed(&mut self, party: Party, bits: &[bool]) -> Vec<Block> {
        let start = self.next_input;
        let indices: Vec<usize> = (start..start + bits.len()).collect();
        self.next_input += bits.len();
        for (&idx, &bit) in indices.iter().zip(bits.iter()) {
            let lbl = self.wire_label(idx).label(bit);
            self.wire_zero[idx] = self.wire_label(idx).zero();
            if matches!(party, Party::Evaluator) {
                self.gen.send_block(&lbl).unwrap();
            }
        }
        indices
            .iter()
            .zip(bits.iter())
            .map(|(&idx, &bit)| self.wire_label(idx).label(bit))
            .collect()
    }

    fn reveal(&mut self, party: Party, labels: &[Block]) -> Vec<bool> {
        match party {
            Party::Garbler => self.decoder.decode_all(labels),
            Party::Evaluator => {
                for lbl in labels {
                    self.gen.send_block(lbl).unwrap();
                }
                Vec::new()
            }
        }
    }
}

impl<IO: IOChannel> RuntimeCircuitExecution for HalfGateGarbler<IO> {
    fn and_gate(&mut self, a: Block, b: Block) -> Block {
        let mut table = [Block::ZERO; 2];
        let w0 = halfgates_garble(
            a,
            a ^ self.delta,
            b,
            b ^ self.delta,
            self.delta,
            &mut table,
            &mut self.gen.mitccrh,
        );
        self.gen.send_block_vec(&table).unwrap();
        w0
    }

    fn xor_gate(&mut self, a: Block, b: Block) -> Block {
        a ^ b
    }

    fn not_gate(&mut self, a: Block) -> Block {
        self.gen.not_gate(a)
    }

    fn public_label(&self, b: bool) -> Block {
        self.gen.public_label(b)
    }
}
