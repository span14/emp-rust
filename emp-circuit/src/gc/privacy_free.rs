//! Privacy-free garbling primitives (single-ciphertext AND) setup.

use crate::core::{circuit::Circuit, wire::Wire};
use crate::gc::input_map::InputMap;
use crate::gc::label::{OutputDecoder, WireLabel};
use crate::gc::party::Party;
use emp_tool::{prg::Prg, prp::Prp, Block, IOChannel};
use crate::core::protocol_runtime::{
    CircuitExecution as RuntimeCircuitExecution, ProtocolExecution as RuntimeProtocolExecution,
};

/// Privacy-free garbler side: manages delta, public labels, and PRP state.
pub struct PrivacyFreeGen<IO: IOChannel> {
    delta: Block,
    io: IO,
    pub(crate) constant: [Block; 2],
    pub(crate) prp: Prp,
    gid: u64,
}

impl<IO: IOChannel> PrivacyFreeGen<IO> {
    /// Create a new generator, sample delta/constants, and send public info to the evaluator.
    pub fn new(io: IO) -> Self {
        let mut gen = Self {
            delta: Block::ZERO,
            io,
            constant: [Block::ZERO; 2],
            prp: Prp::new(Block::ZERO),
            gid: 0,
        };
        gen.init();
        gen
    }

    fn init(&mut self) {
        // Sample delta and enforce LSB.
        let mut tmp = [Block::ZERO; 2];
        Prg::new().random_blocks(&mut tmp);
        let mut delta = tmp[0];
        delta.set_lsb();
        self.delta = delta;
        // Sample public constants and share with evaluator.
        let mut c0 = [Block::ZERO; 1];
        Prg::new().random_blocks(&mut c0);
        // Force permute bits and set 1-label via delta.
        let mut c0raw: u128 = c0[0].into();
        c0raw &= !1u128;
        self.constant[0] = Block::from(c0raw);
        self.constant[1] = self.constant[0] ^ self.delta;
        self.io
            .send_block_vec(&self.constant)
            .expect("send constants");
        // Use a fixed-key PRP (default seeded to zero in ctor).
    }

    /// Public label helper.
    pub fn public_label(&self, b: bool) -> Block {
        self.constant[b as usize]
    }

    /// Access delta.
    pub fn delta(&self) -> Block {
        self.delta
    }

    /// Number of AND gates garbled so far.
    pub fn num_and(&self) -> u64 {
        self.gid
    }

    /// Fetch the current AND id and increment.
    pub fn next_and_id(&mut self) -> u64 {
        let id = self.gid;
        self.gid += 1;
        id
    }

    /// Garble a privacy-free AND; assumes garbler knows one input.
    pub fn and_gate(&mut self, a0: Block, a1: Block, b0: Block, b1: Block) -> Block {
        let mut table = [Block::ZERO; 1];
        let res = privacy_free_garble(
            a0,
            a1,
            b0,
            b1,
            self.delta,
            &mut table,
            self.next_and_id(),
            &self.prp,
        );
        self.io.send_block_vec(&table).expect("send pf table");
        res
    }

    /// IO helper: send a single block.
    pub fn send_block(&mut self, blk: &Block) -> std::io::Result<()> {
        self.io.send_block(blk)
    }

    /// IO helper: send a vector of blocks.
    pub fn send_block_vec(&mut self, blks: &[Block]) -> std::io::Result<()> {
        self.io.send_block_vec(blks)
    }

    /// IO helper: receive a block.
    pub fn recv_block(&mut self) -> std::io::Result<Block> {
        self.io.recv_block()
    }
}

/// Privacy-free evaluator side: receives public labels and PRP seed (fixed-key).
pub struct PrivacyFreeEva<IO: IOChannel> {
    pub(crate) io: IO,
    constant: [Block; 2],
    pub(crate) prp: Prp,
    gid: u64,
}

/// Privacy-free garbler that tracks per-wire zero labels.
pub struct PrivacyFreeGarbler<IO: IOChannel> {
    pub(crate) gen: PrivacyFreeGen<IO>,
    pub(crate) zero_labels: Vec<Block>,
    pub(crate) delta: Block,
    pub(crate) wire_zero: Vec<Block>,
    pub(crate) decoder: OutputDecoder,
    pub(crate) next_input: usize,
}

impl<IO: IOChannel> PrivacyFreeGarbler<IO> {
    /// Initialize with an IO channel and allocate labels for `wire_count` wires.
    pub fn new(io: IO, wire_count: usize) -> Self {
        let gen = PrivacyFreeGen::new(io);
        let mut prg = Prg::new();
        let delta = gen.delta();
        let mut zero_labels = Vec::with_capacity(wire_count);
        for _ in 0..wire_count {
            let mut z = prg.random_block();
            // Enforce permute bit = 0 for zero labels; one-label inherits permute=1 via delta.
            let mut raw: u128 = z.into();
            raw &= !1u128;
            z = Block::from(raw);
            zero_labels.push(z);
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

    fn wire_label(&self, idx: usize) -> WireLabel {
        WireLabel::new(self.zero_labels[idx], self.delta)
    }

    /// Assign input labels for a party; only evaluator inputs are sent.
    pub fn feed(&mut self, party: Party, wire_indices: &[usize], bits: &[bool]) {
        assert_eq!(wire_indices.len(), bits.len());
        for (&idx, &bit) in wire_indices.iter().zip(bits.iter()) {
            let lbl = self.wire_label(idx).label(bit);
            self.wire_zero[idx] = self.wire_label(idx).zero();
            if matches!(party, Party::Evaluator) {
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

    /// Send garbler-owned labels to the evaluator explicitly.
    pub fn send_garbler_inputs(&mut self, wire_indices: &[usize], bits: &[bool]) {
        assert_eq!(wire_indices.len(), bits.len());
        for (&idx, &bit) in wire_indices.iter().zip(bits.iter()) {
            let lbl = self.wire_label(idx).label(bit);
            self.gen.send_block(&lbl).unwrap();
        }
    }

    /// Garble gates in the circuit using privacy-free AND.
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
                        let mut table = [Block::ZERO; 1];
                        let gid = self.gen.next_and_id();
                        let w0 = privacy_free_garble(
                            la0,
                            la1,
                            lb0,
                            lb1,
                            self.delta,
                            &mut table,
                            gid,
                            &self.gen.prp,
                        );
                        self.gen.send_block_vec(&table).unwrap();
                        self.wire_zero[g.output().id()] = w0;
                    }
                }
                crate::core::gate::GateKind::Xor => {
                    let a_pub = g.inputs()[0].public_value();
                    let b_pub = g.inputs()[1].public_value();
                    match (a_pub, b_pub) {
                        (Some(_), Some(_)) => {
                            // Output public; zero-label = public false.
                            self.wire_zero[g.output().id()] = self.gen.public_label(false);
                        }
                        (Some(_), None) => {
                            let b0 = self.zero_for_wire(g.inputs()[1]);
                            self.wire_zero[g.output().id()] = b0 ^ self.gen.public_label(false);
                        }
                        (None, Some(_)) => {
                            let a0 = self.zero_for_wire(g.inputs()[0]);
                            self.wire_zero[g.output().id()] = a0 ^ self.gen.public_label(false);
                        }
                        (None, None) => {
                            let a0 = self.zero_for_wire(g.inputs()[0]);
                            let b0 = self.zero_for_wire(g.inputs()[1]);
                            self.wire_zero[g.output().id()] = a0 ^ b0;
                        }
                    }
                }
                crate::core::gate::GateKind::Not => {
                    let a_pub = g.inputs()[0].public_value();
                    if let Some(val) = a_pub {
                        let lbl = if val {
                            self.gen.public_label(false) ^ self.delta
                        } else {
                            self.gen.public_label(true)
                        };
                        self.wire_zero[g.output().id()] = lbl;
                    } else {
                        let a0 = self.zero_for_wire(g.inputs()[0]);
                        self.wire_zero[g.output().id()] = a0 ^ self.delta;
                    }
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

    /// Expose the current output decoder.
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

    fn zero_for_wire(&mut self, wire: Wire) -> Block {
        if let Some(_value) = wire.public_value() {
            let z = self.gen.public_label(false);
            self.wire_zero[wire.id()] = z;
            return z;
        }
        if self.wire_zero[wire.id()] == Block::ZERO {
            self.wire_zero[wire.id()] = self.wire_label(wire.id()).zero();
        }
        self.wire_zero[wire.id()]
    }
}

/// Privacy-free evaluator that consumes garbled tables.
pub struct PrivacyFreeEvaluator<IO: IOChannel> {
    pub(crate) eva: PrivacyFreeEva<IO>,
    pub(crate) wire_labels: Vec<Block>,
    pub(crate) next_input: usize,
}

impl<IO: IOChannel> PrivacyFreeEvaluator<IO> {
    /// Initialize with an IO channel.
    pub fn new(io: IO) -> Self {
        Self {
            eva: PrivacyFreeEva::new(io),
            wire_labels: Vec::new(),
            next_input: 0,
        }
    }

    /// Receive labels for evaluator-owned input wires.
    pub fn feed(&mut self, party: Party, wire_indices: &[usize]) {
        if !matches!(party, Party::Evaluator) {
            return;
        }
        let need = wire_indices.iter().max().map(|x| x + 1).unwrap_or(0);
        if self.wire_labels.len() < need {
            self.wire_labels.resize(need, Block::ZERO);
        }
        for &idx in wire_indices {
            let lbl = self.eva.recv_block().unwrap();
            self.wire_labels[idx] = lbl;
        }
    }

    /// Receive garbler-owned input labels from the channel.
    pub fn receive_garbler_inputs(&mut self, wire_indices: &[usize]) {
        let need = wire_indices.iter().max().map(|x| x + 1).unwrap_or(0);
        if self.wire_labels.len() < need {
            self.wire_labels.resize(need, Block::ZERO);
        }
        for &idx in wire_indices {
            let lbl = self.eva.recv_block().unwrap();
            self.wire_labels[idx] = lbl;
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
                        let table = self.eva.recv_block().unwrap();
                        let a = self.label_for_wire(g.inputs()[0]);
                        let b = self.label_for_wire(g.inputs()[1]);
                        let gid = self.eva.num_and();
                        let out = privacy_free_eval(a, b, table, gid, &self.eva.prp);
                        self.eva.bump();
                        self.wire_labels[g.output().id()] = out;
                    }
                }
                crate::core::gate::GateKind::Xor => {
                    let a_pub = g.inputs()[0].public_value();
                    let b_pub = g.inputs()[1].public_value();
                    match (a_pub, b_pub) {
                        (Some(va), Some(vb)) => {
                            self.wire_labels[g.output().id()] =
                                self.eva.public_label(va ^ vb);
                        }
                        (Some(va), None) => {
                            let b = self.label_for_wire(g.inputs()[1]);
                            self.wire_labels[g.output().id()] =
                                if va { b ^ self.eva.public_label(true) } else { b };
                        }
                        (None, Some(vb)) => {
                            let a = self.label_for_wire(g.inputs()[0]);
                            self.wire_labels[g.output().id()] =
                                if vb { a ^ self.eva.public_label(true) } else { a };
                        }
                        (None, None) => {
                            let a = self.label_for_wire(g.inputs()[0]);
                            let b = self.label_for_wire(g.inputs()[1]);
                            self.wire_labels[g.output().id()] = a ^ b;
                        }
                    }
                }
                crate::core::gate::GateKind::Not => {
                    let a_pub = g.inputs()[0].public_value();
                    if let Some(val) = a_pub {
                        self.wire_labels[g.output().id()] = self.eva.public_label(!val);
                    } else {
                        let a = self.label_for_wire(g.inputs()[0]);
                        self.wire_labels[g.output().id()] = self.eva.public_label(true) ^ a;
                    }
                }
            }
        }
    }

    /// Send output labels back to the garbler.
    pub fn send_outputs(&mut self, outputs: &[usize]) -> Vec<Block> {
        let mut out_lbls = Vec::with_capacity(outputs.len());
        for &idx in outputs {
            let lbl = self.wire_labels[idx];
            self.eva.send_block(&lbl).unwrap();
            out_lbls.push(lbl);
        }
        out_lbls
    }

    fn label_for_wire(&mut self, wire: Wire) -> Block {
        if let Some(val) = wire.public_value() {
            return self.eva.public_label(val);
        }
        self.wire_labels[wire.id()]
    }
}

impl<IO: IOChannel> RuntimeProtocolExecution for PrivacyFreeGarbler<IO> {
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

impl<IO: IOChannel> RuntimeCircuitExecution for PrivacyFreeGarbler<IO> {
    fn and_gate(&mut self, a: Block, b: Block) -> Block {
        self.gen.and_gate(a, a ^ self.delta, b, b ^ self.delta)
    }

    fn xor_gate(&mut self, a: Block, b: Block) -> Block {
        a ^ b
    }

    fn not_gate(&mut self, a: Block) -> Block {
        a ^ self.gen.public_label(true)
    }

    fn public_label(&self, b: bool) -> Block {
        self.gen.public_label(b)
    }
}

impl<IO: IOChannel> RuntimeProtocolExecution for PrivacyFreeEvaluator<IO> {
    fn feed(&mut self, _party: Party, bits: &[bool]) -> Vec<Block> {
        let start = self.next_input;
        let end = start + bits.len();
        self.next_input = end;
        if self.wire_labels.len() < end {
            self.wire_labels.resize(end, Block::ZERO);
        }
        let mut lbls = Vec::with_capacity(bits.len());
        for idx in start..end {
            let lbl = self.eva.recv_block().unwrap();
            self.wire_labels[idx] = lbl;
            lbls.push(lbl);
        }
        lbls
    }

    fn reveal(&mut self, party: Party, labels: &[Block]) -> Vec<bool> {
        match party {
            Party::Garbler => {
                for lbl in labels {
                    self.eva.send_block(lbl).unwrap();
                }
                Vec::new()
            }
            Party::Evaluator => labels.iter().map(|_| false).collect(),
        }
    }
}

impl<IO: IOChannel> RuntimeCircuitExecution for PrivacyFreeEvaluator<IO> {
    fn and_gate(&mut self, a: Block, b: Block) -> Block {
        let tbl = self.eva.recv_block().unwrap();
        let gid = self.eva.num_and();
        let res = privacy_free_eval(a, b, tbl, gid, &self.eva.prp);
        self.eva.bump();
        res
    }

    fn xor_gate(&mut self, a: Block, b: Block) -> Block {
        a ^ b
    }

    fn not_gate(&mut self, a: Block) -> Block {
        self.eva.public_label(true) ^ a
    }

    fn public_label(&self, b: bool) -> Block {
        self.eva.public_label(b)
    }
}

impl<IO: IOChannel> PrivacyFreeEva<IO> {
    /// Create a new evaluator, receiving constants from the garbler.
    pub fn new(mut io: IO) -> Self {
        let mut constant = [Block::ZERO; 2];
        let consts = io.recv_block_vec(2).expect("recv constants");
        constant.copy_from_slice(&consts[..]);
        Self {
            io,
            constant,
            prp: Prp::new(Block::ZERO),
            gid: 0,
        }
    }

    /// Public label helper.
    pub fn public_label(&self, b: bool) -> Block {
        self.constant[b as usize]
    }

    /// Number of AND gates evaluated so far.
    pub fn num_and(&self) -> u64 {
        self.gid
    }

    /// Manually bump the gate counter (used by evaluator wrapper).
    pub fn bump(&mut self) {
        self.gid += 1;
    }

    /// IO helper: send a single block.
    pub fn send_block(&mut self, blk: &Block) -> std::io::Result<()> {
        self.io.send_block(blk)
    }

    /// IO helper: receive a block.
    pub fn recv_block(&mut self) -> std::io::Result<Block> {
        self.io.recv_block()
    }

    /// Evaluate a privacy-free AND gate, consuming one table block.
    pub fn and_gate(&mut self, a: Block, b: Block) -> Block {
        let tbl = self.io.recv_block().expect("recv pf table");
        let res = privacy_free_eval(a, b, tbl, self.gid, &self.prp);
        self.gid += 1;
        res
    }
}

/// Garble a single privacy-free AND gate, producing one table entry and w0.
pub fn privacy_free_garble(
    la0: Block,
    a1: Block,
    lb0: Block,
    _b1: Block,
    _delta: Block,
    table: &mut [Block; 1],
    gid: u64,
    prp: &Prp,
) -> Block {
    let tweak = Block::from([2 * gid as u64, 0u64]);
    let mut keys = [Block::sigma(la0) ^ tweak, Block::sigma(a1) ^ tweak];
    let masks = keys;
    prp.permute_block_slice(&mut keys);
    let mut hla0 = keys[0] ^ masks[0];
    let mut ha1 = keys[1] ^ masks[1];
    // Fix permute bits.
    let mut tmp: u128 = hla0.into();
    tmp &= !1u128;
    hla0 = Block::from(tmp);
    let mut t1: u128 = ha1.into();
    t1 |= 1u128;
    ha1 = Block::from(t1);
    let xor = hla0 ^ ha1;
    table[0] = xor ^ lb0;
    hla0
}

/// Evaluate a privacy-free AND gate.
pub fn privacy_free_eval(a: Block, b: Block, table: Block, gid: u64, prp: &Prp) -> Block {
    let sa = a.get_lsb();
    let tweak = Block::from([2 * gid as u64, 0u64]);
    let mut tmp = Block::sigma(a) ^ tweak;
    let mask = tmp;
    prp.permute_block_slice(std::slice::from_mut(&mut tmp));
    let mut ha = tmp ^ mask;
    let mut bits: u128 = ha.into();
    if sa {
        bits |= 1u128;
        ha = Block::from(bits);
        let mut w = ha ^ table;
        w ^= b;
        w
    } else {
        bits &= !1u128;
        Block::from(bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gc::mock_io::MockIO;
    use crate::gc::party::Party;
    use crate::core::circuit::Circuit;
    use crate::gc::input_map::InputMap;
    use emp_tool::Block;

    #[test]
    fn handshake_sets_delta_and_constants() {
        let (gio, eio) = MockIO::pair();
        let handle = std::thread::spawn(move || {
            let gen = PrivacyFreeGen::new(gio);
            (gen.delta(), gen.public_label(false), gen.public_label(true))
        });

        let eva = PrivacyFreeEva::new(eio);
        let (delta, c0_g, c1_g) = handle.join().unwrap();
        let c0_e = eva.public_label(false);
        let c1_e = eva.public_label(true);
        assert_ne!(delta, Block::ZERO);
        assert!(delta.get_lsb());
        assert_eq!(c0_g, c0_e);
        assert_eq!(c1_g, c1_e);
        assert_eq!(c1_g, c0_g ^ delta);
    }

    #[test]
    fn pf_and_matches_known_vector() {
        // Fixed test vector aligned with the C++ privacy-free primitive.
        let mut delta = Block::from([0x70afa76b7e34d831, 0xc3fb04611f403b10]);
        delta.set_lsb();
        let la0 = Block::from([0x1559ff9f3af59426, 0xf0e194d4c3db4845]);
        let lb0 = Block::from([0xce94a58dc6a20eb0, 0xcc7822a2420cff48]);
        let a1 = la0 ^ delta;
        let b1 = lb0 ^ delta;

        let prp = Prp::new(Block::ZERO);
        let mut table = [Block::ZERO; 1];
        let w0 = privacy_free_garble(la0, a1, lb0, b1, delta, &mut table, 0, &prp);
        // Evaluate on both 00 and 11.
        let out00 = privacy_free_eval(la0, lb0, table[0], 0, &prp);
        let out11 = privacy_free_eval(a1, b1, table[0], 0, &prp);

        let expected_table = Block::from([0x09b05accdde484c1, 0xf3dad2714977e724]);
        let expected_w0 = Block::from([0x88aeb70ef5bba86c, 0x36b6679694108750]);
        let expected_out11 = Block::from([0xf80110658b8f705d, 0xf54d63f78b50bc40]);

        assert_eq!(table[0], expected_table);
        assert_eq!(w0, expected_w0);
        assert_eq!(out00, expected_w0);
        assert_eq!(out11, expected_out11);
    }

    #[test]
    fn pf_end_to_end_and() {
        let mut c = Circuit::new();
        let a = c.fresh_wire();
        let b = c.fresh_wire();
        let out = c.and(a, b);
        let inputs_alice = [true];
        let inputs_bob = [false];
        let input_map = InputMap::new(inputs_alice.len(), inputs_bob.len());
        let input_map_e = input_map.clone();

        let (gio, eio) = MockIO::pair();
        let cg = c.clone();
        let ce = c.clone();
        let g_handle = std::thread::spawn(move || {
            let mut g = PrivacyFreeGarbler::new(gio, cg.wire_count());
            let alice_idx = input_map.indices(Party::Garbler);
            let bob_idx = input_map.indices(Party::Evaluator);
            g.feed(Party::Garbler, &alice_idx, &inputs_alice);
            g.send_garbler_inputs(&alice_idx, &inputs_alice);
            g.feed(Party::Evaluator, &bob_idx, &inputs_bob);
            g.garble(&cg);
            g.set_outputs(&[out.id()]);
            g.reveal(&[out.id()])[0]
        });

        let e_handle = std::thread::spawn(move || {
            let mut e = PrivacyFreeEvaluator::new(eio);
            let alice_idx = input_map_e.indices(Party::Garbler);
            let bob_idx = input_map_e.indices(Party::Evaluator);
            e.receive_garbler_inputs(&alice_idx);
            e.feed(Party::Evaluator, &bob_idx);
            e.evaluate(&ce);
            e.send_outputs(&[out.id()]);
        });

        let bit = g_handle.join().unwrap();
        e_handle.join().unwrap();
        assert_eq!(bit, inputs_alice[0] & inputs_bob[0]);
    }
}
