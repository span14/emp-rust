//! Half-gate garbling (Zahur et al.) ported from EMP.

use crate::core::protocol_runtime::CircuitExecution as RuntimeCircuitExecution;
use emp_tool::{prg::Prg, Block, IOChannel, Mitccrh};

/// Garble a single AND gate using half-gates. Returns the 0-label for the
/// output wire and fills `table` with the two ciphertext blocks.
pub(crate) fn halfgates_garble(
    la0: Block,
    a1: Block,
    lb0: Block,
    b1: Block,
    delta: Block,
    table: &mut [Block; 2],
    mitccrh: &mut Mitccrh,
) -> Block {
    let pa = la0.get_lsb();
    let pb = lb0.get_lsb();

    let mut h = [la0, a1, lb0, b1];
    mitccrh.hash_cir::<2, 2>(&mut h);
    let hla0 = h[0];
    let ha1 = h[1];
    let hlb0 = h[2];
    let hb1 = h[3];

    table[0] = hla0 ^ ha1 ^ (Block::SELECT_MASK[pb as usize] & delta);

    let mut w0 = hla0 ^ (Block::SELECT_MASK[pa as usize] & table[0]);

    let tmp = hlb0 ^ hb1;
    table[1] = tmp ^ la0;
    w0 ^= hlb0;
    w0 ^= Block::SELECT_MASK[pb as usize] & tmp;

    w0
}

/// Evaluate a half-gate AND given input labels and table.
pub fn halfgates_eval(a: Block, b: Block, table: &[Block; 2], mitccrh: &mut Mitccrh) -> Block {
    let sa = a.get_lsb();
    let sb = b.get_lsb();

    let mut h = [a, b];
    mitccrh.hash_cir::<2, 1>(&mut h);
    let ha = h[0];
    let hb = h[1];

    let mut w = ha ^ hb;
    w ^= Block::SELECT_MASK[sa as usize] & table[0];
    w ^= Block::SELECT_MASK[sb as usize] & table[1];
    w ^= Block::SELECT_MASK[sb as usize] & a;
    w
}

/// Half-gate garbler.
pub struct HalfGateGen<IO: IOChannel> {
    delta: Block,
    io: IO,
    pub(crate) constant: [Block; 2],
    pub(crate) mitccrh: Mitccrh,
}

impl<IO: IOChannel> HalfGateGen<IO> {
    /// Create a new garbler, sampling delta and seeds, and sending public labels to the evaluator.
    pub fn new(io: IO) -> Self {
        let mut tmp = [Block::ZERO; 2];
        Prg::new().random_blocks(&mut tmp);
        let mut gen = Self {
            delta: Block::ZERO,
            io,
            constant: [Block::ZERO; 2],
            mitccrh: Mitccrh::new(),
        };
        gen.set_delta(tmp[0]).expect("send delta constants");
        gen.io.send_block(&tmp[1]).expect("send mitccrh seed");
        gen.mitccrh.set_s(tmp[1]);
        gen.mitccrh.renew_with_gid(0);
        gen
    }

    fn set_delta(&mut self, mut delta: Block) -> std::io::Result<()> {
        delta.set_lsb();
        self.delta = delta;
        let mut c0 = [Block::ZERO; 1];
        Prg::new().random_blocks(&mut c0);
        let mut raw: u128 = c0[0].into();
        raw &= !1u128;
        self.constant[0] = Block::from(raw);
        self.constant[1] = self.constant[0] ^ delta;
        self.io.send_block_vec(&self.constant)?;
        Ok(())
    }

    /// Public label helper.
    pub fn public_label(&self, b: bool) -> Block {
        self.constant[b as usize]
    }

    /// Garble an AND gate and send its table.
    pub fn and_gate(&mut self, a: Block, b: Block) -> Block {
        let mut table = [Block::ZERO; 2];
        let res = halfgates_garble(
            a,
            a ^ self.delta,
            b,
            b ^ self.delta,
            self.delta,
            &mut table,
            &mut self.mitccrh,
        );
        self.io.send_block_vec(&table).expect("send table");
        res
    }

    /// XOR gate (free-XOR).
    pub fn xor_gate(&self, a: Block, b: Block) -> Block {
        a ^ b
    }

    /// NOT gate via XOR with public true label.
    pub fn not_gate(&self, a: Block) -> Block {
        self.xor_gate(a, self.public_label(true))
    }

    /// Number of ANDs garbled so far.
    pub fn num_and(&self) -> u64 {
        self.mitccrh.gid() / 2
    }

    /// Access delta.
    pub fn delta(&self) -> Block {
        self.delta
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

/// Half-gate evaluator.
pub struct HalfGateEva<IO: IOChannel> {
    pub(crate) io: IO,
    constant: [Block; 2],
    pub(crate) mitccrh: Mitccrh,
}

impl<IO: IOChannel> HalfGateEva<IO> {
    /// Create a new evaluator, receiving public labels and seed from the garbler.
    pub fn new(mut io: IO) -> Self {
        let mut constant = [Block::ZERO; 2];
        let consts = io.recv_block_vec(2).expect("recv constants");
        constant.copy_from_slice(&consts[..]);
        let seed = io.recv_block().expect("recv mitccrh seed");
        let mut mitccrh = Mitccrh::new();
        mitccrh.set_s(seed);
        mitccrh.renew_with_gid(0);
        Self {
            io,
            constant,
            mitccrh,
        }
    }

    /// Public label helper.
    pub fn public_label(&self, b: bool) -> Block {
        self.constant[b as usize]
    }

    /// Evaluate AND gate by consuming two table blocks from the channel.
    pub fn and_gate(&mut self, a: Block, b: Block) -> Block {
        let tbl = self.io.recv_block_vec(2).expect("recv table");
        let table = [tbl[0], tbl[1]];
        halfgates_eval(a, b, &table, &mut self.mitccrh)
    }

    /// XOR gate (free-XOR).
    pub fn xor_gate(&self, a: Block, b: Block) -> Block {
        a ^ b
    }

    /// NOT gate via XOR with public true label.
    pub fn not_gate(&self, a: Block) -> Block {
        self.xor_gate(a, self.public_label(true))
    }

    /// Number of ANDs evaluated so far.
    pub fn num_and(&self) -> u64 {
        self.mitccrh.gid() / 2
    }
}

impl<IO: IOChannel> RuntimeCircuitExecution for HalfGateGen<IO> {
    fn and_gate(&mut self, a: Block, b: Block) -> Block {
        <HalfGateGen<IO>>::and_gate(self, a, b)
    }

    fn xor_gate(&mut self, a: Block, b: Block) -> Block {
        <HalfGateGen<IO>>::xor_gate(self, a, b)
    }

    fn not_gate(&mut self, a: Block) -> Block {
        <HalfGateGen<IO>>::not_gate(self, a)
    }

    fn public_label(&self, b: bool) -> Block {
        <HalfGateGen<IO>>::public_label(self, b)
    }
}

impl<IO: IOChannel> RuntimeCircuitExecution for HalfGateEva<IO> {
    fn and_gate(&mut self, a: Block, b: Block) -> Block {
        <HalfGateEva<IO>>::and_gate(self, a, b)
    }

    fn xor_gate(&mut self, a: Block, b: Block) -> Block {
        <HalfGateEva<IO>>::xor_gate(self, a, b)
    }

    fn not_gate(&mut self, a: Block) -> Block {
        <HalfGateEva<IO>>::not_gate(self, a)
    }

    fn public_label(&self, b: bool) -> Block {
        <HalfGateEva<IO>>::public_label(self, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::{unbounded, Receiver, Sender};
    use std::sync::Arc;

    #[test]
    fn half_gate_functions_match() {
        // Test vector taken from the C++ implementation for matching parity.
        let delta = Block::from([0x70afa76b7e34d831, 0xc3fb04611f403b10]);
        let seed = Block::from([0x2936929b986f518f, 0x8a41ad73c9b0f5d3]);
        let a0 = Block::from([0x1559ff9f3af59426, 0xf0e194d4c3db4845]);
        let a1 = Block::from([0x65f658f444c14c17, 0x331a90b5dc9b7355]);
        let b0 = Block::from([0xce94a58dc6a20eb0, 0xcc7822a2420cff48]);
        let b1 = Block::from([0xbe3b02e6b896d681, 0x0f8326c35d4cc458]);
        let expected_table0 = Block::from([0x9e6fad62d1505220, 0x360cda8e01c6fe00]);
        let expected_table1 = Block::from([0x373e2a950937783d, 0xb3c1dfd662ff5ee8]);
        let expected_w0 = Block::from([0xea7a7c56d4ebd884, 0xb12ae6bec83ce6d4]);
        let expected_out11 = Block::from([0x9ad5db3daadf00b5, 0x72d1e2dfd77cddc4]);

        let mut table = [Block::ZERO; 2];
        let mut mit = Mitccrh::new();
        mit.set_s(seed);
        mit.renew_with_gid(0);
        let mut mit_eval = mit.clone();

        let w0 = halfgates_garble(a0, a1, b0, b1, delta, &mut table, &mut mit);
        assert_eq!(table[0], expected_table0);
        assert_eq!(table[1], expected_table1);
        assert_eq!(w0, expected_w0);

        let out00 = halfgates_eval(a0, b0, &table, &mut mit_eval);

        let mut mit_eval2 = Mitccrh::new();
        mit_eval2.set_s(seed);
        mit_eval2.renew_with_gid(0);
        let out11 = halfgates_eval(a1, b1, &table, &mut mit_eval2);

        assert_eq!(out00, expected_w0);
        assert_eq!(out11, expected_out11);
    }

    /// Simple in-memory IO channel for tests.
    struct MockIO {
        tx: Sender<Vec<u8>>,
        rx: Arc<Receiver<Vec<u8>>>,
        stash: Vec<u8>,
    }

    impl MockIO {
        fn pair() -> (Self, Self) {
            let (a_tx, a_rx) = unbounded::<Vec<u8>>();
            let (b_tx, b_rx) = unbounded::<Vec<u8>>();
            (
                MockIO {
                    tx: a_tx,
                    rx: Arc::new(b_rx),
                    stash: Vec::new(),
                },
                MockIO {
                    tx: b_tx,
                    rx: Arc::new(a_rx),
                    stash: Vec::new(),
                },
            )
        }
    }

    impl IOChannel for MockIO {
        fn send_bytes(&mut self, buffer: &[u8]) -> std::io::Result<()> {
            self.tx.send(buffer.to_vec()).unwrap();
            Ok(())
        }

        fn recv_bytes(&mut self, buffer: &mut [u8]) -> std::io::Result<()> {
            while self.stash.len() < buffer.len() {
                let chunk = self.rx.recv().unwrap();
                self.stash.extend_from_slice(&chunk);
            }
            let tail = self.stash.split_off(buffer.len());
            buffer.copy_from_slice(&self.stash);
            self.stash = tail;
            Ok(())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn end_to_end_and() {
        use crate::core::circuit::Circuit;
        let (garbler_io, eva_io) = MockIO::pair();

        // Build circuit: out = a AND b
        let mut c = Circuit::new();
        let a = c.fresh_wire();
        let b = c.fresh_wire();
        let out = c.and(a, b);
        assert_eq!(out.id(), 2);

        let alice_input = true;
        let bob_input = false;

        // Garbler thread
        let garbler = std::thread::spawn(move || {
            let mut gen = HalfGateGen::new(garbler_io);
            let mut prg = Prg::new();
            let delta = gen.delta();

            // assign labels for all wires
            let mut zero_labels = vec![Block::ZERO; c.wire_count()];
            for z in zero_labels.iter_mut() {
                *z = prg.random_block();
                if z.get_lsb() == false {
                    // ensure permute bit random enough; leave as is
                }
            }
            let one_labels: Vec<Block> = zero_labels.iter().map(|z| *z ^ delta).collect();

            // send input labels to evaluator
            let lbl_a = if alice_input {
                one_labels[a.id()]
            } else {
                zero_labels[a.id()]
            };
            let lbl_b = if bob_input {
                one_labels[b.id()]
            } else {
                zero_labels[b.id()]
            };
            gen.io.send_block(&lbl_a).unwrap();
            gen.io.send_block(&lbl_b).unwrap();

            // evaluate/garble
            let la0 = zero_labels[a.id()];
            let lb0 = zero_labels[b.id()];
            let la1 = one_labels[a.id()];
            let lb1 = one_labels[b.id()];
            let mut table = [Block::ZERO; 2];
            let w0 = halfgates_garble(la0, la1, lb0, lb1, delta, &mut table, &mut gen.mitccrh);
            gen.io.send_block_vec(&table).unwrap();
            let lbl_out = if alice_input & bob_input {
                w0 ^ delta
            } else {
                w0
            };

            // receive evaluator's output label and decode
            let eva_out = gen.io.recv_block().unwrap();
            let decoded = if eva_out == lbl_out {
                alice_input & bob_input
            } else {
                !(alice_input & bob_input)
            };
            decoded
        });

        // Evaluator thread
        let evaluator = std::thread::spawn(move || {
            let mut eva = HalfGateEva::new(eva_io);
            let lbl_a = eva.io.recv_block().unwrap();
            let lbl_b = eva.io.recv_block().unwrap();
            let table = {
                let tbl = eva.io.recv_block_vec(2).unwrap();
                [tbl[0], tbl[1]]
            };
            let out_lbl = halfgates_eval(lbl_a, lbl_b, &table, &mut eva.mitccrh);
            eva.io.send_block(&out_lbl).unwrap();
        });

        let decoded = garbler.join().unwrap();
        evaluator.join().unwrap();
        assert_eq!(decoded, alice_input & bob_input);
    }

    #[test]
    fn end_to_end_small_circuit() {
        use crate::core::circuit::Circuit;
        // Circuit: ((a AND b) XOR c)
        let mut circ = Circuit::new();
        let a = circ.fresh_wire();
        let b = circ.fresh_wire();
        let c = circ.fresh_wire();
        let t = circ.and(a, b);
        let out = circ.xor(t, c);
        assert_eq!(out.id(), 4);

        let inputs = [true, true, false]; // expected output = true

        let (garbler_io, eva_io) = MockIO::pair();
        let circ_g = circ.clone();
        let _circ_e = circ.clone();
        let garbler = std::thread::spawn(move || {
            let mut gen = HalfGateGen::new(garbler_io);
            let mut prg = Prg::new();
            let delta = gen.delta();

            // labels for all wires
            let mut zero = Vec::with_capacity(circ_g.wire_count());
            for _ in 0..circ_g.wire_count() {
                let lbl = prg.random_block();
                zero.push(lbl);
            }
            let one: Vec<Block> = zero.iter().map(|z| *z ^ delta).collect();

            // send input labels to evaluator
            for (i, &val) in inputs.iter().enumerate() {
                let lbl = if val { one[i] } else { zero[i] };
                gen.io.send_block(&lbl).unwrap();
            }

            // garble gates
            let mut wire_val: Vec<Block> = Vec::with_capacity(circ_g.wire_count());
            wire_val.resize(circ_g.wire_count(), Block::ZERO);
            let mut bit_val: Vec<bool> = Vec::with_capacity(circ_g.wire_count());
            bit_val.resize(circ_g.wire_count(), false);
            // set input labels (garbler knows inputs)
            for (i, &val) in inputs.iter().enumerate() {
                wire_val[i] = if val { one[i] } else { zero[i] };
                bit_val[i] = val;
            }
            for g in circ_g.gates() {
                match g.kind() {
                    crate::core::gate::GateKind::And => {
                        let _a = wire_val[g.inputs()[0].id()];
                        let _b = wire_val[g.inputs()[1].id()];
                        let abit = bit_val[g.inputs()[0].id()];
                        let bbit = bit_val[g.inputs()[1].id()];
                        // need both zero/one for each input wire
                        let la0 = zero[g.inputs()[0].id()];
                        let lb0 = zero[g.inputs()[1].id()];
                        let la1 = one[g.inputs()[0].id()];
                        let lb1 = one[g.inputs()[1].id()];
                        let mut table = [Block::ZERO; 2];
                        let w0 = halfgates_garble(
                            la0,
                            la1,
                            lb0,
                            lb1,
                            delta,
                            &mut table,
                            &mut gen.mitccrh,
                        );
                        gen.io.send_block_vec(&table).unwrap();
                        // derive output label depending on actual bits
                        let lbl_out = if abit & bbit { w0 ^ delta } else { w0 };
                        wire_val[g.output().id()] = lbl_out;
                        bit_val[g.output().id()] = abit & bbit;
                    }
                    crate::core::gate::GateKind::Xor => {
                        let a = wire_val[g.inputs()[0].id()];
                        let b = wire_val[g.inputs()[1].id()];
                        wire_val[g.output().id()] = a ^ b;
                        bit_val[g.output().id()] =
                            bit_val[g.inputs()[0].id()] ^ bit_val[g.inputs()[1].id()];
                    }
                    crate::core::gate::GateKind::Not => {
                        let a = wire_val[g.inputs()[0].id()];
                        wire_val[g.output().id()] = a ^ gen.public_label(true);
                        bit_val[g.output().id()] = !bit_val[g.inputs()[0].id()];
                    }
                }
            }
            // receive evaluator output and compare
            let eva_lbl = gen.io.recv_block().unwrap();
            let expected_lbl = wire_val[out.id()];
            eva_lbl == expected_lbl
        });

        let circ_e = circ.clone();
        let evaluator = std::thread::spawn(move || {
            let mut eva = HalfGateEva::new(eva_io);
            let mut in_labels = Vec::new();
            for _ in 0..3 {
                in_labels.push(eva.io.recv_block().unwrap());
            }
            let mut wire = in_labels;
            for g in circ_e.gates() {
                match g.kind() {
                    crate::core::gate::GateKind::And => {
                        let table = {
                            let tbl = eva.io.recv_block_vec(2).unwrap();
                            [tbl[0], tbl[1]]
                        };
                        let a = wire[g.inputs()[0].id()];
                        let b = wire[g.inputs()[1].id()];
                        wire.push(halfgates_eval(a, b, &table, &mut eva.mitccrh));
                    }
                    crate::core::gate::GateKind::Xor => {
                        let a = wire[g.inputs()[0].id()];
                        let b = wire[g.inputs()[1].id()];
                        wire.push(a ^ b);
                    }
                    crate::core::gate::GateKind::Not => {
                        let a = wire[g.inputs()[0].id()];
                        wire.push(eva.not_gate(a));
                    }
                }
            }
            // send last wire as output label
            let out_lbl = wire[out.id()];
            eva.io.send_block(&out_lbl).unwrap();
            out_lbl
        });

        let garbler_ok = garbler.join().unwrap();
        let eva_lbl = evaluator.join().unwrap();
        assert!(garbler_ok, "garbler rejected evaluator output");
        assert_ne!(eva_lbl, Block::ZERO); // basic sanity
    }
}
