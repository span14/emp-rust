use crate::{Role, Share};
use emp_tool::{Aes, Block, io_channel::IOChannel, prg::Prg};
use rand::SeedableRng;
use std::io;

/// Stateful context that owns the global key, delta, nonce and IO channel.
pub struct OneHotContext<'a, IO: IOChannel> {
    role: Role,
    io: &'a mut IO,
    prg: Prg,
    fixed_key: Aes,
    delta: Block,
    nonce: u64,
}

impl<'a, IO: IOChannel> OneHotContext<'a, IO> {
    /// Create a generator context.
    pub fn new_generator(io: &'a mut IO, fixed_key: Block, seed: Block) -> Self {
        let mut prg = Prg::from_seed(seed);
        let mut delta: u128 = prg.random_block().into();
        delta |= 1;
        Self {
            role: Role::Generator,
            io,
            prg,
            fixed_key: Aes::new(fixed_key),
            delta: Block::from(delta),
            nonce: 0,
        }
    }

    /// Create an evaluator context.
    pub fn new_evaluator(io: &'a mut IO, fixed_key: Block, seed: Block) -> Self {
        Self {
            role: Role::Evaluator,
            io,
            prg: Prg::from_seed(seed),
            fixed_key: Aes::new(fixed_key),
            delta: Block::ZERO,
            nonce: 0,
        }
    }

    /// Return the party role.
    #[inline(always)]
    pub fn role(&self) -> Role {
        self.role
    }

    /// Return the global delta (only meaningful for the generator).
    #[inline(always)]
    pub fn delta(&self) -> Block {
        self.delta
    }

    /// Current nonce.
    #[inline(always)]
    pub(crate) fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Set nonce to a specific value.
    #[inline(always)]
    pub(crate) fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }

    #[inline(always)]
    pub(crate) fn bump_nonce(&mut self, by: u64) {
        self.nonce = self.nonce.wrapping_add(by);
    }

    #[inline(always)]
    pub(crate) fn is_generator(&self) -> bool {
        self.role == Role::Generator
    }

    /// Create a constant share (0/1).
    #[inline(always)]
    pub fn bit(&self, value: bool) -> Share {
        if value {
            Share(self.delta)
        } else {
            Share(Block::ZERO)
        }
    }

    /// Sample a random bit label.
    #[inline(always)]
    pub fn uniform_bit(&mut self) -> Share {
        if self.is_generator() {
            let b = self.prg.random_bool();
            self.bit(b)
        } else {
            self.bit(false)
        }
    }

    /// Logical NOT implemented by xoring with delta (no-op for the evaluator).
    #[inline(always)]
    pub fn not(&self, s: Share) -> Share {
        if self.is_generator() {
            Share(s.0 ^ self.delta)
        } else {
            s
        }
    }

    /// Hash a label with an explicit tweak.
    #[inline(always)]
    pub(crate) fn hash_with_tweak(&self, label: Share, tweak: u64) -> Share {
        let tweak_block = Block::from(tweak as u128);
        Share(self.fixed_key.encrypt_block(label.0 ^ tweak_block))
    }

    /// Hash a label with the current nonce.
    #[inline(always)]
    pub(crate) fn hash_current(&self, label: Share) -> Share {
        self.hash_with_tweak(label, self.nonce)
    }

    /// Send/receive a garbled input bit from the generator.
    pub fn ginput(&mut self, value: bool) -> io::Result<Share> {
        if self.is_generator() {
            let label = Share(self.prg.random_block());
            let masked = Share(label.0 ^ self.bit(value).0);
            self.io.send_block(&masked.0)?;
            Ok(label)
        } else {
            Ok(Share(self.io.recv_block()?))
        }
    }

    /// Reveal the color bit of `share`. Returns the opened bit.
    pub fn reveal(&mut self, share: &mut Share) -> io::Result<bool> {
        if self.is_generator() {
            let bit = share.color();
            self.io.send_bool(&bit)?;
            share.clear_color();
            Ok(bit)
        } else {
            let bit = self.io.recv_bool()?;
            share.xor_color(bit);
            Ok(share.color())
        }
    }

    /// Half-gate AND.
    pub fn and_gate(&mut self, a: Share, b: Share) -> io::Result<Share> {
        let a_color = a.color();
        let b_color = b.color();
        let zero = self.bit(false);
        let one = self.bit(true);

        if self.is_generator() {
            // Evaluator gate
            let nonce0 = self.nonce;
            let x = self.hash_with_tweak(Share(a.0 ^ if a_color { one.0 } else { zero.0 }), nonce0);
            let e_row = self
                .hash_with_tweak(Share(a.0 ^ if a_color { zero.0 } else { one.0 }), nonce0)
                ^ x
                ^ b;
            self.io.send_block(&e_row.0)?;
            self.bump_nonce(1);

            // Garbler gate
            let nonce1 = self.nonce;
            let y = self.hash_with_tweak(Share(b.0 ^ if b_color { one.0 } else { zero.0 }), nonce1)
                ^ if a_color && b_color { one } else { zero };
            let g_row = self
                .hash_with_tweak(Share(b.0 ^ if b_color { zero.0 } else { one.0 }), nonce1)
                ^ y
                ^ if a_color && !b_color { one } else { zero };
            self.io.send_block(&g_row.0)?;
            self.bump_nonce(1);

            Ok(Share(x.0 ^ y.0))
        } else {
            // Evaluator gate
            let nonce0 = self.nonce;
            let e_row = Share(self.io.recv_block()?);
            let x = self.hash_with_tweak(a, nonce0) ^ if a_color { e_row ^ b } else { zero };
            self.bump_nonce(1);

            // Garbler gate
            let nonce1 = self.nonce;
            let g_row = Share(self.io.recv_block()?);
            let y = self.hash_with_tweak(b, nonce1) ^ if b_color { g_row } else { zero };
            self.bump_nonce(1);

            Ok(Share(x.0 ^ y.0))
        }
    }

    #[inline(always)]
    pub(crate) fn io_mut(&mut self) -> &mut IO {
        self.io
    }
}
