use emp_tool::Block;
use std::ops::{BitXor, BitXorAssign};

/// A garbled wire label.
#[derive(Clone, Copy, Debug, Default)]
pub struct Share(pub Block);

impl Share {
    /// Return the color (least-significant bit) of the label.
    #[inline(always)]
    pub fn color(&self) -> bool {
        let v: u128 = self.0.into();
        (v & 1) == 1
    }

    /// Clear the color bit.
    #[inline(always)]
    pub fn clear_color(&mut self) {
        let mut v: u128 = self.0.into();
        v &= !1;
        self.0 = Block::from(v);
    }

    /// XOR the color bit with `bit`.
    #[inline(always)]
    pub(crate) fn xor_color(&mut self, bit: bool) {
        if bit {
            let mut v: u128 = self.0.into();
            v ^= 1;
            self.0 = Block::from(v);
        }
    }
}

impl BitXor for Share {
    type Output = Share;

    #[inline(always)]
    fn bitxor(self, rhs: Share) -> Self::Output {
        Share(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for Share {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Share) {
        self.0 ^= rhs.0;
    }
}
