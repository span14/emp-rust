use emp_tool::{Block, aes::Aes};

/// Two-key PRP using a small Feistel network with AES-derived round function.
///
/// This is still a simplified construction but provides an invertible permutation
/// with separate keys for the round function.
#[derive(Clone)]
pub struct TwoKeyPrp {
    k0: Aes,
    k1: Aes,
}

impl TwoKeyPrp {
    pub fn new(k0: Block, k1: Block) -> Self {
        Self {
            k0: Aes::new(k0),
            k1: Aes::new(k1),
        }
    }

    /// Permute a block.
    pub fn permute(&self, input: Block) -> Block {
        feistel(input, |b| self.f(b))
    }

    /// Invert a previously permuted block.
    pub fn invert(&self, input: Block) -> Block {
        feistel_inverse(input, |b| self.f(b))
    }

    fn f(&self, right: Block) -> Block {
        let a = self.k0.encrypt_block(right);
        let b = self.k1.encrypt_block(right);
        a ^ b
    }

    /// Expand one parent into two children using PRP outputs.
    pub fn node_expand_1to2(&self, children: &mut [Block], parent: Block) {
        let left = self.permute(parent ^ Block::from(0u128));
        let right = self.permute(parent ^ Block::from(1u128));
        children[0] = left;
        children[1] = right;
    }

    /// Expand two parents into four children.
    pub fn node_expand_2to4(&self, children: &mut [Block], parents: &[Block]) {
        self.node_expand_1to2(&mut children[0..2], parents[0]);
        self.node_expand_1to2(&mut children[2..4], parents[1]);
    }

    /// Expand four parents into eight children.
    pub fn node_expand_4to8(&self, children: &mut [Block], parents: &[Block]) {
        self.node_expand_1to2(&mut children[0..2], parents[0]);
        self.node_expand_1to2(&mut children[2..4], parents[1]);
        self.node_expand_1to2(&mut children[4..6], parents[2]);
        self.node_expand_1to2(&mut children[6..8], parents[3]);
    }
}

fn feistel<F: Fn(Block) -> Block>(state: Block, f: F) -> Block {
    let mut halves: [u64; 2] = state.into();
    for _ in 0..4 {
        let l = halves[0];
        let r = halves[1];
        let fr: u128 = f(Block::from([0u64, r])).into();
        halves[0] = r;
        halves[1] = l ^ (fr as u64);
    }
    Block::from(halves)
}

fn feistel_inverse<F: Fn(Block) -> Block>(state: Block, f: F) -> Block {
    let mut halves: [u64; 2] = state.into();
    for _ in 0..4 {
        let l = halves[0];
        let r = halves[1];
        let fr: u128 = f(Block::from([0u64, l])).into();
        halves[0] = r ^ (fr as u64);
        halves[1] = l;
    }
    Block::from(halves)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prp_round_trip() {
        let prp = TwoKeyPrp::new(Block::from(1u128), Block::from(2u128));
        let inputs = [
            Block::from(0u128),
            Block::from(42u128),
            Block::from(u128::MAX / 2),
            Block::from(0xDEADBEEFCAFEBABE_u128),
        ];
        for &inp in &inputs {
            let perm = prp.permute(inp);
            let inv = prp.invert(perm);
            assert_eq!(inv, inp);
        }
    }
}
