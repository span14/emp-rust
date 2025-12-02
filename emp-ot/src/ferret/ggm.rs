use crate::ferret::twokeyprp::TwoKeyPrp;
use emp_tool::Block;

/// Generate a full binary GGM tree of depth `depth` (number of levels of internal nodes + leaves).
/// Leaves are returned in `leaves` (length 2^{depth-1}). Internal XORs per level are returned in `ot_msgs0/1`.
pub fn ggm_expand(
    prp: &TwoKeyPrp,
    seed: Block,
    depth: usize,
    leaves: &mut [Block],
    ot_msgs0: &mut [Block],
    ot_msgs1: &mut [Block],
) {
    assert!(depth >= 2);
    assert_eq!(leaves.len(), 1usize << (depth - 1));
    assert_eq!(ot_msgs0.len(), depth - 1);
    assert_eq!(ot_msgs1.len(), depth - 1);

    // Level 0 -> 1
    let mut level = vec![Block::ZERO; 1];
    level[0] = seed;
    let mut next = vec![Block::ZERO; 2];
    prp.node_expand_1to2(&mut next, level[0]);
    ot_msgs0[0] = next[0];
    ot_msgs1[0] = next[1];

    // Level 1 -> leaves
    level = next;
    let mut width = 2;
    for h in 1..depth - 1 {
        next = vec![Block::ZERO; width * 2];
        // Expand in chunks of 4->8 when possible
        if width >= 4 {
            for chunk in 0..(width / 4) {
                let parents = &level[chunk * 4..chunk * 4 + 4];
                let children = &mut next[chunk * 8..chunk * 8 + 8];
                prp.node_expand_4to8(children, parents);
            }
        } else {
            // Fallback on 2->4 expansion
            for chunk in 0..(width / 2) {
                let parents = &level[chunk * 2..chunk * 2 + 2];
                let children = &mut next[chunk * 4..chunk * 4 + 4];
                prp.node_expand_2to4(children, parents);
            }
        }
        let mut xor0 = Block::ZERO;
        let mut xor1 = Block::ZERO;
        for child in next.chunks_exact(2) {
            xor0 ^= child[0];
            xor1 ^= child[1];
        }
        ot_msgs0[h] = xor0;
        ot_msgs1[h] = xor1;
        level = next.clone();
        width *= 2;
    }

    leaves.copy_from_slice(&level);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ggm_outputs_deterministic() {
        let prp = TwoKeyPrp::new(Block::from(1u128), Block::from(2u128));
        let mut leaves = vec![Block::ZERO; 8];
        let mut m0 = vec![Block::ZERO; 3];
        let mut m1 = vec![Block::ZERO; 3];
        ggm_expand(&prp, Block::from(42u128), 4, &mut leaves, &mut m0, &mut m1);
        let mut leaves2 = vec![Block::ZERO; 8];
        let mut m02 = vec![Block::ZERO; 3];
        let mut m12 = vec![Block::ZERO; 3];
        ggm_expand(
            &prp,
            Block::from(42u128),
            4,
            &mut leaves2,
            &mut m02,
            &mut m12,
        );
        assert_eq!(leaves, leaves2);
        assert_eq!(m0, m02);
        assert_eq!(m1, m12);
    }
}
