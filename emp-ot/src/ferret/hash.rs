use emp_tool::Block;
use sha2::{Digest, Sha256};

/// Minimal correlation-robust hash over `Block` inputs.
///
/// This is a stand-in for the EMP CCRH/MITCCRH family. It hashes each block with
/// its position to derive a pseudorandom mask.
#[derive(Default, Clone, Debug)]
pub struct Ccrh;

impl Ccrh {
    pub fn hash_blocks(&self, inputs: &[Block]) -> Vec<Block> {
        inputs
            .iter()
            .enumerate()
            .map(|(i, b)| hash_block_with_idx(*b, i as u64))
            .collect()
    }
}

pub fn hash_block_with_idx(b: Block, idx: u64) -> Block {
    let mut hasher = Sha256::new();
    hasher.update(<[u8; 16]>::from(b));
    hasher.update(idx.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    Block::from(out)
}
