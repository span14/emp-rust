#![deny(missing_docs)]

//! This crate defines and implements basic tools for MPC
#![cfg_attr(target_arch = "aarch64", feature(stdsimd))]
pub mod aes;

pub mod block;
pub mod constants;
pub mod f2k;
pub mod ggm_tree;
pub mod group;
pub mod hash;
pub mod io_channel;
pub mod lpn;
pub mod mitccrh;
pub mod prg;
pub mod prp;
pub mod sse2neon;
pub mod tkprp;
pub mod utils;

pub use aes::Aes;
pub use block::Block;
pub use constants::{ALICE, BOB, PUBLIC};
pub use f2k::{
    gfmul, gfmul_reflect, mul128, reduce, uni_hash_coeff_gen, vector_inn_prdt_sum_no_red,
    vector_inn_prdt_sum_red,
};
pub use group::{BigInt, Group, Point};
pub use hash::{CcrHash, CrHash, TccrHash};
pub use io_channel::{CommandLineOpt, FileIO, IOChannel, MemIO, NetIO};
pub use mitccrh::Mitccrh;
pub use utils::{
    block_to_bools, bools_to_block, bools_to_u128, clock_start, file_exists, int_to_bools,
    pack_bits_to_bytes, time_from, unpack_bytes_to_bits,
};
