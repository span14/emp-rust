//! Define constants used in the libraries.

/// Party PUBLIC
pub const PUBLIC: usize = 0;

/// Party ALICE
pub const ALICE: usize = 1;

/// Party BOB
pub const BOB: usize = 2;

/// Default network buffer size (1 MiB)
pub const NETWORK_BUFFER_SIZE: usize = 1024 * 1024;

/// Auxiliary network buffer size (32 KiB) used by high-speed channels
pub const NETWORK_BUFFER_SIZE2: usize = 1024 * 32;

/// Default file IO buffer size (16 KiB)
pub const FILE_BUFFER_SIZE: usize = 1024 * 16;
