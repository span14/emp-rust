use crate::ferret::constants::{FERRET_B11, FERRET_B12, FERRET_B13, PrimalLpnParameter};

/// Convenience wrapper for selecting Ferret parameter presets.
#[derive(Clone, Copy, Debug)]
pub struct FerretConfig {
    pub params: PrimalLpnParameter,
    /// Density parameter for the LPN sampler (d in the paper).
    pub density: usize,
}

pub const FERRET_CONFIG_B13: FerretConfig = FerretConfig {
    params: FERRET_B13,
    density: 10,
};

pub const FERRET_CONFIG_B12: FerretConfig = FerretConfig {
    params: FERRET_B12,
    density: 10,
};

pub const FERRET_CONFIG_B11: FerretConfig = FerretConfig {
    params: FERRET_B11,
    density: 10,
};
