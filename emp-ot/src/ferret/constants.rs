/// Parameters copied from the upstream EMP ferret implementation.
#[derive(Clone, Copy, Debug)]
pub struct PrimalLpnParameter {
    pub n: i64,
    pub t: i64,
    pub k: i64,
    pub log_bin_sz: i64,
    pub n_pre: i64,
    pub t_pre: i64,
    pub k_pre: i64,
    pub log_bin_sz_pre: i64,
}

impl PrimalLpnParameter {
    pub const fn new(
        n: i64,
        t: i64,
        k: i64,
        log_bin_sz: i64,
        n_pre: i64,
        t_pre: i64,
        k_pre: i64,
        log_bin_sz_pre: i64,
    ) -> Self {
        Self {
            n,
            t,
            k,
            log_bin_sz,
            n_pre,
            t_pre,
            k_pre,
            log_bin_sz_pre,
        }
    }
}

pub const FERRET_B13: PrimalLpnParameter =
    PrimalLpnParameter::new(10_485_760, 1_280, 452_000, 13, 470_016, 918, 32_768, 9);
pub const FERRET_B12: PrimalLpnParameter =
    PrimalLpnParameter::new(10_268_672, 2_507, 238_000, 12, 268_800, 1_050, 17_384, 8);
pub const FERRET_B11: PrimalLpnParameter =
    PrimalLpnParameter::new(10_180_608, 4_971, 124_000, 11, 178_944, 699, 17_384, 8);
