use super::Config;
use crate::{
    beacon::Version,
    fork::{ForkParameter, ForkParameters},
    internal_prelude::*,
    preset,
    types::U64,
};

pub fn get_config() -> Config {
    Config {
        preset: preset::mainnet::PRESET,
        fork_parameters: ForkParameters::new(
            Version([144, 0, 0, 105]),
            vec![
                ForkParameter::new(Version([144, 0, 0, 0]), U64(u64::MAX)),
                ForkParameter::new(Version([144, 0, 0, 114]), U64(56832)),
                ForkParameter::new(Version([144, 0, 0, 113]), U64(100)),
                ForkParameter::new(Version([144, 0, 0, 112]), U64(50)),
            ],
        ),
        min_genesis_time: U64(1655647200),
    }
}
