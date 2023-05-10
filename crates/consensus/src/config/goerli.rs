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
            Version([0, 0, 16, 32]),
            vec![
                ForkParameter::new(Version([4, 0, 16, 32]), U64(u64::MAX)),
                ForkParameter::new(Version([3, 0, 16, 32]), U64(162304)),
                ForkParameter::new(Version([2, 0, 16, 32]), U64(112260)),
                ForkParameter::new(Version([1, 0, 16, 32]), U64(36660)),
            ],
        ),
        min_genesis_time: U64(1614588812),
    }
}
