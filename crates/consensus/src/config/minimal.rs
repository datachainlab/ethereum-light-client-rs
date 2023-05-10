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
        preset: preset::minimal::PRESET,
        fork_parameters: ForkParameters::new(
            Version([0, 0, 0, 1]),
            vec![
                ForkParameter::new(Version([4, 0, 0, 1]), U64(u64::MAX)),
                ForkParameter::new(Version([3, 0, 0, 1]), U64(0)),
                ForkParameter::new(Version([2, 0, 0, 1]), U64(0)),
                ForkParameter::new(Version([1, 0, 0, 1]), U64(0)),
            ],
        ),
        min_genesis_time: U64(1578009600),
    }
}
