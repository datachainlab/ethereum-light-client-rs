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
            Version([0, 0, 0, 0]),
            vec![
                ForkParameter::new(Version([1, 0, 0, 0]), U64(74240)),
                ForkParameter::new(Version([2, 0, 0, 0]), U64(144896)),
                ForkParameter::new(Version([3, 0, 0, 0]), U64(194048)),
                ForkParameter::new(Version([4, 0, 0, 0]), U64(269568)),
                ForkParameter::new(Version([5, 0, 0, 0]), U64(u64::MAX)),
            ],
        )
        .unwrap(),
        min_genesis_time: U64(1606824000),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let _ = get_config();
    }
}
