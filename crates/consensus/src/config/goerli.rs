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
                ForkParameter::new(Version([1, 0, 16, 32]), U64(36660)),
                ForkParameter::new(Version([2, 0, 16, 32]), U64(112260)),
                ForkParameter::new(Version([3, 0, 16, 32]), U64(162304)),
                ForkParameter::new(Version([4, 0, 16, 32]), U64(231680)),
                ForkParameter::new(Version([5, 0, 16, 32]), U64(u64::MAX)),
            ],
        ),
        min_genesis_time: U64(1614588812),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = get_config();
        assert!(config.fork_parameters.validate().is_ok());
    }
}
