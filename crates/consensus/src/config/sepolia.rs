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
                ForkParameter::new(Version([144, 0, 0, 112]), U64(50)),
                ForkParameter::new(Version([144, 0, 0, 113]), U64(100)),
                ForkParameter::new(Version([144, 0, 0, 114]), U64(56832)),
                ForkParameter::new(Version([144, 0, 0, 115]), U64(132608)),
                ForkParameter::new(Version([144, 0, 0, 116]), U64(u64::MAX)),
            ],
        )
        .unwrap(),
        min_genesis_time: U64(1655647200),
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
