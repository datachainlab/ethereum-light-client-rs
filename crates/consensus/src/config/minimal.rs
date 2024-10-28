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
                // altair
                ForkParameter::new(Version([1, 0, 0, 1]), U64(0)),
                // belatrix
                ForkParameter::new(Version([2, 0, 0, 1]), U64(0)),
                // capella
                ForkParameter::new(Version([3, 0, 0, 1]), U64(0)),
                // deneb
                ForkParameter::new(Version([4, 0, 0, 1]), U64(0)),
            ],
        )
        .unwrap(),
        min_genesis_time: U64(1578009600),
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
