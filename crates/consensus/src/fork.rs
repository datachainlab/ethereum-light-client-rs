pub mod altair;
pub mod bellatrix;
pub mod capella;
pub mod deneb;

use crate::beacon::{Epoch, Slot, Version};
use crate::errors::Error;
use crate::internal_prelude::*;
use crate::types::U64;

pub const GENESIS_SPEC: ForkSpec = ForkSpec {
    finalized_root_depth: 0,
    current_sync_committee_depth: 0,
    next_sync_committee_depth: 0,
    execution_payload_depth: 0,
    execution_payload_tree_depth: 0,
};

/// Fork parameters for the beacon chain
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ForkParameters {
    genesis_version: Version,
    /// Forks in order of ascending epoch
    /// The first element is the first fork after genesis
    /// i.e., [Altair, Bellatrix, Capella, Deneb, ...]
    forks: Vec<ForkParameter>,
}

impl ForkParameters {
    pub fn new(genesis_version: Version, forks: Vec<ForkParameter>) -> Result<Self, Error> {
        let this = Self {
            genesis_version,
            forks,
        };
        this.validate()?;
        Ok(this)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.forks.windows(2).all(|f| f[0].epoch <= f[1].epoch) {
            Ok(())
        } else {
            Err(Error::InvalidForkParamersOrder(self.clone()))
        }
    }

    pub fn genesis_slot(&self) -> Slot {
        U64(0)
    }

    pub fn genesis_version(&self) -> &Version {
        &self.genesis_version
    }

    pub fn forks(&self) -> &[ForkParameter] {
        &self.forks
    }

    /// Compute the fork version for the given epoch
    pub fn compute_fork_version(&self, epoch: Epoch) -> Version {
        self.compute_fork(epoch)
            .map(|f| f.version)
            .unwrap_or(self.genesis_version.clone())
    }

    /// Compute the fork spec for the given epoch
    pub fn compute_fork_spec(&self, epoch: Epoch) -> ForkSpec {
        self.compute_fork(epoch)
            .map(|f| f.spec)
            .unwrap_or(GENESIS_SPEC)
    }

    fn compute_fork(&self, epoch: Epoch) -> Option<ForkParameter> {
        self.forks.iter().rev().find(|f| epoch >= f.epoch).cloned()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ForkSpec {
    pub finalized_root_depth: u32,
    pub current_sync_committee_depth: u32,
    pub next_sync_committee_depth: u32,
    pub execution_payload_depth: u32,
    pub execution_payload_tree_depth: u32,
}

/// Fork parameters for each fork
/// In the mainnet, you can find the parameters here: https://github.com/ethereum/consensus-specs/blob/9849fb39e75e6228ebd610ef0ad22f5b41543cd5/configs/mainnet.yaml#L35
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ForkParameter {
    pub version: Version,
    pub epoch: Epoch,
    pub spec: ForkSpec,
}

impl ForkParameter {
    pub const fn new(version: Version, epoch: Epoch, spec: ForkSpec) -> Self {
        Self {
            version,
            epoch,
            spec,
        }
    }
}

#[cfg(test)]
mod tests {
    use altair::ALTAIR_FORK_SPEC;
    use bellatrix::BELLATRIX_FORK_SPEC;
    use capella::CAPELLA_FORK_SPEC;
    use deneb::DENEB_FORK_SPEC;

    use super::*;

    #[test]
    pub fn test_fork_parameters() {
        let res = ForkParameters::new(
            Version([0, 0, 0, 1]),
            vec![
                ForkParameter::new(Version([1, 0, 0, 1]), U64(0), ALTAIR_FORK_SPEC),
                ForkParameter::new(Version([2, 0, 0, 1]), U64(0), BELLATRIX_FORK_SPEC),
                ForkParameter::new(Version([3, 0, 0, 1]), U64(0), CAPELLA_FORK_SPEC),
                ForkParameter::new(Version([4, 0, 0, 1]), U64(0), DENEB_FORK_SPEC),
            ],
        );
        assert!(res.is_ok());
        let params = res.unwrap();
        assert_eq!(params.compute_fork_version(0.into()), Version([4, 0, 0, 1]));

        let res = ForkParameters::new(Version([0, 0, 0, 1]), vec![]);
        assert!(res.is_ok());
        let params = res.unwrap();
        assert_eq!(params.compute_fork_version(0.into()), Version([0, 0, 0, 1]));

        let res = ForkParameters::new(
            Version([0, 0, 0, 1]),
            vec![ForkParameter::new(
                Version([1, 0, 0, 1]),
                U64(0),
                ALTAIR_FORK_SPEC,
            )],
        );
        let params = res.unwrap();
        assert_eq!(params.compute_fork_version(0.into()), Version([1, 0, 0, 1]));

        let res = ForkParameters::new(
            Version([0, 0, 0, 1]),
            vec![
                ForkParameter::new(Version([1, 0, 0, 1]), U64(0), ALTAIR_FORK_SPEC),
                ForkParameter::new(Version([2, 0, 0, 1]), U64(1), BELLATRIX_FORK_SPEC),
                ForkParameter::new(Version([3, 0, 0, 1]), U64(2), CAPELLA_FORK_SPEC),
                ForkParameter::new(Version([4, 0, 0, 1]), U64(3), DENEB_FORK_SPEC),
            ],
        );
        assert!(res.is_ok());
        let params = res.unwrap();
        assert_eq!(params.compute_fork_version(0.into()), Version([1, 0, 0, 1]));
        assert_eq!(params.compute_fork_version(1.into()), Version([2, 0, 0, 1]));
        assert_eq!(params.compute_fork_version(2.into()), Version([3, 0, 0, 1]));
        assert_eq!(params.compute_fork_version(3.into()), Version([4, 0, 0, 1]));
        assert_eq!(params.compute_fork_version(4.into()), Version([4, 0, 0, 1]));

        let res = ForkParameters::new(
            Version([0, 0, 0, 1]),
            vec![
                ForkParameter::new(Version([2, 0, 0, 1]), U64(1), ALTAIR_FORK_SPEC),
                ForkParameter::new(Version([1, 0, 0, 1]), U64(0), GENESIS_SPEC),
            ],
        );
        assert!(res.is_err());
    }
}
