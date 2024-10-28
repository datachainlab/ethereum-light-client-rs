pub mod bellatrix;
pub mod capella;
pub mod deneb;

use crate::beacon::{Epoch, Slot, Version};
use crate::errors::Error;
use crate::internal_prelude::*;
use crate::types::U64;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Fork {
    Genesis(Version),
    Altair(ForkParameter),
    Bellatrix(ForkParameter),
    Capella(ForkParameter),
    Deneb(ForkParameter),
}

impl Fork {
    pub fn execution_payload_tree_depth(&self) -> Result<usize, Error> {
        match self {
            Fork::Genesis(v) => Err(Error::NotSupportedExecutionPayload(v.clone())),
            Fork::Altair(f) => Err(Error::NotSupportedExecutionPayload(f.version.clone())),
            Fork::Bellatrix(_) => Ok(bellatrix::EXECUTION_PAYLOAD_TREE_DEPTH),
            Fork::Capella(_) => Ok(capella::EXECUTION_PAYLOAD_TREE_DEPTH),
            Fork::Deneb(_) => Ok(deneb::EXECUTION_PAYLOAD_TREE_DEPTH),
        }
    }
}

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
    pub fn compute_fork_version(&self, epoch: Epoch) -> Result<&Version, Error> {
        for fork in self.forks.iter().rev() {
            if epoch >= fork.epoch {
                return Ok(&fork.version);
            }
        }
        Ok(&self.genesis_version)
    }

    /// Compute the fork for the given epoch
    ///
    /// If `forks` does not contain a fork for the given epoch, it returns an error.
    pub fn compute_fork(&self, epoch: Epoch) -> Result<Fork, Error> {
        for (i, fork) in self.forks.iter().enumerate().rev() {
            if epoch >= fork.epoch {
                let fork = fork.clone();
                return Ok(match i {
                    0 => Fork::Altair(fork),
                    1 => Fork::Bellatrix(fork),
                    2 => Fork::Capella(fork),
                    3 => Fork::Deneb(fork),
                    _ => return Err(Error::UnknownFork(epoch, fork.epoch, i)),
                });
            }
        }
        Ok(Fork::Genesis(self.genesis_version.clone()))
    }
}

/// Fork parameters for each fork
/// In the mainnet, you can find the parameters here: https://github.com/ethereum/consensus-specs/blob/9849fb39e75e6228ebd610ef0ad22f5b41543cd5/configs/mainnet.yaml#L35
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ForkParameter {
    pub version: Version,
    pub epoch: Epoch,
}

impl ForkParameter {
    pub const fn new(version: Version, epoch: Epoch) -> Self {
        Self { version, epoch }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_fork_parameters() {
        let res = ForkParameters::new(
            Version([0, 0, 0, 1]),
            vec![
                ForkParameter::new(Version([1, 0, 0, 1]), U64(0)),
                ForkParameter::new(Version([2, 0, 0, 1]), U64(0)),
                ForkParameter::new(Version([3, 0, 0, 1]), U64(0)),
                ForkParameter::new(Version([4, 0, 0, 1]), U64(0)),
            ],
        );
        assert!(res.is_ok());
        let params = res.unwrap();
        let res = params.compute_fork(0.into());
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            Fork::Deneb(ForkParameter::new(Version([4, 0, 0, 1]), U64(0)))
        );

        let res = ForkParameters::new(Version([0, 0, 0, 1]), vec![]);
        assert!(res.is_ok());
        let params = res.unwrap();
        let res = params.compute_fork(0.into());
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Fork::Genesis(Version([0, 0, 0, 1])));

        let res = ForkParameters::new(
            Version([0, 0, 0, 1]),
            vec![ForkParameter::new(Version([1, 0, 0, 1]), U64(0))],
        );
        let params = res.unwrap();
        let res = params.compute_fork(0.into());
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            Fork::Altair(ForkParameter::new(Version([1, 0, 0, 1]), U64(0)))
        );

        let res = ForkParameters::new(
            Version([0, 0, 0, 1]),
            vec![
                ForkParameter::new(Version([1, 0, 0, 1]), U64(0)),
                ForkParameter::new(Version([2, 0, 0, 1]), U64(1)),
                ForkParameter::new(Version([3, 0, 0, 1]), U64(2)),
                ForkParameter::new(Version([4, 0, 0, 1]), U64(3)),
            ],
        );
        assert!(res.is_ok());
        let params = res.unwrap();
        let res = params.compute_fork(0.into());
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            Fork::Altair(ForkParameter::new(Version([1, 0, 0, 1]), U64(0)))
        );
        let res = params.compute_fork(1.into());
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            Fork::Bellatrix(ForkParameter::new(Version([2, 0, 0, 1]), U64(1)))
        );
        let res = params.compute_fork(2.into());
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            Fork::Capella(ForkParameter::new(Version([3, 0, 0, 1]), U64(2)))
        );
        let res = params.compute_fork(3.into());
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            Fork::Deneb(ForkParameter::new(Version([4, 0, 0, 1]), U64(3)))
        );
        let res = params.compute_fork(4.into());
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            Fork::Deneb(ForkParameter::new(Version([4, 0, 0, 1]), U64(3)))
        );

        let res = ForkParameters::new(
            Version([0, 0, 0, 1]),
            vec![
                ForkParameter::new(Version([2, 0, 0, 1]), U64(1)),
                ForkParameter::new(Version([1, 0, 0, 1]), U64(0)),
            ],
        );
        assert!(res.is_err());
    }
}
