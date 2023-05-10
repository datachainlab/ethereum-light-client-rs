use crate::beacon::{Epoch, Slot, Version};
use crate::errors::Error;
use crate::internal_prelude::*;
use crate::types::U64;

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ForkParameters {
    pub genesis_version: Version,
    pub forks: Vec<ForkParameter>,
}

impl ForkParameters {
    pub const fn new(genesis_version: Version, forks: Vec<ForkParameter>) -> Self {
        Self {
            genesis_version,
            forks,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.forks.windows(2).all(|f| f[0].epoch >= f[1].epoch) {
            Ok(())
        } else {
            Err(Error::InvalidForkParamersOrder(self.clone()))
        }
    }

    pub fn genesis_slot(&self) -> Slot {
        U64(0)
    }

    pub fn compute_fork_version(&self, epoch: Epoch) -> Result<&Version, Error> {
        for fork in self.forks.iter() {
            if epoch >= fork.epoch {
                return Ok(&fork.version);
            }
        }
        Ok(&self.genesis_version)
    }
}

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
