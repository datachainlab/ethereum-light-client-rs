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

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ForkParameters {
    genesis_version: Version,
    /// Forks in order of increasing epoch
    forks: Vec<ForkParameter>,
}

impl ForkParameters {
    pub const fn new(genesis_version: Version, forks: Vec<ForkParameter>) -> Self {
        Self {
            genesis_version,
            forks,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
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

    pub fn compute_fork_version(&self, epoch: Epoch) -> Result<&Version, Error> {
        for fork in self.forks.iter().rev() {
            if epoch >= fork.epoch {
                return Ok(&fork.version);
            }
        }
        Ok(&self.genesis_version)
    }

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
