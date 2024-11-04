#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
#![allow(clippy::result_large_err)]
extern crate alloc;

#[allow(unused_imports)]
mod internal_prelude {
    pub use alloc::string::{String, ToString};
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

pub mod beacon;
pub mod bls;
pub mod compute;
pub mod config;
pub mod context;
pub mod errors;
pub mod fork;
pub mod merkle;
pub mod preset;
pub mod sync_protocol;
pub mod types;

/// re-export
pub use milagro_bls;
pub use ssz_rs;
