// Re-export pure modules from sigyn-core
pub use sigyn_core::{crypto, delegation, environment, error, rotation, secrets};
pub mod forks;
pub use sigyn_core::{Result, SigynError};

// Engine-specific modules (I/O layer + re-exports from core)
pub mod audit;
pub mod hierarchy;
pub mod identity;
pub mod io;
pub mod policy;
pub mod sync;
pub mod vault;
