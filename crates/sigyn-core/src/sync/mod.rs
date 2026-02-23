pub mod conflict;
pub mod crdt;
pub mod git;
pub mod mdns;
pub mod state;
pub mod vector_clock;

pub use conflict::{Conflict, ConflictResolution};
pub use vector_clock::VectorClock;
