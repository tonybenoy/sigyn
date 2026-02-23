pub mod git;
pub mod conflict;
pub mod vector_clock;
pub mod crdt;
pub mod mdns;
pub mod state;

pub use vector_clock::VectorClock;
pub use conflict::{Conflict, ConflictResolution};
