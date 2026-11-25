//! The parts of `mailserv` that are pure functions over untrusted bytes,
//! built as a library so they can be fuzzed (`fuzz/`) and reused: the
//! envelope syntax checks ([`address`]) and the raw header checks run at
//! end of data ([`headers`]). They hold no state and do no I/O. The
//! server binary (`main.rs`) uses them from here.
#![warn(missing_docs)]

pub mod address;
pub mod headers;
