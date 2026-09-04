//! One module per database a subcommand reads: the local database, a repository archive, the
//! two together, and the configuration file.
//!
//! Every function here returns an [`ExitCode`] rather than a `Result`. A subcommand's failure
//! modes are already reported at the point they happen (through [`crate::output::report`]).
//! The caller only needs to know whether to exit non-zero.

pub mod check;
pub mod conf;
pub mod files;
pub mod history;
pub mod info;
pub mod list;
pub mod local;
pub mod plan;
pub mod refresh;
pub mod removal;
pub mod repo;
pub mod search;
pub mod sync;
pub mod txn;
pub mod why;
