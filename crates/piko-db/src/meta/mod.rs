//! The metadata formats piko reads itself: the `%SECTION%` grammar of `desc` and `files`, and
//! the `key = value` grammar of `.PKGINFO`.
//!
//! piko reads these formats with its own reader, and converts each value with `alpm-types`.
//! The reader allocates nothing: every [`section::Section`] borrows the text it came from.
//! The caller decides what a section means, and how a malformed value is reported.

pub(crate) mod desc;
pub mod files;
pub mod kv;
pub mod section;

#[cfg(test)]
mod properties;
