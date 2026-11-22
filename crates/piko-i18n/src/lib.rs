//! Translatable messages for piko.
//!
//! A library crate does not write a sentence in a language. It returns a [`Message`]: an
//! identifier and the values the sentence quotes. A frontend renders the message in the
//! language of its user, through a [`Catalog`]. The CLI and a second frontend, a GUI for
//! example, so read the same translations.
//!
//! The split matters most when the two ends of a message run in two processes. A service that
//! runs as root has the language of root. Its client has the language of the user. The service
//! sends the identifier and the values, and the client renders them.
//!
//! # Two layers
//!
//! - [`Message`], [`Arg`] and [`Localize`] have no dependency. Every library crate uses them.
//! - [`Catalog`], [`Language`], [`Placeables`] and the [`audit`] module need the `catalog`
//!   feature. They hold the Fluent runtime and the translations, and only a frontend needs them.
//!
//! A library type keeps its English `Display`. A log, a test, and a caller with no catalog
//! still get a sentence. Each crate tests that the English catalog renders every message
//! exactly as `Display` does, so the two cannot drift apart.
//!
//! # The translations are in the binary
//!
//! The `.ftl` files in `locales/` are compiled into the crate. piko reads no translation from
//! the disk at run time. A translation file read by root would be a new input that another
//! user could change, with its own trust and size checks. A translation is still text that
//! piko writes to a terminal, so [`audit::check`] refuses a control character or a
//! bidirectional override in it.
//!
//! The same files are the data a frontend in another language reads. The identifiers and the
//! variable names are the interface.
//!
//! # Stability
//!
//! Each public item has one path. The items are exported from the crate root, except the
//! [`audit`] module, which answers one question of its own.
//!
//! - **A result or a report is `#[non_exhaustive]`:** [`FormatError`],
//!   [`audit::Discrepancy`]. Match it with a wildcard arm.
//! - **A closed set is exhaustive:** [`Arg`] and [`Placeables`]. A new kind of argument changes
//!   what every renderer must do. An [`Arg::Message`] nests a message in another, so an error
//!   quotes its reason in the same language.
//! - [`Language`] is `#[non_exhaustive]`. A new translation is not a breaking change.
//! - [`Message`] has private fields. Build it with [`Message::new`] and [`Message::arg`].

mod message;

pub use message::{Arg, Localize, Message};

#[cfg(feature = "catalog")]
mod catalog;
#[cfg(feature = "catalog")]
mod language;

#[cfg(feature = "catalog")]
pub mod audit;

#[cfg(feature = "catalog")]
pub use catalog::{Catalog, FormatError, Placeables};
#[cfg(feature = "catalog")]
pub use language::Language;
