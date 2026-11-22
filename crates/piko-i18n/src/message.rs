//! A sentence as an identifier and its arguments.

use std::borrow::Cow;

/// A sentence that a frontend renders in the language of its user.
///
/// The identifier names a message in the catalog, for example `solve-fact-requires`. Each
/// argument fills one variable of that message, by name.
///
/// The identifier and the names are `Cow<'static, str>`. A library builds them from string
/// literals, at no cost. A client that receives a message from another process builds them from
/// owned strings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    id: Cow<'static, str>,
    args: Vec<(Cow<'static, str>, Arg)>,
}

impl Message {
    /// A message with no arguments yet.
    #[must_use]
    pub fn new(id: impl Into<Cow<'static, str>>) -> Self {
        Self { id: id.into(), args: Vec::new() }
    }

    /// Adds the value of the variable `name`.
    #[must_use]
    pub fn arg(mut self, name: impl Into<Cow<'static, str>>, value: impl Into<Arg>) -> Self {
        self.args.push((name.into(), value.into()));
        self
    }

    /// The identifier of the message in the catalog.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The value of each variable, by name, in the order they were added.
    #[must_use]
    pub fn args(&self) -> &[(Cow<'static, str>, Arg)] {
        &self.args
    }
}

/// The value of one variable of a [`Message`].
///
/// The kind decides how a catalog uses the value. A count selects a plural form, and a text
/// never does.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Arg {
    /// Text the message quotes as it is: a package name, a relation, a path.
    ///
    /// The catalog does not escape it. A frontend escapes text that came from a package or a
    /// mirror before it builds the message.
    Text(String),
    /// A number of items. A catalog selects the plural form of the language with it.
    Count(u64),
    /// A number of bytes. A catalog writes it in the largest binary unit it reaches, with the
    /// decimal mark and the unit names of its language: `1.46 KiB` in English.
    Size(u64),
    /// Another message, rendered in the same language and quoted as text.
    ///
    /// For a value that is itself a sentence or a word the language translates: the reason
    /// inside an error, or the name of a limit.
    Message(Box<Message>),
}

impl Arg {
    /// `items` as one list: each pair is joined by the message `join`, whose variables are
    /// `$head` and `$tail`. An empty list is an empty text.
    ///
    /// The separator is a message, so each language writes its own: `{ $head }, { $tail }`,
    /// `{ $head } or { $tail }`. The list nests one message per item, so keep it short: a
    /// caller shows the first items of a long list and counts the rest.
    pub fn list(items: impl IntoIterator<Item = Message>, join: &'static str) -> Self {
        let items: Vec<Message> = items.into_iter().collect();
        let list = items
            .into_iter()
            .rev()
            .reduce(|tail, head| Message::new(join).arg("head", head).arg("tail", tail));
        list.map_or_else(|| Self::Text(String::new()), Self::from)
    }
}

impl From<Message> for Arg {
    fn from(value: Message) -> Self {
        Self::Message(Box::new(value))
    }
}

impl From<&str> for Arg {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<String> for Arg {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&String> for Arg {
    fn from(value: &String) -> Self {
        Self::Text(value.clone())
    }
}

impl From<u32> for Arg {
    fn from(value: u32) -> Self {
        Self::Count(u64::from(value))
    }
}

impl From<u64> for Arg {
    fn from(value: u64) -> Self {
        Self::Count(value)
    }
}

impl From<usize> for Arg {
    fn from(value: usize) -> Self {
        // A `usize` is at most 64 bits on every target piko builds for. The saturation only
        // keeps the conversion total.
        Self::Count(u64::try_from(value).unwrap_or(u64::MAX))
    }
}

/// A value that has a [`Message`].
///
/// A library type implements this beside its English `Display`. The English catalog renders
/// the message as `Display` writes it.
pub trait Localize {
    /// The message that describes this value.
    fn message(&self) -> Message;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_keep_their_order_and_their_kind() {
        let message = Message::new("plan-matched").arg("pattern", "gnome-*").arg("count", 3usize);
        assert_eq!(message.id(), "plan-matched");
        assert_eq!(
            message.args(),
            &[
                (Cow::Borrowed("pattern"), Arg::Text("gnome-*".to_owned())),
                (Cow::Borrowed("count"), Arg::Count(3)),
            ]
        );
    }

    #[test]
    fn a_message_nests_in_another() {
        let inner = Message::new("inner");
        let outer = Message::new("outer").arg("reason", inner.clone());
        assert_eq!(outer.args(), &[(Cow::Borrowed("reason"), Arg::Message(Box::new(inner)))]);
    }

    #[test]
    fn a_list_nests_from_its_first_item() {
        let list = Arg::list([Message::new("a"), Message::new("b"), Message::new("c")], "join");
        let tail =
            Message::new("join").arg("head", Message::new("b")).arg("tail", Message::new("c"));
        let whole = Message::new("join").arg("head", Message::new("a")).arg("tail", tail);
        assert_eq!(list, Arg::from(whole));
        assert_eq!(Arg::list([Message::new("a")], "join"), Arg::from(Message::new("a")));
        assert_eq!(Arg::list([], "join"), Arg::Text(String::new()));
    }

    #[test]
    fn an_owned_identifier_is_accepted() {
        let message = Message::new(String::from("received-from-a-service"));
        assert_eq!(message.id(), "received-from-a-service");
    }
}
