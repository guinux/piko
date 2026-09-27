//! Text from outside piko, made safe to print on a terminal.
//!
//! A package, a server and a file on disk all choose bytes that piko later prints: a member
//! path, a `.PKGINFO` value quoted in a parse error, a server's message. An escape sequence
//! among them could rewrite what the terminal shows, set its title, or write its clipboard. A
//! line break could print a line piko never wrote. So every such value is escaped before it
//! reaches a message.

/// `text` with every control character and every bidirectional formatting character written as
/// an escape.
///
/// Everything else is kept as it reads, so an ordinary path or message is unchanged.
#[must_use]
pub fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() || is_bidi_control(character) {
            out.extend(character.escape_debug());
        } else {
            out.push(character);
        }
    }
    out
}

/// `path`, converted to text and escaped as [`printable`] does.
#[must_use]
pub fn printable_path(path: &std::path::Path) -> String {
    printable(&path.to_string_lossy())
}

/// Whether `character` changes the direction the text around it is shown in.
const fn is_bidi_control(character: char) -> bool {
    matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message is kept as it reads, except what could drive a terminal.
    #[test]
    fn printable_escapes_what_could_drive_a_terminal() {
        assert_eq!(printable("connection reset: \"core.db\""), "connection reset: \"core.db\"");
        assert_eq!(printable("é ok"), "é ok");
        assert_eq!(printable("a\u{1b}]52;c;cHduZWQ=\u{7}b"), "a\\u{1b}]52;c;cHduZWQ=\\u{7}b");
        assert_eq!(printable("one\nWarning: two"), "one\\nWarning: two");
        assert_eq!(printable("\u{9b}31m"), "\\u{9b}31m");
        assert_eq!(printable("abc\u{202e}fed"), "abc\\u{202e}fed");
    }

    #[test]
    fn a_path_is_escaped_the_same_way() {
        assert_eq!(printable_path(std::path::Path::new("usr/bin/ls")), "usr/bin/ls");
        assert_eq!(printable_path(std::path::Path::new("usr/\u{1b}[2J")), "usr/\\u{1b}[2J");
    }
}
