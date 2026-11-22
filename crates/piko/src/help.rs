//! The `--help` text, in the language of the user.
//!
//! The doc comments of `cli` are the English text. `locales/*/help.ftl` holds one message per
//! text, named after the command and the argument it describes:
//!
//! ```text
//! help-about                    the about line of piko
//! help-list-about               the about line of `piko list`
//! help-list-long-about          its long about, when it has more than one paragraph
//! help-list-arg-repo            the help line of `piko list --repo`
//! help-list-arg-repo-long       its long help
//! help-key-list-keys-about      the about line of `piko key list-keys`
//! ```
//!
//! The English catalog holds each text exactly as clap reads it from the doc comment, and a
//! test compares the two. In another language, [`localize`] replaces each text before clap
//! parses the command line.

use clap::{ArgAction, Command};
use piko_i18n::{Language, Message};

use crate::i18n::tr;

/// The prefix of the messages of `path`, the names of the subcommands down to a command.
fn prefix(path: &str) -> String {
    if path.is_empty() { "help".to_owned() } else { format!("help-{path}") }
}

/// `path` with the subcommand `name` added.
fn child(path: &str, name: &str) -> String {
    if path.is_empty() { name.to_owned() } else { format!("{path}-{name}") }
}

/// `command` with each help text in `language`.
///
/// English is the doc comments themselves, so the command is returned as it is. Another
/// language costs a rendering of each text, on every run.
///
/// The words clap writes itself are replaced too, once the command is built and they exist:
/// the headings, the `--help` and `--version` flags, the `help` subcommand, a default value and
/// an alias. An error in the command line is `crate::parse_error`'s.
pub fn localize(command: Command, language: Language) -> Command {
    if language == Language::English {
        return command;
    }
    let mut command = replace(command, "");
    command.build();
    clap_words(command)
}

/// Whether clap added `command` itself: the `help` subcommand, which has no doc comment.
fn clap_wrote(command: &Command) -> bool {
    command.get_about().is_some_and(|about| about.to_string().starts_with("Print this message"))
}

/// `command` and every subcommand below it, with the words clap writes in the language of
/// this process.
fn clap_words(mut command: Command) -> Command {
    let usage = *command.get_styles().get_usage();
    let heading = format!("{}{}{}", usage.render(), tr!("cli-help-usage"), usage.render_reset());
    command = command
        .help_template(format!(
            "{{before-help}}{{about-with-newline}}\n{heading} {{usage}}\n\n{{all-args}}{{after-help}}"
        ))
        .subcommand_help_heading(tr!("cli-help-commands"));

    let ids: Vec<String> = command.get_arguments().map(|arg| arg.get_id().to_string()).collect();
    for id in ids {
        command = command.mut_arg(&id, |mut arg| {
            // A positional argument under a named heading is listed in display order, so it
            // takes its position as its order.
            arg = match arg.get_index() {
                Some(index) => arg.help_heading(tr!("cli-help-arguments")).display_order(index),
                None => arg.help_heading(tr!("cli-help-options")),
            };
            match arg.get_action() {
                ArgAction::Help => {
                    return arg
                        .help(tr!("cli-help-print-help"))
                        .long_help(tr!("cli-help-print-help-long"));
                }
                ArgAction::Version => return arg.help(tr!("cli-help-print-version")),
                _ => {}
            }
            let shows_default = arg.get_action().takes_values()
                && !arg.is_hide_default_value_set()
                && !arg.get_default_values().is_empty();
            if shows_default {
                let values: Vec<String> = arg
                    .get_default_values()
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect();
                let marker = tr!("cli-help-default", value = values.join(" "));
                let help = arg.get_help().map(ToString::to_string).unwrap_or_default();
                arg = arg.hide_default_value(true).help(format!("{help} {marker}"));
                if let Some(long_help) = arg.get_long_help().map(ToString::to_string) {
                    arg = arg.long_help(format!("{long_help}\n\n{marker}"));
                }
            }
            arg
        });
    }

    let names: Vec<String> =
        command.get_subcommands().map(|each| each.get_name().to_owned()).collect();
    for name in names {
        command = command.mut_subcommand(&name, |mut subcommand| {
            // The subcommand clap adds, which `piko` has no doc comment for.
            if name == "help" && clap_wrote(&subcommand) {
                subcommand = subcommand.about(tr!("cli-help-subcommand"));
                if subcommand.get_arguments().any(|arg| arg.get_id() == "subcommand") {
                    subcommand = subcommand
                        .mut_arg("subcommand", |arg| arg.help(tr!("cli-help-subcommand-arg")));
                }
            }
            let visible: Vec<String> =
                subcommand.get_visible_aliases().map(str::to_owned).collect();
            if !visible.is_empty() {
                let all: Vec<String> = subcommand.get_all_aliases().map(str::to_owned).collect();
                let about = subcommand.get_about().map(ToString::to_string).unwrap_or_default();
                let marker =
                    tr!("cli-help-aliases", aliases = visible.join(", "), count = visible.len());
                subcommand =
                    subcommand.visible_alias(None).aliases(all).about(format!("{about} {marker}"));
            }
            clap_words(subcommand)
        });
    }
    command
}

fn replace(mut command: Command, path: &str) -> Command {
    let prefix = prefix(path);
    let text = |id: String| crate::i18n::render(&Message::new(id));
    if command.get_about().is_some() {
        command = command.about(text(format!("{prefix}-about")));
    }
    if command.get_long_about().is_some() {
        command = command.long_about(text(format!("{prefix}-long-about")));
    }
    let args: Vec<(String, bool, bool)> = command
        .get_arguments()
        .map(|arg| {
            (arg.get_id().to_string(), arg.get_help().is_some(), arg.get_long_help().is_some())
        })
        .collect();
    for (id, help, long_help) in args {
        command = command.mut_arg(&id, |mut arg| {
            if help {
                arg = arg.help(text(format!("{prefix}-arg-{id}")));
            }
            if long_help {
                arg = arg.long_help(text(format!("{prefix}-arg-{id}-long")));
            }
            arg
        });
    }
    let names: Vec<String> =
        command.get_subcommands().map(|each| each.get_name().to_owned()).collect();
    for name in names {
        let path = child(path, &name);
        command = command.mut_subcommand(&name, |subcommand| replace(subcommand, &path));
    }
    command
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::CommandFactory as _;
    use piko_i18n::{Catalog, Placeables};

    use super::*;
    use crate::cli::Cli;

    /// The help texts of `command` and of every subcommand below it: the message identifier of
    /// each, and its text as clap holds it.
    fn texts(command: &Command) -> Vec<(String, String)> {
        let mut found = Vec::new();
        collect(command, "", &mut found);
        found
    }

    fn collect(command: &Command, path: &str, found: &mut Vec<(String, String)>) {
        let prefix = prefix(path);
        if let Some(about) = command.get_about() {
            found.push((format!("{prefix}-about"), about.to_string()));
        }
        if let Some(about) = command.get_long_about() {
            found.push((format!("{prefix}-long-about"), about.to_string()));
        }
        for arg in command.get_arguments() {
            let id = arg.get_id().as_str();
            if let Some(help) = arg.get_help() {
                found.push((format!("{prefix}-arg-{id}"), help.to_string()));
            }
            if let Some(help) = arg.get_long_help() {
                found.push((format!("{prefix}-arg-{id}-long"), help.to_string()));
            }
        }
        for subcommand in command.get_subcommands() {
            collect(subcommand, &child(path, subcommand.get_name()), found);
        }
    }

    /// `text` as a Fluent message named `id`: each line indented, a brace and a character
    /// Fluent reads at the start of a line put in a string literal.
    fn entry(id: &str, text: &str) -> String {
        let mut entry = format!("{id} =");
        for line in text.split('\n') {
            entry.push('\n');
            if line.is_empty() {
                continue;
            }
            entry.push_str("    ");
            for (index, character) in line.chars().enumerate() {
                let special = matches!(character, '{' | '}')
                    || (index == 0 && matches!(character, '[' | '*' | '.'));
                if special {
                    entry.push_str(&format!("{{\"{character}\"}}"));
                } else {
                    entry.push(character);
                }
            }
        }
        entry
    }

    fn english() -> Catalog {
        crate::i18n::HELP.iter().fold(
            Catalog::new(Language::English, Placeables::Plain),
            |catalog, (language, source)| catalog.with(*language, source),
        )
    }

    /// The English catalog is the doc comments. A doc comment changed without its message
    /// fails here, and the message prints the entry to copy into `locales/en/help.ftl`.
    #[test]
    fn the_english_catalog_holds_each_help_text_as_written() {
        let catalog = english();
        for (id, text) in texts(&Cli::command()) {
            let rendered = catalog.try_format(&Message::new(id.clone()));
            assert!(
                rendered.as_deref() == Ok(text.as_str()),
                "{id} differs from its doc comment; the entry is:\n\n{}\n",
                entry(&id, &text)
            );
        }
    }

    #[test]
    fn every_help_message_names_a_help_text() {
        let english = crate::i18n::HELP
            .iter()
            .find(|(language, _)| *language == Language::English)
            .map(|(_, source)| *source)
            .unwrap_or_default();
        let messages: BTreeSet<String> = piko_i18n::audit::variables(english).into_keys().collect();
        let texts: BTreeSet<String> =
            texts(&Cli::command()).into_iter().map(|(id, _)| id).collect();
        let unused: Vec<_> = messages.difference(&texts).collect();
        assert!(unused.is_empty(), "no help text has these messages: {unused:?}");
        assert!(texts.len() > 100, "the walk found only {} texts", texts.len());
    }

    /// A localized command replaces each text it has, and only those.
    #[test]
    fn a_localized_command_has_the_same_texts() {
        let command = replace(Cli::command(), "");
        let before: Vec<String> = texts(&Cli::command()).into_iter().map(|(id, _)| id).collect();
        let after: Vec<String> = texts(&command).into_iter().map(|(id, _)| id).collect();
        assert_eq!(before, after);
        command.debug_assert();
    }

    /// The words clap writes are replaced on every command it built, the `help` subcommand and
    /// its copies of the tree included, and each help still renders. A test renders in English,
    /// so this checks the walk, not the words.
    #[test]
    fn every_command_renders_its_localized_help() {
        fn render(command: &mut Command) {
            let help = command.render_long_help().to_string();
            assert!(!help.is_empty(), "{}", command.get_name());
            let names: Vec<String> =
                command.get_subcommands().map(|each| each.get_name().to_owned()).collect();
            for name in names {
                if let Some(subcommand) = command.find_subcommand_mut(&name) {
                    render(subcommand);
                }
            }
        }
        let mut command = localize(Cli::command(), Language::French);
        command.clone().debug_assert();
        render(&mut command);
    }

    #[test]
    fn an_entry_escapes_what_fluent_reads() {
        assert_eq!(entry("a", "x {y}\n\n.z"), "a =\n    x {\"{\"}y{\"}\"}\n\n    {\".\"}z");
    }

    /// Prints the English catalog from the doc comments, for a new `locales/en/help.ftl`.
    #[test]
    #[ignore = "a tool, not a check: run it with --nocapture"]
    fn print_the_english_help_catalog() {
        for (id, text) in texts(&Cli::command()) {
            println!("{}", entry(&id, &text));
        }
    }
}
