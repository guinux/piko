//! Turning an unsatisfiable core into something a person can act on.
//!
//! libalpm reports a failed transaction through a `void **data` out-param whose real type
//! depends on the error code: `alpm_depmissing_t*` for `ALPM_ERR_UNSATISFIED_DEPS`,
//! `alpm_conflict_t*` for `ALPM_ERR_CONFLICTING_DEPS`, a bare `char*` elsewhere. It is a flat
//! list of *symptoms* — which dependency was missing, which two packages clashed. It cannot say
//! why the situation arose, because by the time it is built, the search that produced it is
//! gone.
//!
//! A [`Derivation`] keeps the search's own reasoning. Each [`Fact`] is one clause the solver
//! actually used, resolved from candidate ids back to package names and the exact relation
//! involved, so the chain reads as an argument:
//!
//! ```text
//! cannot remove bubblewrap:
//!   bubblewrap 0.11.2-1 (installed) cannot be selected
//!   glycin 2.1.5-2 (installed) is installed and must remain
//!   glycin 2.1.5-2 (installed) requires bubblewrap
//! ```
//!
//! Rendering lives here rather than in the CLI because it needs the [`Universe`] the ids came
//! from. Every future frontend — a commit engine's error path, a TUI — needs the same thing.
//! The CLI adds only the indentation.

use std::fmt;

use crate::solve::clause::ClauseKind;
use crate::solve::{Problem, SolvableId, Universe, Unsatisfiable};

/// One clause from the core, in terms of packages rather than candidate ids.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Fact {
    /// A package was requested.
    Requested {
        /// How the package prints, including its origin.
        package: String,
    },
    /// A package cannot be selected — the user asked for it to go.
    Excluded {
        /// How the package prints.
        package: String,
    },
    /// A package is installed and this transaction does not remove it.
    MustRemain {
        /// How the package prints.
        package: String,
    },
    /// A package needs something.
    Requires {
        /// The package with the dependency.
        package: String,
        /// The `%DEPENDS%` entry, verbatim, so the version constraint is visible.
        relation: String,
    },
    /// Two packages cannot both be present.
    Conflicts {
        /// The package whose `%CONFLICTS%` names the other.
        package: String,
        /// The package named — possibly matched through `%PROVIDES%`.
        other: String,
    },
    /// One package replaces another.
    Replaces {
        /// The incoming package.
        package: String,
        /// The installed package it displaces.
        replaced: String,
    },
    /// Two candidates are versions of the same package, so at most one can be chosen.
    SameName {
        /// The first candidate.
        first: String,
        /// The second candidate.
        second: String,
    },
}

impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested { package } => write!(f, "{package} was requested"),
            Self::Excluded { package } => write!(f, "{package} cannot be selected"),
            Self::MustRemain { package } => {
                write!(f, "{package} is installed and must remain")
            }
            Self::Requires { package, relation } => write!(f, "{package} requires {relation}"),
            Self::Conflicts { package, other } => {
                write!(f, "{package} conflicts with {other}")
            }
            Self::Replaces { package, replaced } => write!(f, "{package} replaces {replaced}"),
            Self::SameName { first, second } => {
                write!(f, "{first} and {second} are versions of the same package")
            }
        }
    }
}

/// Why a request could not be satisfied.
#[derive(Clone, Debug)]
pub struct Derivation {
    facts: Vec<Fact>,
}

impl Derivation {
    /// The facts that together cannot all hold.
    #[must_use]
    pub fn facts(&self) -> &[Fact] {
        &self.facts
    }

    /// Whether nothing could be explained.
    ///
    /// Possible in principle: a core made entirely of learned clauses has no package-level
    /// facts to report. Worth checking rather than printing an empty explanation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    /// Renders `unsat` against the universe its ids came from.
    #[must_use]
    pub fn build(universe: &Universe<'_>, problem: &Problem, unsat: &Unsatisfiable) -> Self {
        let facts = unsat
            .core()
            .iter()
            .filter_map(|id| problem.get(*id))
            .filter_map(|clause| fact(universe, clause.kind()))
            .collect();
        Self { facts }
    }
}

impl fmt::Display for Derivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, item) in self.facts.iter().enumerate() {
            if index > 0 {
                writeln!(f)?;
            }
            write!(f, "{item}")?;
        }
        Ok(())
    }
}

/// Resolves one clause into a [`Fact`], or `None` for a clause with nothing to say.
fn fact(universe: &Universe<'_>, kind: ClauseKind) -> Option<Fact> {
    match kind {
        ClauseKind::Requires { dependent, dependency } => Some(Fact::Requires {
            package: describe(universe, dependent),
            relation: universe
                .get(dependent)
                .and_then(|solvable| solvable.depends().ok())
                .and_then(|depends| depends.get(dependency).map(ToString::to_string))
                .unwrap_or_else(|| "?".to_owned()),
        }),
        ClauseKind::Conflicts { declarer, other } => Some(Fact::Conflicts {
            package: describe(universe, declarer),
            other: describe(universe, other),
        }),
        ClauseKind::SameName { first, second } => Some(Fact::SameName {
            first: describe(universe, first),
            second: describe(universe, second),
        }),
        ClauseKind::Replaces { replacement, replaced } => Some(Fact::Replaces {
            package: describe(universe, replacement),
            replaced: describe(universe, replaced),
        }),
        ClauseKind::Target { target } => {
            Some(Fact::Requested { package: describe(universe, target) })
        }
        ClauseKind::Installed { installed } => {
            Some(Fact::MustRemain { package: describe(universe, installed) })
        }
        ClauseKind::Excluded { excluded } => {
            Some(Fact::Excluded { package: describe(universe, excluded) })
        }
        // A learned clause is a fact the solver derived, not one a user could act on. The core
        // already replaces each one with the problem clauses that produced it.
        ClauseKind::Learned => None,
    }
}

/// `name version (origin)`, the form every fact refers to a package by.
///
/// The origin matters: "glibc (installed)" and "glibc (core)" are different candidates. An
/// explanation that could not tell them apart would be unreadable exactly when it matters.
fn describe(universe: &Universe<'_>, id: SolvableId) -> String {
    universe.get(id).map_or_else(
        || "<unknown>".to_owned(),
        |solvable| {
            let origin = match solvable.origin() {
                crate::solve::Origin::Installed => "installed".to_owned(),
                crate::solve::Origin::Repository(index) => universe
                    .repository_name(index)
                    .map_or_else(|| "?".to_owned(), ToString::to_string),
                crate::solve::Origin::File(_) => "file".to_owned(),
            };
            format!("{} {} ({origin})", solvable.name(), solvable.version())
        },
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::Limits;
    use crate::config::DbUsage;
    use crate::fixture::{PackageSpec, Scenario};
    use crate::solve::{Outcome, Request, Solver, UniverseOptions, encode, resolve_target};

    /// A dependency nothing provides must name the package and the exact relation.
    #[test]
    fn a_missing_dependency_names_the_relation_that_is_missing() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("app", "1.0.0-1").depends(["absent>=2.0"])])
            .build();

        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let request = Request::new().target(id);
        let encoded = encode(&universe, &request, &limits, &Default::default()).unwrap();

        let Ok(Outcome::Unsatisfiable(unsat)) = Solver::new(encoded.problem(), limits).solve()
        else {
            panic!("expected unsatisfiable");
        };

        let derivation = Derivation::build(&universe, encoded.problem(), &unsat);
        let rendered = derivation.to_string();
        assert!(
            derivation.facts().iter().any(|fact| matches!(
                fact,
                Fact::Requires { relation, .. } if relation == "absent>=2.0"
            )),
            "the exact relation must appear: {rendered}"
        );
        assert!(rendered.contains("app 1.0.0-1 (core)"), "{rendered}");
    }

    /// A conflict explanation must name both sides and say which is installed.
    #[test]
    fn a_conflict_names_both_packages_and_their_origins() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old-thing", "1.0.0-1"))
            .installed(PackageSpec::new("needs-old", "1.0.0-1").depends(["old-thing"]))
            .repo("core", [PackageSpec::new("new-thing", "1.0.0-1").conflicts(["old-thing"])])
            .build();

        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"new-thing".parse().unwrap()).unwrap();
        // `allow_removals(false)` keeps the conflict fatal, so there is a core to explain.
        let request = Request::new().target(id).allow_removals(false);
        let encoded = encode(&universe, &request, &limits, &Default::default()).unwrap();

        let Ok(Outcome::Unsatisfiable(unsat)) = Solver::new(encoded.problem(), limits).solve()
        else {
            panic!("expected unsatisfiable");
        };

        let rendered = Derivation::build(&universe, encoded.problem(), &unsat).to_string();
        assert!(rendered.contains("old-thing 1.0.0-1 (installed)"), "{rendered}");
        assert!(rendered.contains("new-thing 1.0.0-1 (core)"), "{rendered}");
        assert!(rendered.contains("conflicts with"), "{rendered}");
    }

    /// Learned clauses are the solver's own bookkeeping and must never surface.
    #[test]
    fn a_derivation_reports_no_derived_clauses() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("app", "1.0.0-1").depends(["absent"])])
            .build();

        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let request = Request::new().target(id);
        let encoded = encode(&universe, &request, &limits, &Default::default()).unwrap();

        let Ok(Outcome::Unsatisfiable(unsat)) = Solver::new(encoded.problem(), limits).solve()
        else {
            panic!("expected unsatisfiable");
        };

        let derivation = Derivation::build(&universe, encoded.problem(), &unsat);
        assert!(!derivation.is_empty(), "there should be something to say");
        assert!(!derivation.to_string().contains("(derived)"), "{derivation}");
    }
}
