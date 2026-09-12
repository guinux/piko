//! The clause form a planning problem is compiled into, before solving.
//!
//! Every rule ALPM dependency resolution enforces becomes a disjunction over "package `x` is
//! selected":
//!
//! | rule | clause |
//! |---|---|
//! | `p` requires `dep` | `¬p ∨ q₁ ∨ … ∨ qₙ`, over every satisfier in preference order |
//! | `p` conflicts with `q` | `¬p ∨ ¬q` |
//! | at most one candidate per package name | `¬a ∨ ¬b` for each pair in the group |
//! | `p` is a target / is installed and stays | `p` |
//! | `p` is excluded | `¬p` |
//!
//! Two properties are deliberate. First, **literal order inside a requirement is preference
//! order**. [`crate::solve::Universe::satisfiers`] already returns candidates in the order
//! `resolvedep` would rank them. The solver's decision heuristic takes the first unassigned
//! literal, so a run that never backtracks selects exactly what libalpm selects.
//! Second, every clause carries a [`ClauseKind`] that records why it exists. This is what
//! turns an unsatisfiable core back into a sentence a user can act on.
//!
//! `%OPTDEPENDS%` are never encoded. libalpm reports them and never resolves them, and a
//! clause would make them mandatory.

use crate::solve::SolvableId;

/// A candidate together with a sign: either "`x` is selected" or "`x` is not selected".
///
/// Packed as `id << 1 | negated`. The shift cannot overflow:
/// [`crate::Limits::solve_max_solvables`] bounds the candidate count far below `u32::MAX`,
/// and [`crate::solve::Universe::build`] enforces it before minting any id. Bit operations
/// fall outside what `clippy::arithmetic_side_effects` checks. This was verified against the
/// lint before choosing this representation, the same way `SigLevel`'s bitmask was.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Lit(u32);

impl Lit {
    /// "`id` is selected".
    #[must_use]
    pub const fn positive(id: SolvableId) -> Self {
        Self(id.get() << 1)
    }

    /// "`id` is not selected".
    #[must_use]
    pub const fn negative(id: SolvableId) -> Self {
        Self((id.get() << 1) | 1)
    }

    /// The candidate this literal is about.
    #[must_use]
    pub const fn solvable(self) -> SolvableId {
        SolvableId::from_raw(self.0 >> 1)
    }

    /// Whether this literal is the negated form.
    #[must_use]
    pub const fn is_negative(self) -> bool {
        (self.0 & 1) == 1
    }

    /// The same candidate with the opposite sign.
    #[must_use]
    pub const fn negate(self) -> Self {
        Self(self.0 ^ 1)
    }

    /// The value this literal needs the candidate to take in order to be true.
    #[must_use]
    pub const fn expects(self) -> bool {
        !self.is_negative()
    }

    /// A dense index over both signs, for watch lists.
    #[must_use]
    pub const fn watch_index(self) -> usize {
        self.0 as usize
    }
}

/// Why a clause exists, kept so an unsatisfiable core can be explained rather than merely
/// reported.
///
/// libalpm's equivalent is a heterogeneous `void **data` out-param, discriminated by the
/// error code: `alpm_depmissing_t`, `alpm_conflict_t`, or a bare string, depending on which
/// failure occurred. The clause records its own provenance, so the explanation comes from
/// the same structure the solver used, not from something reconstructed afterward.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClauseKind {
    /// `dependent` lists a `%DEPENDS%` entry, and the clause's literals are its satisfiers.
    Requires {
        /// The package whose `%DEPENDS%` produced this clause.
        dependent: SolvableId,
        /// Which of `dependent`'s `%DEPENDS%` entries this was, so the explanation can quote
        /// the exact relation rather than guess at it.
        dependency: usize,
    },
    /// `dependent` lists a `%DEPENDS%` entry, and the caller answered
    /// `ALPM_QUESTION_SELECT_PROVIDER` for it, so the clause's one literal is the provider
    /// they named.
    ///
    /// Distinct from [`Self::Requires`] so an explanation can say *why* the other providers
    /// are gone. Without it, a transaction made impossible by the answer reports that nothing
    /// satisfies the dependency, which sends the reader looking for a package that is in fact
    /// right there.
    Chosen {
        /// The package whose `%DEPENDS%` produced this clause.
        dependent: SolvableId,
        /// Which of `dependent`'s `%DEPENDS%` entries this was.
        dependency: usize,
        /// The provider the caller named.
        chosen: SolvableId,
    },
    /// Two candidates cannot both be selected because one declares `%CONFLICTS%` on the
    /// other.
    Conflicts {
        /// The package that named the other in its `%CONFLICTS%`.
        declarer: SolvableId,
        /// The package named, which may match through `%PROVIDES%` rather than by name.
        other: SolvableId,
    },
    /// Two candidates cannot both be selected because they are two versions of one package.
    SameName {
        /// The earlier candidate in priority order.
        first: SolvableId,
        /// The later candidate in priority order.
        second: SolvableId,
    },
    /// The candidate replaces an installed package, which must therefore go.
    Replaces {
        /// The incoming package carrying the `%REPLACES%` entry.
        replacement: SolvableId,
        /// The installed package it displaces.
        replaced: SolvableId,
    },
    /// The user asked for this candidate.
    Target {
        /// The requested package.
        target: SolvableId,
    },
    /// The candidate is installed and nothing in this transaction removes it.
    Installed {
        /// The installed package.
        installed: SolvableId,
    },
    /// The candidate is unavailable — filtered out by policy rather than by a dependency.
    Excluded {
        /// The package that cannot be selected.
        excluded: SolvableId,
    },
    /// Derived by the solver during conflict analysis rather than stated by the problem.
    Learned,
}

/// One clause's literals plus its provenance.
#[derive(Clone, Copy, Debug)]
pub struct Clause<'a> {
    literals: &'a [Lit],
    kind: ClauseKind,
}

impl<'a> Clause<'a> {
    /// The disjunction.
    #[must_use]
    pub const fn literals(&self) -> &'a [Lit] {
        self.literals
    }

    /// Why this clause exists.
    #[must_use]
    pub const fn kind(&self) -> ClauseKind {
        self.kind
    }
}

/// Identifies a clause within a [`Problem`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClauseId(u32);

impl ClauseId {
    /// This id as an index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    /// Builds an id from a raw index.
    ///
    /// Crate-visible: the solver numbers its learned clauses immediately after the problem's
    /// own, so it needs to mint ids the problem never issued.
    #[must_use]
    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
}

/// A compiled planning problem: a flat arena of clauses over a fixed candidate count.
///
/// Literals live in one `Vec` with a `starts` offset array, not in a `Vec<Vec<Lit>>` — the
/// same shape `repo::files_arena` uses. This gives one allocation instead of one per clause.
/// Slicing through `get(..).unwrap_or(&[])` keeps it inside `clippy::indexing_slicing`.
#[derive(Clone, Debug)]
pub struct Problem {
    literals: Vec<Lit>,
    starts: Vec<u32>,
    kinds: Vec<ClauseKind>,
    solvables: usize,
}

impl Problem {
    /// An empty problem over `solvables` candidates.
    #[must_use]
    pub fn new(solvables: usize) -> Self {
        Self { literals: Vec::new(), starts: vec![0], kinds: Vec::new(), solvables }
    }

    /// The number of candidates this problem is defined over.
    #[must_use]
    pub const fn solvables(&self) -> usize {
        self.solvables
    }

    /// The number of clauses.
    //
    // Not `const`: `Vec::len` is only usable in a `const fn` from Rust 1.87. This workspace
    // declares an MSRV of 1.85 (the `alpm-*` crates').
    #[must_use]
    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    /// Whether there are no clauses.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    /// Appends a clause, returning its id.
    ///
    /// An empty clause is admissible and means "unsatisfiable". The encoder produces one for
    /// a dependency with no satisfier at all. This way the failure is reported through the
    /// same explanation path as any other conflict, not as a special case.
    pub fn add(&mut self, literals: impl IntoIterator<Item = Lit>, kind: ClauseKind) -> ClauseId {
        self.literals.extend(literals);
        let end = u32::try_from(self.literals.len()).unwrap_or(u32::MAX);
        self.starts.push(end);
        self.kinds.push(kind);
        ClauseId(u32::try_from(self.kinds.len().saturating_sub(1)).unwrap_or(u32::MAX))
    }

    /// A clause by id.
    #[must_use]
    pub fn get(&self, id: ClauseId) -> Option<Clause<'_>> {
        let kind = *self.kinds.get(id.index())?;
        Some(Clause { literals: self.literals_of(id), kind })
    }

    /// A clause's literals, or an empty slice for an id this problem never issued.
    #[must_use]
    pub fn literals_of(&self, id: ClauseId) -> &[Lit] {
        let start = self.starts.get(id.index()).copied().unwrap_or(0);
        let end = self.starts.get(id.index().saturating_add(1)).copied().unwrap_or(start);
        let range = (start as usize)..(end as usize);
        self.literals.get(range).unwrap_or(&[])
    }

    /// Every clause, in the order it was added.
    pub fn iter(&self) -> impl Iterator<Item = (ClauseId, Clause<'_>)> {
        (0..self.kinds.len()).filter_map(move |index| {
            let id = ClauseId(u32::try_from(index).ok()?);
            Some((id, self.get(id)?))
        })
    }

    /// Adds `¬a ∨ ¬b` for every pair in `group` — "at most one of these".
    ///
    /// Quadratic in the group size. This is fine: a group is the candidates that share one
    /// package name — three or four in practice, bounded by the number of configured
    /// repositories plus one.
    pub fn add_at_most_one(&mut self, group: &[SolvableId]) {
        for (offset, first) in group.iter().enumerate() {
            for second in group.iter().skip(offset.saturating_add(1)) {
                self.add(
                    [Lit::negative(*first), Lit::negative(*second)],
                    ClauseKind::SameName { first: *first, second: *second },
                );
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn id(raw: u32) -> SolvableId {
        SolvableId::from_raw(raw)
    }

    #[test]
    fn a_literal_round_trips_through_its_packed_form() {
        for raw in [0, 1, 2, 12_345, u32::MAX >> 1] {
            let positive = Lit::positive(id(raw));
            let negative = Lit::negative(id(raw));

            assert_eq!(positive.solvable(), id(raw));
            assert_eq!(negative.solvable(), id(raw));
            assert!(!positive.is_negative());
            assert!(negative.is_negative());
            assert_eq!(positive.negate(), negative);
            assert_eq!(negative.negate(), positive);
            assert!(positive.expects());
            assert!(!negative.expects());
        }
    }

    #[test]
    fn the_two_signs_of_a_candidate_get_distinct_watch_indexes() {
        let positive = Lit::positive(id(7));
        let negative = Lit::negative(id(7));
        assert_ne!(positive.watch_index(), negative.watch_index());
        assert_eq!(positive.watch_index(), 14);
        assert_eq!(negative.watch_index(), 15);
    }

    #[test]
    fn clauses_are_stored_and_retrieved_in_order() {
        let mut problem = Problem::new(4);
        let first = problem.add(
            [Lit::negative(id(0)), Lit::positive(id(1))],
            ClauseKind::Requires { dependent: id(0), dependency: 0 },
        );
        let second = problem.add([Lit::positive(id(2))], ClauseKind::Target { target: id(2) });

        assert_eq!(problem.len(), 2);
        assert_eq!(problem.literals_of(first), [Lit::negative(id(0)), Lit::positive(id(1))]);
        assert_eq!(problem.literals_of(second), [Lit::positive(id(2))]);
        assert_eq!(problem.get(second).unwrap().kind(), ClauseKind::Target { target: id(2) });
    }

    /// A dependency with no satisfier produces one. It must not be confused with a clause
    /// that merely has no literals recorded yet.
    #[test]
    fn an_empty_clause_is_representable() {
        let mut problem = Problem::new(1);
        let empty = problem.add([], ClauseKind::Requires { dependent: id(0), dependency: 0 });
        assert!(problem.literals_of(empty).is_empty());
        assert_eq!(problem.len(), 1);
    }

    #[test]
    fn an_unissued_clause_id_yields_nothing_rather_than_panicking() {
        let problem = Problem::new(1);
        assert!(problem.get(ClauseId(9)).is_none());
        assert!(problem.literals_of(ClauseId(9)).is_empty());
    }

    #[test]
    fn at_most_one_emits_every_pair_once() {
        let mut problem = Problem::new(3);
        problem.add_at_most_one(&[id(0), id(1), id(2)]);

        assert_eq!(problem.len(), 3, "three candidates make three pairs");
        for (_, clause) in problem.iter() {
            assert_eq!(clause.literals().len(), 2);
            assert!(clause.literals().iter().copied().all(Lit::is_negative));
        }
    }

    #[test]
    fn at_most_one_over_a_single_candidate_constrains_nothing() {
        let mut problem = Problem::new(1);
        problem.add_at_most_one(&[id(0)]);
        assert!(problem.is_empty());
    }
}
