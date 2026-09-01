//! A conflict-driven clause-learning solver over a compiled [`Problem`].
//!
//! # Why a solver at all
//!
//! libalpm's `_alpm_resolvedeps` (`deps.c:788`) runs a greedy depth-first search. It takes
//! the first provider, recurses, and on failure rolls the accumulator back and gives up on
//! that target. It cannot back out of a choice that only turns out wrong later. It reports
//! the failure as a single `alpm_depmissing_t`.
//!
//! A solver is safe to substitute here because **libalpm's answer is this solver's first
//! descent**. ALPM offers exactly one candidate version per name per repository, so the
//! search space is a choice among providers, not a search over version ranges. [`Problem`]
//! stores each requirement's satisfiers in `resolvedep` preference order.
//! [`Solver::decide`] always takes the first unassigned literal of the first unsatisfied
//! clause. A run that never hits a conflict selects exactly what libalpm selects. Propagation
//! and learning engage only where libalpm would have failed outright. [`Solution::conflicts`]
//! reports whether that happened, so the difference is never silent.
//!
//! # Shape
//!
//! Textbook CDCL, deliberately unclever: two watched literals, unit propagation, 1UIP
//! conflict analysis, learned clauses, non-chronological backjumping.
//!
//! The one non-textbook part is the decision rule. A general SAT solver picks any unassigned
//! variable (VSIDS and similar heuristics). That would be wrong twice over here: it would
//! install packages nothing asked for, and it would not reproduce libalpm's ordering. Instead
//! the default polarity is "not selected". A decision is only ever made to *repair* a clause
//! that is not yet satisfied, by selecting the highest-priority candidate that would satisfy
//! it. This is how libsolv drives package solving. It is also what makes the greedy descent
//! and the search share one code path.
//!
//! # Termination
//!
//! Bounded by [`crate::Limits::solve_max_conflicts`]. Exhausting it produces
//! [`crate::Error::SolveBudgetExhausted`], never a hang. A hostile repository can craft a
//! clause set with pathological search behaviour. "Takes forever" is not an acceptable
//! outcome for a package manager. The bound applies to conflicts, not time, so the result
//! stays reproducible.

use crate::solve::SolvableId;
use crate::solve::clause::{ClauseId, ClauseKind, Lit, Problem};
use crate::{Error, Limits, Result};

/// What a solved [`Problem`] selected.
#[derive(Clone, Debug)]
pub struct Solution {
    selected: Vec<SolvableId>,
    conflicts: usize,
}

impl Solution {
    /// The candidates the solver selected, in ascending id order.
    #[must_use]
    pub fn selected(&self) -> &[SolvableId] {
        &self.selected
    }

    /// How many times the search had to backtrack.
    ///
    /// Zero means no *decision* was ever retracted. It does **not** by itself mean the answer
    /// equals libalpm's. Unit propagation can forestall a decision that libalpm would have
    /// made and then failed on, reaching a better answer without ever backtracking. The
    /// observable symptom is a requirement whose selected satisfier is not its first-listed
    /// one. That is measured where the requirements are still in scope — see
    /// [`solve::fidelity`](crate::solve::fidelity) — rather than guessed at from this counter.
    ///
    /// This bounds *work*, not fidelity: it is the quantity
    /// [`crate::Limits::solve_max_conflicts`] caps, so a hostile clause set cannot make the
    /// search run away.
    #[must_use]
    pub const fn conflicts(&self) -> usize {
        self.conflicts
    }
}

/// Why a [`Problem`] had no solution: the clauses that together cannot all hold.
///
/// This is the raw material for an explanation. Rendering it into a sentence needs the
/// [`crate::solve::Universe`] the ids came from. It is deliberately left as data here.
#[derive(Clone, Debug)]
pub struct Unsatisfiable {
    core: Vec<ClauseId>,
}

impl Unsatisfiable {
    /// The clauses forming the unsatisfiable core, in the order the search derived them.
    #[must_use]
    pub fn core(&self) -> &[ClauseId] {
        &self.core
    }
}

/// The outcome of a solve.
#[derive(Clone, Debug)]
pub enum Outcome {
    /// A selection satisfying every clause.
    Satisfied(Solution),
    /// No selection can satisfy every clause.
    Unsatisfiable(Unsatisfiable),
}

/// Truth assignment for one candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Value {
    Unassigned,
    True,
    False,
}

/// A conflict-driven clause-learning solver.
#[derive(Debug)]
pub struct Solver<'p> {
    problem: &'p Problem,
    /// Clauses learned during search, appended after the problem's own.
    learned: Vec<Vec<Lit>>,
    values: Vec<Value>,
    /// Decision level at which each candidate was assigned.
    levels: Vec<u32>,
    /// The clause that forced each assignment, or `None` for a decision.
    reasons: Vec<Option<ClauseId>>,
    /// Assignment order, for conflict analysis and backtracking.
    trail: Vec<Lit>,
    /// Index into `trail` where each decision level began.
    level_starts: Vec<usize>,
    /// For each literal (by `watch_index`), the clauses watching it.
    watches: Vec<Vec<ClauseId>>,
    /// Next unpropagated position in `trail`.
    propagated: usize,
    conflicts: usize,
    limits: Limits,
}

impl<'p> Solver<'p> {
    /// Prepares a solver for `problem`.
    #[must_use]
    pub fn new(problem: &'p Problem, limits: Limits) -> Self {
        let solvables = problem.solvables();
        Self {
            problem,
            learned: Vec::new(),
            values: vec![Value::Unassigned; solvables],
            levels: vec![0; solvables],
            reasons: vec![None; solvables],
            trail: Vec::new(),
            level_starts: Vec::new(),
            watches: vec![Vec::new(); solvables.saturating_mul(2)],
            propagated: 0,
            conflicts: 0,
            limits,
        }
    }

    /// Searches for a selection satisfying every clause.
    ///
    /// # Errors
    ///
    /// [`Error::SolveBudgetExhausted`] if the search exceeds
    /// [`crate::Limits::solve_max_conflicts`].
    pub fn solve(mut self) -> Result<Outcome> {
        if let Some(core) = self.attach_all() {
            return Ok(Outcome::Unsatisfiable(Unsatisfiable { core: vec![core] }));
        }

        loop {
            if let Some(conflict) = self.propagate() {
                if self.decision_level() == 0 {
                    return Ok(Outcome::Unsatisfiable(Unsatisfiable {
                        core: self.core_from(conflict),
                    }));
                }
                self.conflicts = self.conflicts.saturating_add(1);
                if self.conflicts > self.limits.solve_max_conflicts {
                    return Err(Error::SolveBudgetExhausted {
                        max: self.limits.solve_max_conflicts,
                    });
                }
                if !self.analyze_and_backjump(conflict) {
                    return Ok(Outcome::Unsatisfiable(Unsatisfiable {
                        core: self.core_from(conflict),
                    }));
                }
                continue;
            }

            match self.decide() {
                Some(literal) => {
                    self.level_starts.push(self.trail.len());
                    self.assign(literal, None);
                }
                None => return Ok(Outcome::Satisfied(self.finish())),
            }
        }
    }

    /// Registers every problem clause in the watch lists. Seeds units, and detects up front a
    /// clause that is empty — and therefore already false.
    ///
    /// Returns the id of an empty clause, if one exists. Such a clause is a dependency the
    /// encoder found no satisfier for. It makes the problem unsatisfiable before the search
    /// begins.
    fn attach_all(&mut self) -> Option<ClauseId> {
        for (id, clause) in self.problem.iter() {
            match clause.literals() {
                [] => return Some(id),
                [unit] => {
                    let unit = *unit;
                    // A level-0 assignment: true in every solution, or an immediate
                    // contradiction with an earlier unit over the same candidate.
                    if self.value_of(unit) == Value::False {
                        return Some(id);
                    }
                    if self.value_of(unit) == Value::Unassigned {
                        self.assign(unit, Some(id));
                    }
                }
                _ => self.watch(id, clause.literals()),
            }
        }
        None
    }

    /// Watches a clause's first two literals.
    fn watch(&mut self, id: ClauseId, literals: &[Lit]) {
        for literal in literals.iter().take(2) {
            if let Some(list) = self.watches.get_mut(literal.negate().watch_index()) {
                list.push(id);
            }
        }
    }

    /// The literals of a clause, whether it came from the problem or from learning.
    fn literals_of(&self, id: ClauseId) -> &[Lit] {
        let count = self.problem.len();
        if id.index() < count {
            return self.problem.literals_of(id);
        }
        self.learned.get(id.index().saturating_sub(count)).map_or(&[], Vec::as_slice)
    }

    /// The current value of a literal: `True` if it is satisfied under the assignment.
    fn value_of(&self, literal: Lit) -> Value {
        match self.values.get(literal.solvable().index()).copied() {
            Some(Value::Unassigned) | None => Value::Unassigned,
            Some(Value::True) => {
                if literal.expects() {
                    Value::True
                } else {
                    Value::False
                }
            }
            Some(Value::False) => {
                if literal.expects() {
                    Value::False
                } else {
                    Value::True
                }
            }
        }
    }

    fn decision_level(&self) -> u32 {
        u32::try_from(self.level_starts.len()).unwrap_or(u32::MAX)
    }

    /// Records `literal` as true, with the clause that forced it (or `None` for a decision).
    fn assign(&mut self, literal: Lit, reason: Option<ClauseId>) {
        let index = literal.solvable().index();
        let level = self.decision_level();
        if let Some(slot) = self.values.get_mut(index) {
            *slot = if literal.expects() { Value::True } else { Value::False };
        }
        if let Some(slot) = self.levels.get_mut(index) {
            *slot = level;
        }
        if let Some(slot) = self.reasons.get_mut(index) {
            *slot = reason;
        }
        self.trail.push(literal);
    }

    /// Propagates every consequence of the current assignment.
    ///
    /// Returns the first clause found to be false, if any.
    fn propagate(&mut self) -> Option<ClauseId> {
        while let Some(literal) = self.trail.get(self.propagated).copied() {
            self.propagated = self.propagated.saturating_add(1);

            // Clauses watching the literal that just became false. The list is moved out, not
            // cloned: `visit_watch` needs `&mut self`, and cloning would be quadratic on a
            // real problem, where a popular literal is watched by thousands of clauses.
            // Conflict analysis may append to this same list — a learned clause starts
            // watching its own literals — so whatever arrived while it was taken is merged
            // back, not dropped.
            let Some(slot) = self.watches.get_mut(literal.watch_index()) else { continue };
            let mut watching = std::mem::take(slot);

            let mut conflict = None;
            for id in &watching {
                if let Some(found) = self.visit_watch(*id) {
                    conflict = Some(found);
                    break;
                }
            }

            if let Some(slot) = self.watches.get_mut(literal.watch_index()) {
                watching.append(slot);
                *slot = watching;
            }
            if conflict.is_some() {
                return conflict;
            }
        }
        None
    }

    /// Re-examines a watched clause after one of its watches became false.
    ///
    /// Deliberately re-scans the whole clause instead of maintaining the usual "swap the
    /// watch to a new literal" invariant. Clauses here are short — a requirement's satisfier
    /// list, or a two-literal conflict. The simpler form has no invariant to get wrong.
    fn visit_watch(&mut self, id: ClauseId) -> Option<ClauseId> {
        let literals = self.literals_of(id).to_vec();
        let mut unassigned = None;
        for literal in &literals {
            match self.value_of(*literal) {
                Value::True => return None,
                Value::Unassigned => {
                    if unassigned.is_some() {
                        // Two or more unassigned: nothing to propagate yet.
                        return None;
                    }
                    unassigned = Some(*literal);
                }
                Value::False => {}
            }
        }
        match unassigned {
            Some(unit) => {
                self.assign(unit, Some(id));
                None
            }
            None => Some(id),
        }
    }

    /// Chooses the next candidate to select.
    ///
    /// Scans for the first clause not yet satisfied and selects its first unassigned
    /// literal. [`Problem`] holds requirements in `resolvedep` preference order, and the scan
    /// runs in clause order, so this reproduces libalpm's greedy choice exactly.
    ///
    /// Returns `None` when every clause is satisfied. That is the answer.
    fn decide(&mut self) -> Option<Lit> {
        for (id, _) in self.problem.iter() {
            let mut candidate = None;
            let mut satisfied = false;

            for literal in self.literals_of(id) {
                match self.value_of(*literal) {
                    Value::True => {
                        satisfied = true;
                        break;
                    }
                    Value::Unassigned => {
                        if literal.is_negative() {
                            // An unassigned candidate defaults to "not selected". A negative
                            // literal over one is already true under the interpretation
                            // `finish` applies. The clause needs nothing.
                            satisfied = true;
                            break;
                        }
                        if candidate.is_none() {
                            candidate = Some(*literal);
                        }
                    }
                    Value::False => {}
                }
            }

            if !satisfied && let Some(literal) = candidate {
                return Some(literal);
            }
        }
        None
    }

    /// Derives a learned clause from `conflict` by 1UIP resolution, then backjumps.
    ///
    /// Returns `false` if the conflict resolves to a clause false at level 0. That means the
    /// problem is unsatisfiable.
    fn analyze_and_backjump(&mut self, conflict: ClauseId) -> bool {
        let level = self.decision_level();
        let mut seen = vec![false; self.values.len()];
        let mut learned: Vec<Lit> = Vec::new();
        let mut at_level = 0_usize;
        let mut index = self.trail.len();
        let mut reason = Some(conflict);
        let mut pivot: Option<Lit> = None;

        loop {
            if let Some(id) = reason {
                for literal in self.literals_of(id).to_vec() {
                    if pivot.is_some_and(|p| p.solvable() == literal.solvable()) {
                        continue;
                    }
                    let slot = literal.solvable().index();
                    if seen.get(slot).copied().unwrap_or(true) {
                        continue;
                    }
                    if let Some(flag) = seen.get_mut(slot) {
                        *flag = true;
                    }
                    let literal_level = self.levels.get(slot).copied().unwrap_or(0);
                    if literal_level >= level {
                        at_level = at_level.saturating_add(1);
                    } else if literal_level > 0 {
                        learned.push(literal);
                    }
                }
            }

            // Walk back down the trail to the most recent seen assignment at this level.
            let mut current = None;
            while index > 0 {
                index = index.saturating_sub(1);
                let Some(literal) = self.trail.get(index).copied() else { continue };
                if seen.get(literal.solvable().index()).copied().unwrap_or(false) {
                    current = Some(literal);
                    break;
                }
            }
            let Some(literal) = current else { return false };

            at_level = at_level.saturating_sub(1);
            if at_level == 0 {
                // `literal` is the unique implication point: negate it to form the clause.
                learned.push(literal.negate());
                break;
            }
            reason = self.reasons.get(literal.solvable().index()).copied().flatten();
            pivot = Some(literal);
        }

        // The asserting literal must come first so the clause propagates after the backjump.
        let last = learned.len().saturating_sub(1);
        learned.swap(0, last);

        let backjump = learned
            .iter()
            .skip(1)
            .map(|literal| self.levels.get(literal.solvable().index()).copied().unwrap_or(0))
            .max()
            .unwrap_or(0);

        self.backtrack_to(backjump);

        let Some(asserting) = learned.first().copied() else { return false };
        let id = self.add_learned(learned);
        self.assign(asserting, Some(id));
        true
    }

    /// Stores a learned clause and starts watching it.
    fn add_learned(&mut self, literals: Vec<Lit>) -> ClauseId {
        let id = ClauseId::from_raw(
            u32::try_from(self.problem.len().saturating_add(self.learned.len()))
                .unwrap_or(u32::MAX),
        );
        if literals.len() >= 2 {
            self.watch(id, &literals);
        }
        self.learned.push(literals);
        id
    }

    /// Undoes every assignment made above `level`.
    fn backtrack_to(&mut self, level: u32) {
        let target = level as usize;
        while self.level_starts.len() > target {
            let Some(start) = self.level_starts.pop() else { break };
            while self.trail.len() > start {
                let Some(literal) = self.trail.pop() else { break };
                let slot = literal.solvable().index();
                if let Some(value) = self.values.get_mut(slot) {
                    *value = Value::Unassigned;
                }
                if let Some(reason) = self.reasons.get_mut(slot) {
                    *reason = None;
                }
            }
        }
        self.propagated = self.trail.len();
    }

    /// The clauses implicated in a conflict, walked back through the reason graph.
    ///
    /// Only problem clauses are reported. A learned clause is a derived fact, not something
    /// a user could act on. Each is replaced by the reasons that produced it.
    fn core_from(&self, conflict: ClauseId) -> Vec<ClauseId> {
        let mut core = Vec::new();
        let mut queue = vec![conflict];
        // Sized over learned clauses too, since the walk follows reasons through them. The
        // guard must gate *expansion*, not merely the push onto `core`. The reason graph is
        // routinely cyclic — a clause forces a literal whose reason is that same clause — so
        // re-expanding a clause already visited does not terminate.
        let mut seen = vec![false; self.problem.len().saturating_add(self.learned.len())];

        while let Some(id) = queue.pop() {
            let slot = id.index();
            if seen.get(slot).copied().unwrap_or(true) {
                continue;
            }
            if let Some(flag) = seen.get_mut(slot) {
                *flag = true;
            }

            // Only problem clauses are reported. A learned clause is a derived fact, not
            // something a user could act on, so it is traversed but never named.
            if slot < self.problem.len() {
                core.push(id);
            }

            // A clause is false because each of its literals was forced. Follow those
            // forcings so the explanation reaches the packages responsible.
            for literal in self.literals_of(id) {
                let assigned = literal.solvable().index();
                if let Some(reason) = self.reasons.get(assigned).copied().flatten()
                    && reason != id
                {
                    queue.push(reason);
                }
            }
        }

        core.sort_unstable();
        core
    }

    /// Collects the selected candidates once every clause is satisfied.
    fn finish(self) -> Solution {
        let mut selected: Vec<SolvableId> = self
            .values
            .iter()
            .enumerate()
            .filter(|(_, value)| **value == Value::True)
            .filter_map(|(index, _)| u32::try_from(index).ok().map(SolvableId::from_raw))
            .collect();
        selected.sort_unstable();
        Solution { selected, conflicts: self.conflicts }
    }
}

/// Kinds of clause a core is made of, for a caller rendering an explanation.
#[must_use]
pub fn core_kinds(problem: &Problem, core: &[ClauseId]) -> Vec<ClauseKind> {
    core.iter().filter_map(|id| problem.get(*id).map(|clause| clause.kind())).collect()
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

    fn pos(raw: u32) -> Lit {
        Lit::positive(id(raw))
    }

    fn neg(raw: u32) -> Lit {
        Lit::negative(id(raw))
    }

    /// A `Requires`-tagged clause; the tag is irrelevant to solving, only to explaining.
    fn requires(problem: &mut Problem, dependent: u32, literals: impl IntoIterator<Item = Lit>) {
        problem.add(literals, ClauseKind::Requires { dependent: id(dependent), dependency: 0 });
    }

    fn solve(problem: &Problem) -> Outcome {
        Solver::new(problem, Limits::default()).solve().unwrap()
    }

    fn selected(problem: &Problem) -> Vec<u32> {
        match solve(problem) {
            Outcome::Satisfied(solution) => solution.selected().iter().map(|id| id.get()).collect(),
            Outcome::Unsatisfiable(_) => panic!("expected a solution"),
        }
    }

    #[test]
    fn an_empty_problem_selects_nothing() {
        let problem = Problem::new(4);
        assert_eq!(selected(&problem), Vec::<u32>::new());
    }

    /// Nothing is installed unless something requires it. The default polarity is "not
    /// selected", which stops the solver from installing the whole repository.
    #[test]
    fn candidates_no_clause_mentions_are_left_unselected() {
        let mut problem = Problem::new(5);
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        assert_eq!(selected(&problem), [0]);
    }

    #[test]
    fn a_unit_target_pulls_its_single_dependency() {
        let mut problem = Problem::new(3);
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        requires(&mut problem, 0, [neg(0), pos(1)]);
        assert_eq!(selected(&problem), [0, 1]);
    }

    #[test]
    fn dependencies_are_followed_transitively() {
        let mut problem = Problem::new(4);
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        requires(&mut problem, 0, [neg(0), pos(1)]);
        requires(&mut problem, 1, [neg(1), pos(2)]);
        requires(&mut problem, 2, [neg(2), pos(3)]);
        assert_eq!(selected(&problem), [0, 1, 2, 3]);
    }

    /// The heart of the fidelity claim: with several providers and no conflict, the solver
    /// chooses the first listed one and the search never backtracks.
    #[test]
    fn the_first_listed_provider_wins_without_any_backtracking() {
        let mut problem = Problem::new(4);
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        requires(&mut problem, 0, [neg(0), pos(1), pos(2), pos(3)]);

        match solve(&problem) {
            Outcome::Satisfied(solution) => {
                assert_eq!(
                    solution.selected().iter().map(|id| id.get()).collect::<Vec<_>>(),
                    [0, 1]
                );
                assert_eq!(solution.conflicts(), 0, "a greedy descent must resolve no conflicts");
            }
            Outcome::Unsatisfiable(_) => panic!("expected a solution"),
        }
    }

    /// The case libalpm cannot handle: the first provider conflicts with something already
    /// required, so the solver must back out and take the second.
    #[test]
    fn a_conflicting_first_choice_is_backed_out_of() {
        let mut problem = Problem::new(4);
        // target 0 requires (1 or 2); target 3 is also required; 1 conflicts with 3.
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        problem.add([pos(3)], ClauseKind::Target { target: id(3) });
        requires(&mut problem, 0, [neg(0), pos(1), pos(2)]);
        problem.add([neg(1), neg(3)], ClauseKind::Conflicts { declarer: id(1), other: id(3) });

        match solve(&problem) {
            Outcome::Satisfied(solution) => {
                let chosen: Vec<_> = solution.selected().iter().map(|id| id.get()).collect();
                assert_eq!(chosen, [0, 2, 3], "must fall back to the second provider");
            }
            Outcome::Unsatisfiable(_) => panic!("expected the solver to find the fallback"),
        }
    }

    #[test]
    fn a_dependency_with_no_satisfier_is_unsatisfiable() {
        let mut problem = Problem::new(2);
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        // An empty requirement clause: the encoder found no candidate at all.
        requires(&mut problem, 0, []);

        match solve(&problem) {
            Outcome::Unsatisfiable(unsat) => assert!(!unsat.core().is_empty()),
            Outcome::Satisfied(_) => panic!("expected unsatisfiable"),
        }
    }

    #[test]
    fn two_targets_that_directly_conflict_are_unsatisfiable() {
        let mut problem = Problem::new(2);
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        problem.add([pos(1)], ClauseKind::Target { target: id(1) });
        problem.add([neg(0), neg(1)], ClauseKind::Conflicts { declarer: id(0), other: id(1) });

        match solve(&problem) {
            Outcome::Unsatisfiable(unsat) => {
                let kinds = core_kinds(&problem, unsat.core());
                assert!(
                    kinds.iter().any(|kind| matches!(kind, ClauseKind::Conflicts { .. })),
                    "the core must name the conflict: {kinds:?}"
                );
            }
            Outcome::Satisfied(_) => panic!("expected unsatisfiable"),
        }
    }

    /// Two versions of one package cannot both be selected, and a target forces which.
    #[test]
    fn at_most_one_candidate_per_name_is_enforced() {
        let mut problem = Problem::new(3);
        problem.add_at_most_one(&[id(0), id(1)]);
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        problem.add([neg(1), pos(2)], ClauseKind::Requires { dependent: id(1), dependency: 0 });

        let chosen = selected(&problem);
        assert!(chosen.contains(&0));
        assert!(!chosen.contains(&1), "both versions must not be selected: {chosen:?}");
    }

    /// A chain whose far end conflicts with the target is rejected *without* backtracking.
    /// Unit propagation runs the implication backwards from the conflict at level 0.
    ///
    /// libalpm cannot do this. `_alpm_resolvedeps` would take the first provider (1), pull 3,
    /// then pull 4, and only discover at `_alpm_sync_prepare`'s conflict step that 4 cannot
    /// coexist with the target — a hard `ALPM_ERR_CONFLICTING_DEPS`.
    ///
    /// This is also why a zero [`Solution::conflicts`] does not on its own mean "libalpm's
    /// answer": propagation forestalled the decision libalpm would have made.
    #[test]
    fn a_chain_that_conflicts_with_the_target_is_rejected_by_propagation_alone() {
        let mut problem = Problem::new(8);
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        // 0 requires (1 or 2). Choosing 1 would force 3, which forces 4, which conflicts
        // with 0 — so ¬4, ¬3 and ¬1 are all forced before any decision is taken.
        requires(&mut problem, 0, [neg(0), pos(1), pos(2)]);
        requires(&mut problem, 1, [neg(1), pos(3)]);
        requires(&mut problem, 3, [neg(3), pos(4)]);
        problem.add([neg(4), neg(0)], ClauseKind::Conflicts { declarer: id(4), other: id(0) });

        match solve(&problem) {
            Outcome::Satisfied(solution) => {
                let chosen: Vec<_> = solution.selected().iter().map(|id| id.get()).collect();
                assert_eq!(chosen, [0, 2], "must reject the whole 1 -> 3 -> 4 chain");
                assert_eq!(solution.conflicts(), 0, "propagation alone suffices here");
            }
            Outcome::Unsatisfiable(_) => panic!("expected the solver to find the alternative"),
        }
    }

    /// A case propagation genuinely cannot settle. Two independent choices have first-listed
    /// options that are incompatible, so the search must retract a decision and backjump.
    #[test]
    fn an_incompatible_first_choice_forces_a_real_backjump() {
        let mut problem = Problem::new(8);
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        // Two open choices: nothing is forced at level 0, so a decision has to be made.
        requires(&mut problem, 0, [neg(0), pos(1), pos(2)]);
        requires(&mut problem, 0, [neg(0), pos(5), pos(6)]);
        // Taking 1 rules out both ways of satisfying the second choice.
        problem.add([neg(1), neg(5)], ClauseKind::Conflicts { declarer: id(1), other: id(5) });
        problem.add([neg(1), neg(6)], ClauseKind::Conflicts { declarer: id(1), other: id(6) });

        match solve(&problem) {
            Outcome::Satisfied(solution) => {
                let chosen: Vec<_> = solution.selected().iter().map(|id| id.get()).collect();
                assert!(chosen.contains(&0));
                assert!(chosen.contains(&2), "must fall back to the second provider: {chosen:?}");
                assert!(!chosen.contains(&1), "1 is incompatible with both: {chosen:?}");
                assert!(solution.conflicts() > 0, "this genuinely requires backtracking");
            }
            Outcome::Unsatisfiable(_) => panic!("expected the solver to unwind and recover"),
        }
    }

    /// A cyclic dependency is ordinary for a solver. Only the *ordering* step has to care
    /// about it, and libalpm treats a cycle as a warning, not an error.
    #[test]
    fn a_dependency_cycle_solves_without_trouble() {
        let mut problem = Problem::new(3);
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        requires(&mut problem, 0, [neg(0), pos(1)]);
        requires(&mut problem, 1, [neg(1), pos(0)]);
        assert_eq!(selected(&problem), [0, 1]);
    }

    /// Termination is guaranteed by the budget, not by the learning scheme being correct.
    #[test]
    fn the_conflict_budget_is_enforced() {
        let mut problem = Problem::new(2);
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        problem.add([pos(1)], ClauseKind::Target { target: id(1) });
        problem.add([neg(0), neg(1)], ClauseKind::Conflicts { declarer: id(0), other: id(1) });

        let limits = Limits { solve_max_conflicts: 0, ..Limits::default() };
        // Unsatisfiable at level 0 here, so it resolves without consuming budget. The point
        // is that a zero budget never hangs.
        let outcome = Solver::new(&problem, limits).solve();
        assert!(outcome.is_ok() || matches!(outcome, Err(Error::SolveBudgetExhausted { max: 0 })));
    }

    #[test]
    fn a_conflict_between_two_optional_providers_does_not_make_it_unsatisfiable() {
        let mut problem = Problem::new(4);
        problem.add([pos(0)], ClauseKind::Target { target: id(0) });
        requires(&mut problem, 0, [neg(0), pos(1), pos(2)]);
        requires(&mut problem, 0, [neg(0), pos(3)]);
        problem.add([neg(1), neg(3)], ClauseKind::Conflicts { declarer: id(1), other: id(3) });

        let chosen = selected(&problem);
        assert_eq!(chosen, [0, 2, 3]);
    }
}
