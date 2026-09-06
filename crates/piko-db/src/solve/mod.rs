//! Dependency solving: turns a set of targets into an ordered, inspectable plan.
//!
//! [`crate::resolve`] answers one dependency at a time, by scanning. That shape fits
//! `piko resolve`, which asks exactly one question. A planner asks thousands, so the same
//! shape is wrong for it. Measured on the machine this was developed against, one
//! `%PROVIDES%` scan across `core` and `extra` (15 200 packages) costs about 56 ms. A few
//! hundred of those scans would dominate a run that opens those archives in 671 ms.
//! [`Universe`] pays that cost once, as an index, and answers from it.
//!
//! The two must still agree on what "satisfies" means. Neither implements it directly; both
//! call [`crate::depcmp`].

mod cache;
mod clause;
mod encode;
mod explain;
mod file;
mod plan;
mod removal;
mod solver;
mod universe;
mod why;

pub use cache::{NoCache, PackageCache};
pub use clause::{Clause, ClauseId, ClauseKind, Lit, Problem};
pub use encode::{
    Divergence, Encoded, Fidelity, FidelityReport, Planned, Request, Requirement, Sysupgrade,
    TargetResolutionFailure, encode, fidelity, recurse_unneeded, resolve_group, resolve_target,
    resolve_targets, solve_with_removals, sysupgrade,
};
pub use explain::{Derivation, Fact};
pub use file::FilePackage;
pub use plan::{Change, Plan, PlanDiagnostic, Step};
pub use removal::{RemovalFailure, RemovalOptions, plan_removal, removal_names};
pub use solver::{Outcome, Solution, Solver, Unsatisfiable, core_kinds};
pub use universe::{Origin, Solvable, SolvableId, Universe, UniverseOptions};
pub use why::{Dependents, WhyResult, dependents, explain_why_installed, orphans};
