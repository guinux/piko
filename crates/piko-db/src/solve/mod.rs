//! Dependency solving: turns a set of targets into an ordered, inspectable plan.
//!
//! [`crate::resolve`] answers one dependency at a time, by scanning. That shape fits
//! `piko resolve`, which asks exactly one question. A planner asks thousands, so the same
//! shape is wrong for it. Measured on the machine this was developed against, one
//! `%PROVIDES%` scan across `core` and `extra` (15 200 packages) costs about 56 ms. A few
//! hundred of those scans would dominate a run that opens those archives in 671 ms.
//! [`Universe`] pays that cost once, as an index, and answers from it.
//!
//! The two must still agree on what "satisfies" means. Neither implements it directly; both call
//! `depcmp`.

mod cache;
mod clause;
mod encode;
mod explain;
mod file;
mod glob;
mod install;
mod justify;
mod plan;
mod removal;
mod solver;
mod universe;
mod why;

pub use cache::{NoCache, PackageCache};
pub(crate) use clause::ClauseId;
pub(crate) use clause::Problem;
#[doc(hidden)]
pub use encode::resolve_target;
pub use encode::{
    Ambiguity, AmbiguityReport, Fidelity, GroupChoice, GroupTarget, IgnoredChange, IgnoredTarget,
    IgnoredUpgrade, Planned, ProviderChoice, Request, Resolution, TargetResolutionFailure,
    ambiguities, encode, fidelity, resolve_targets, solve_with_removals, sysupgrade,
};
pub use encode::{BrokenDependency, Divergence, Encoded, FidelityReport, RemovalCause, Sysupgrade};
pub use explain::Derivation;
pub use explain::Fact;
pub use explain::{Diagnosis, Remedy, Shape, describe_candidate};
pub use file::FilePackage;
pub use glob::{Expansion, ExpansionFailure, Side};
#[doc(hidden)]
pub use glob::{InstallableTargets, expand_installable_targets};
pub use install::{
    Defaults, InstallFailure, InstallOptions, InstallPlan, InstallQuestions, ResolutionNotes,
    plan_install,
};
pub use justify::Alternative;
pub use justify::{Cause, PlanExplanation, Verdict, describe_cause, explain_plan};
pub use plan::{Change, Plan, PlanDiagnostic, Step};
pub use removal::NamedRemoval;
pub use removal::{
    NamedRemovalFailure, Removal, RemovalFailure, RemovalOptions, named_removal, plan_removal,
    removal_names,
};
pub(crate) use solver::Solver;
pub(crate) use solver::{Outcome, Unsatisfiable};
pub use universe::IgnoredCandidate;
pub use universe::{Origin, Solvable, SolvableId, Universe, UniverseOptions};
pub use why::Dependents;
pub use why::{DependentsIndex, WhyResult, dependents, explain_why_installed, orphans};
