# The transaction planner: why a request has no solution (`piko_db::solve`).
#
# English is the source language. Each message renders exactly as the `Display` of the
# `piko-db` type it describes, and `piko-db`'s tests compare the two.
#
# Every value is a string a frontend already escaped: a package as the planner prints it,
# with its version and its origin, or a `%DEPENDS%` entry, verbatim.

## Fact: one clause of the unsatisfiable core.

solve-fact-requested = { $package } was requested
solve-fact-excluded = { $package } cannot be selected
solve-fact-must-remain = { $package } is installed and must remain
solve-fact-requires = { $package } requires { $relation }
solve-fact-conflicts = { $package } conflicts with { $other }
solve-fact-replaces = { $package } replaces { $replaced }
# $reason names the list and the pattern that matched, as pacman.conf spells them.
solve-fact-ignored = { $candidate } would satisfy { $relation }, but it is ignored ({ $reason })
solve-fact-no-version = nothing satisfies { $relation }; the closest candidate is { $nearest }
solve-fact-chose = { $chosen } was chosen to satisfy { $relation }, which { $package } requires
solve-fact-same-name = { $first } and { $second } are versions of the same package

## Shape: what kind of failure the core describes. A frontend prints it after "Error:".

solve-shape-unsatisfied = nothing satisfies { $relation }
solve-shape-ignored-only = every candidate satisfying { $relation } is ignored
solve-shape-chosen-provider = { $chosen } was chosen to satisfy { $relation }, and leaves no solution
solve-shape-conflict = { $first } and { $second } cannot both be installed
solve-shape-removal = removing { $package } would leave the system unsatisfied
solve-shape-unclassified = the requested transaction has no solution

## Remedy: one change that leaves the request solvable. A frontend prints it after "Try:".

solve-remedy-drop-target = drop { $package } from the transaction
solve-remedy-allow-removal = let { $package } be removed
solve-remedy-choose-other = take { $provider } for { $relation } instead
solve-remedy-unignore = allow { $package }, which { $reason } covers
