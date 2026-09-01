//! Whether a package satisfies a dependency.
//!
//! This is a leaf module. [`crate::resolve`] shares it to answer one dependency at a time,
//! from a keyed lookup. [`crate::solve`] shares it to answer thousands, from an index. Both
//! must agree on what "satisfies" means down to the last edge case. The cheapest way to
//! guarantee that is a single implementation. A copy in the solver that drifted from the copy
//! in the resolver would stay invisible until it produced a plan a user could not explain.
//!
//! The rules encoded here, all from `deps.c`:
//!
//! - A package *automatically satisfies its own name and version*
//!   ([`literal_satisfies`]). A package never lists this in its own `%PROVIDES%`.
//! - A dependency with no operator is `ALPM_DEP_MOD_ANY`. Any version satisfies it.
//! - An **unversioned or non-`=` `%PROVIDES%` entry can never satisfy a versioned
//!   dependency** ([`relation_provide_satisfies`]). `provides=foo` does not satisfy `foo>=2`.
//! - A soname matches a `%PROVIDES%` entry only by exact structural equality.
//!   There is no compatible-range notion, and a soname never
//!   cross-matches a named relation in either direction.
//!
//! Nothing here reimplements version comparison or dependency parsing.
//! [`alpm_types::VersionRequirement::is_satisfied_by`] already evaluates the operator. That
//! includes `dep_vercmp`'s `parseEVR`-derived rule: a constraint carrying no `pkgrel`
//! (`foo=1.0`) is satisfied by any `pkgrel` of a matching `pkgver`, `foo-1.0-3` included.

use alpm_types::{
    FullVersion, Name, PackageRelation, RelationOrSoname, SonameV1, Version, VersionComparison,
    VersionRequirement,
};

/// `_alpm_depcmp` (`deps.c`) in full: a package satisfies `dep` either literally, or through
/// one of its `%PROVIDES%` entries.
///
/// ```c
/// int _alpm_depcmp(alpm_pkg_t *pkg, alpm_depend_t *dep) {
///     return _alpm_depcmp_literal(pkg, dep)
///         || _alpm_depcmp_provides(dep, alpm_pkg_get_provides(pkg));
/// }
/// ```
///
/// This is the predicate `%CONFLICTS%` matching needs. `check_conflict` (`conflict.c`) calls
/// `_alpm_depcmp`, not the literal half, so a package conflicts with anything *providing* the
/// named thing, not only with the thing itself. Plain dependency resolution does not use this
/// function: there, the two halves are reached through different indexes, in a defined order.
pub(crate) fn satisfies(
    name: &Name,
    version: &FullVersion,
    provides: &[RelationOrSoname],
    dep: &PackageRelation,
) -> bool {
    if literal_satisfies(name, version, dep) {
        return true;
    }
    provides.iter().any(|provided| match provided {
        RelationOrSoname::Relation(provided) => relation_provide_satisfies(dep, provided),
        RelationOrSoname::SonameV1(_) | RelationOrSoname::SonameV2(_) => false,
    })
}

/// `_alpm_depcmp_literal` (`deps.c`): whether a package called `name` at `version` is itself
/// the thing `dep` asks for.
pub(crate) fn literal_satisfies(name: &Name, version: &FullVersion, dep: &PackageRelation) -> bool {
    *name == dep.name && version_satisfies(version, dep)
}

/// The version half of [`literal_satisfies`], for a caller that already matched the name
/// through a keyed lookup and would only be re-comparing it.
///
/// The conversion is the one piece piko supplies rather than delegates: a package's
/// [`FullVersion`] has a mandatory `pkgrel`, while the [`Version`] a requirement compares
/// against has an optional one. It is lossless and provided by `alpm-types` itself.
pub(crate) fn version_satisfies(version: &FullVersion, dep: &PackageRelation) -> bool {
    dep.version_requirement
        .as_ref()
        .is_none_or(|requirement| requirement.is_satisfied_by(&Version::from(version)))
}

/// Whether one `%PROVIDES%` entry satisfies `dep`.
///
/// A named relation and a soname never satisfy one another. The two `%PROVIDES%` grammars do
/// not collide in practice. Treating a near-miss as a match would be a false positive, not a
/// helpful fallback.
pub(crate) fn provides_satisfies(provided: &RelationOrSoname, dep: &RelationOrSoname) -> bool {
    match (dep, provided) {
        (RelationOrSoname::Relation(dep), RelationOrSoname::Relation(provided)) => {
            relation_provide_satisfies(dep, provided)
        }

        // **alpm-sonamev2** (`lib:libfoo.so.1`) is matched by exact structural equality — the
        // "exact match" rule the specification states. It never cross-matches the v1 forms.
        // The `lib:` prefix makes the two grammars unambiguous, so a near-miss is a false
        // positive here too, not a helpful fallback.
        (RelationOrSoname::SonameV2(_), _) | (_, RelationOrSoname::SonameV2(_)) => provided == dep,

        // Everything else is v1.
        // An **unversioned** dependency is `ALPM_DEP_MOD_ANY`, so any same-named provide
        // satisfies it regardless of its own version.
        _ => {
            let (Some(dep_name), Some(provided_name)) = (v1_name(dep), v1_name(provided)) else {
                return false;
            };
            if dep_name != provided_name {
                return false;
            }
            if is_unversioned(dep) {
                return true;
            }
            // An identical requirement always satisfies itself. This check runs before
            // reassembling and parsing a `Version` below, because that parse can fail on a
            // real, pacman-accepted package. `SonameV1::Unversioned`'s grammar reuses the
            // soname itself as the "version" (`example.so=example.so-64`). The reconstructed
            // string is not a valid `<pkgver>-<pkgrel>` — it has no numeric release — so
            // `Version::from_str` rejects it even when `dep` and `provided` are the same
            // struct. Real case: `gimp` depends on
            // `libgegl-npd-0.4.so=libgegl-npd-0.4.so-64`, and `gegl` `%PROVIDES%`s the
            // identical text. libalpm has no such parse step. It feeds the two raw strings
            // straight to `alpm_pkg_vercmp`, which compares identical strings equal
            // regardless of grammar.
            if dep == provided {
                return true;
            }
            // A versioned dependency needs an exact-version provide. `_alpm_depcmp_provides`
            // applies the same rule to named relations: `dep_vercmp(provision->version,
            // dep->mod, dep->version)`, a real version comparison, not a string comparison.
            // `alpm-types` splits a v1 soname's `<version>-<arch>` into two typed fields, while
            // libalpm's `alpm_depend_t` holds one version string. A mismatched pair — a plain
            // relation dependency like `libalpm.so>=14` against a soname provide like
            // `libalpm.so=16-64` — needs that string reassembled and parsed back into a
            // `Version` before the comparison. Falling back to structural equality of two
            // different enum variants would never match, regardless of the values inside.
            let (Some(dep_requirement), Some(provided_version)) =
                (v1_requirement(dep), exact_v1_version(provided))
            else {
                return false;
            };
            dep_requirement.is_satisfied_by(&provided_version)
        }
    }
}

/// The version requirement a v1 soname or relation dependency implies. Returns `None` for
/// [`is_unversioned`]. A v1 soname dependency has no comparison operator of its own — its
/// grammar means "exactly this version", so it implies `=`.
fn v1_requirement(dep: &RelationOrSoname) -> Option<VersionRequirement> {
    match dep {
        RelationOrSoname::Relation(relation) => relation.version_requirement.clone(),
        RelationOrSoname::SonameV1(SonameV1::Basic(_)) => None,
        RelationOrSoname::SonameV1(SonameV1::Explicit { version, architecture, .. }) => {
            format!("{version}-{architecture}")
                .parse()
                .ok()
                .map(|version| VersionRequirement { comparison: VersionComparison::Equal, version })
        }
        RelationOrSoname::SonameV1(SonameV1::Unversioned { soname, architecture, .. }) => {
            format!("{soname}-{architecture}")
                .parse()
                .ok()
                .map(|version| VersionRequirement { comparison: VersionComparison::Equal, version })
        }
        RelationOrSoname::SonameV2(_) => None,
    }
}

/// The exact version a `%PROVIDES%` entry asserts, the way `_alpm_depcmp_provides` requires.
/// Returns `None` for an unconstrained (`ALPM_DEP_MOD_ANY`) provide, and for a named relation
/// provide whose own comparison is not `=` — an inequality provide can never stand in for an
/// exact one.
fn exact_v1_version(provided: &RelationOrSoname) -> Option<Version> {
    match provided {
        RelationOrSoname::Relation(relation) => {
            let requirement = relation.version_requirement.as_ref()?;
            (requirement.comparison == VersionComparison::Equal)
                .then(|| requirement.version.clone())
        }
        RelationOrSoname::SonameV1(SonameV1::Basic(_)) => None,
        RelationOrSoname::SonameV1(SonameV1::Explicit { version, architecture, .. }) => {
            format!("{version}-{architecture}").parse().ok()
        }
        RelationOrSoname::SonameV1(SonameV1::Unversioned { soname, architecture, .. }) => {
            format!("{soname}-{architecture}").parse().ok()
        }
        RelationOrSoname::SonameV2(_) => None,
    }
}

/// The name half of a v1 relation — a package name, or a shared object name.
///
/// Returns `None` for **alpm-sonamev2**, which is matched whole rather than by name.
///
/// Crate-visible because it is also the **index key** [`crate::solve::Universe`] files
/// `%PROVIDES%` entries under. Matching is by name plus a version rule, so an index keyed by
/// anything finer than the name would miss the pairs this module exists to match.
pub(crate) fn v1_name(value: &RelationOrSoname) -> Option<&str> {
    match value {
        RelationOrSoname::Relation(relation) => Some(relation.name.as_ref()),
        RelationOrSoname::SonameV1(SonameV1::Basic(name)) => Some(name.as_str()),
        RelationOrSoname::SonameV1(
            SonameV1::Unversioned { name, .. } | SonameV1::Explicit { name, .. },
        ) => Some(name.as_str()),
        RelationOrSoname::SonameV2(_) => None,
    }
}

/// Whether `value` carries no version constraint at all — libalpm's `ALPM_DEP_MOD_ANY`.
///
/// [`SonameV1::Unversioned`] is *not* unversioned in this sense, despite its name. Its textual
/// form is `example.so=example.so-64`, which libalpm reads as an `=` constraint whose version
/// happens to be a soname.
fn is_unversioned(value: &RelationOrSoname) -> bool {
    match value {
        RelationOrSoname::Relation(relation) => relation.version_requirement.is_none(),
        RelationOrSoname::SonameV1(SonameV1::Basic(_)) => true,
        RelationOrSoname::SonameV1(_) | RelationOrSoname::SonameV2(_) => false,
    }
}

/// `_alpm_depcmp_provides`'s per-entry check (`deps.c`). An unconstrained `dep` is satisfied
/// by any same-named provide, versioned or not. A version-constrained `dep` is satisfied only
/// by a same-named provide that itself carries an exact (`=`) version meeting the constraint —
/// `dep_vercmp(provision->version, dep->mod, dep->version)`, gated on `provision->mod ==
/// ALPM_DEP_MOD_EQ`.
pub(crate) fn relation_provide_satisfies(
    dep: &PackageRelation,
    provided: &PackageRelation,
) -> bool {
    if provided.name != dep.name {
        return false;
    }
    let Some(requirement) = &dep.version_requirement else {
        return true;
    };
    match &provided.version_requirement {
        Some(provided_requirement)
            if provided_requirement.comparison == VersionComparison::Equal =>
        {
            requirement.is_satisfied_by(&provided_requirement.version)
        }
        _ => false,
    }
}

/// The name a dependency is keyed by in an index, or `None` for a soname.
///
/// A soname is never a package name. That is why [`crate::solve`] indexes the two
/// separately, and why `resolvedep`'s literal step never runs for one.
pub(crate) fn dep_name(dep: &RelationOrSoname) -> Option<&Name> {
    match dep {
        RelationOrSoname::Relation(relation) => Some(&relation.name),
        RelationOrSoname::SonameV1(_) | RelationOrSoname::SonameV2(_) => None,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn dep(text: &str) -> PackageRelation {
        text.parse().unwrap()
    }

    fn relation(text: &str) -> RelationOrSoname {
        text.parse().unwrap()
    }

    fn version(text: &str) -> FullVersion {
        text.parse().unwrap()
    }

    #[test]
    fn a_package_satisfies_its_own_name_at_any_version_when_unconstrained() {
        let name: Name = "foo".parse().unwrap();
        assert!(literal_satisfies(&name, &version("1.0.0-1"), &dep("foo")));
        assert!(literal_satisfies(&name, &version("9.9.9-9"), &dep("foo")));
    }

    #[test]
    fn a_literal_match_still_honors_a_version_constraint() {
        let name: Name = "foo".parse().unwrap();
        assert!(literal_satisfies(&name, &version("2.0.0-1"), &dep("foo>=2.0")));
        assert!(!literal_satisfies(&name, &version("1.0.0-1"), &dep("foo>=2.0")));
    }

    #[test]
    fn a_different_name_never_satisfies_literally() {
        let name: Name = "bar".parse().unwrap();
        assert!(!literal_satisfies(&name, &version("1.0.0-1"), &dep("foo")));
    }

    /// `_alpm_depcmp_provides`' asymmetry, and the single most consequential rule here.
    #[test]
    fn an_unversioned_provide_cannot_satisfy_a_versioned_dependency() {
        assert!(!relation_provide_satisfies(&dep("foo>=2.0"), &dep("foo")));
        assert!(relation_provide_satisfies(&dep("foo"), &dep("foo")));
    }

    #[test]
    fn only_an_exact_version_provide_satisfies_a_versioned_dependency() {
        assert!(relation_provide_satisfies(&dep("foo>=2.0"), &dep("foo=2.1")));
        assert!(!relation_provide_satisfies(&dep("foo>=2.0"), &dep("foo=1.0")));
        // A non-`=` provide is rejected regardless of whether the range would overlap.
        assert!(!relation_provide_satisfies(&dep("foo>=2.0"), &dep("foo>=3.0")));
    }

    #[test]
    fn a_constraint_without_a_pkgrel_matches_any_pkgrel() {
        let name: Name = "foo".parse().unwrap();
        assert!(literal_satisfies(&name, &version("1.0-3"), &dep("foo=1.0")));
    }

    #[test]
    fn a_soname_matches_only_an_identical_provide() {
        let want = relation("lib:libexample.so.1");
        assert!(provides_satisfies(&relation("lib:libexample.so.1"), &want));
        assert!(!provides_satisfies(&relation("lib:libexample.so.2"), &want));
    }

    #[test]
    fn a_soname_and_a_named_relation_never_cross_match() {
        let soname = relation("lib:libexample.so.1");
        let named = relation("libexample");
        assert!(!provides_satisfies(&named, &soname));
        assert!(!provides_satisfies(&soname, &named));
    }

    /// A real-world case: `paru` requires `libalpm.so>=14`, satisfied by `pacman`'s
    /// `%PROVIDES% = libalpm.so=16-64`. A plain versioned relation dependency and a v1 soname
    /// provide are different `RelationOrSoname` variants, so the comparison must be by
    /// version. Structural equality would make a mismatched pair unsatisfiable regardless of
    /// the actual versions involved.
    #[test]
    fn a_versioned_relation_dependency_is_satisfied_by_a_newer_soname_provide() {
        let dep = relation("libalpm.so>=14");
        assert!(provides_satisfies(&relation("libalpm.so=16-64"), &dep));
        assert!(provides_satisfies(&relation("libalpm.so=14-64"), &dep));
        assert!(!provides_satisfies(&relation("libalpm.so=13-64"), &dep));
        // An unconstrained (`ALPM_DEP_MOD_ANY`) soname provide can never satisfy a versioned
        // dependency, the same rule a named relation provide follows.
        assert!(!provides_satisfies(&relation("libalpm.so"), &dep));
    }

    #[test]
    fn dep_name_is_none_exactly_for_sonames() {
        assert!(dep_name(&relation("foo")).is_some());
        assert!(dep_name(&relation("lib:libexample.so.1")).is_none());
        assert!(dep_name(&relation("libexample.so=1-64")).is_none());
    }

    /// A real-world case: `gimp` requires `libgegl-npd-0.4.so=libgegl-npd-0.4.so-64`,
    /// satisfied by `gegl`'s identical `%PROVIDES%` entry. `SonameV1::Unversioned` reuses the
    /// soname text as the "version", so the reassembled `<version>-<arch>` string
    /// (`libgegl-npd-0.4.so-64`) is not a valid `<pkgver>-<pkgrel>`. `Version::from_str`
    /// rejects it even though `dep` and `provided` are the identical struct. libalpm has no
    /// such parse step. It feeds the two raw strings straight to `alpm_pkg_vercmp`, which
    /// compares identical strings equal regardless of grammar.
    #[test]
    fn an_unversioned_soname_whose_version_text_is_not_a_valid_version_still_matches_itself() {
        let want = relation("libgegl-npd-0.4.so=libgegl-npd-0.4.so-64");
        assert!(provides_satisfies(&want, &want));
    }
}
