# The messages of the `piko` command line. English is the source language.
#
# Indentation and the `:: ` prefix of a question are not part of a message: the code adds
# them. Fluent removes the spaces at the start and at the end of a value.
#
# Every value is escaped by the code before it reaches a message.


## The keyword at the start of a diagnostic line. $text is the rest of the line.

cli-error = Error: { $text }
cli-warning = Warning: { $text }
cli-note = Note: { $text }
cli-caused-by = Caused by: { $text }
cli-try = Try: { $text }

## Questions and answers.

cli-yes-answers = y yes
cli-invalid-number = Invalid value: it must be a number between 1 and { $count }
cli-invalid-selection = Invalid value: it must be a number or a range between 1 and { $count }
cli-invalid-letter = Invalid value: it must be one of { $letters }

## Shared pieces.

cli-write-failed = failed to write output: { $error }
cli-unknown = <unknown>
cli-and-more = { $shown }, and { $rest } more
cli-problems-not-shown =
    { $count ->
        [one] 1 further problem not shown
       *[other] { $count } further problems not shown
    }

## Resolving targets (piko plan, install, remove).

plan-invalid-dependency = { $target } is not a valid dependency string
plan-not-found = no package satisfying { $target } was found in any configured repository
plan-closest-candidate = the closest candidate is { $nearest }
plan-pattern-ignored = every package matching { $pattern } is ignored
plan-target-ignored = every package satisfying { $target } is ignored
plan-never-installs-ignored = piko never installs an ignored package; edit IgnorePkg or IgnoreGroup in pacman.conf to allow it
plan-ignoring-package = ignoring package { $package }
plan-pattern-not-found = no package or group matching { $pattern } was found in any configured repository
plan-pattern-not-installed = no installed package or group matches { $pattern }
plan-pattern-too-broad = { $pattern } matches more than { $limit } packages
plan-pattern-too-broad-note = name the packages, or narrow the pattern
plan-pattern-versioned = { $target } is a glob pattern with a version requirement
plan-pattern-versioned-note = a pattern expands to names only; name the package to constrain its version

## Ignored upgrades. The wordings are libalpm's.

plan-ignoring-upgrade = { $name }: ignoring package upgrade ({ $old } => { $new })
plan-ignoring-downgrade = { $name }: ignoring package downgrade ({ $old } => { $new })
plan-ignoring-replacement = ignoring package replacement ({ $old } => { $new })
plan-lost-file-candidate = Internal error: the universe lost a package file candidate

## Glob targets. $pattern is the pattern as the user typed it.

cli-pattern-matched =
    { $pattern } matched { $packages ->
        [one] 1 package
       *[other] { $packages } packages
    }
cli-pattern-matched-groups =
    { $pattern } matched { $groups ->
        [one] 1 group
       *[other] { $groups } groups
    } and { $packages ->
        [one] 1 package
       *[other] { $packages } packages
    }
cli-groups-list = Groups: { $list }
cli-packages-list = Packages: { $list }

## Why a request has no solution.

cli-explanation-gave-up = the explanation itself exceeded the solver's conflict budget
cli-facts-not-shown =
    { $count ->
        [one] ... and 1 further fact not shown
       *[other] ... and { $count } further facts not shown
    }
cli-changes-not-tried =
    { $count ->
        [one] ... and 1 further change not tried
       *[other] ... and { $count } further changes not tried
    }

## What a plan noticed while it was assembled.

plan-dependency-cycle = { $name } is on a dependency cycle; it may be installed before something it depends on
plan-broken-dependency = { $name } requires { $relation }, which nothing installed provides
plan-broken-not-shown =
    { $count ->
        [one] 1 further broken dependency not shown
       *[other] { $count } further broken dependencies not shown
    }
plan-divergences =
    { $count ->
        [one] 1 dependency requirement was satisfied by a candidate pacman would not have tried first; the plan is valid and may differ from `pacman -Sp`
       *[other] { $count } dependency requirements were satisfied by a candidate pacman would not have tried first; the plan is valid and may differ from `pacman -Sp`
    }
plan-divergence = { $name } requires { $relation }: took { $taken }, pacman would have tried { $preferred }
cli-requirements-not-shown =
    { $count ->
        [one] 1 further requirement not shown
       *[other] { $count } further requirements not shown
    }
cli-unknown-failure = { $failure }

## The step list of a plan.

plan-verb-install = install
plan-verb-upgrade = upgrade
plan-verb-downgrade = downgrade
plan-verb-reinstall = reinstall
plan-verb-remove = remove
plan-tally-install = { $count } to install
plan-tally-upgrade = { $count } to upgrade
plan-tally-downgrade = { $count } to downgrade
plan-tally-reinstall = { $count } to reinstall
plan-tally-remove = { $count } to remove
plan-download-size = { $size } to download
plan-installed-size = { $size } installed size

## The command line itself.

main-blank-search = every search term is blank; name what to search for
main-no-targets = no targets given (use --sysupgrade to upgrade everything)

## Reading the configuration and opening the databases.

context-repository-unused = repository [{ $name }] is not used: { $reason }
context-config-fallback = failed to read { $config } ({ $reason }); falling back to { $fallback }
context-repository-skipped = skipping repository { $name }: { $reason }
context-config-unavailable = failed to read { $path }: { $reason }

## Why a subcommand stopped.

error-invalid-repo-name = { $name } is not a valid repository name
error-signature-rejected = the signature on { $archive } was rejected: { $reason }
error-signature-uncheckable = cannot check the signature on { $archive }
error-not-root = piko { $command } must run as root to change { $path }. Run it as root, or use { $flags } to name paths you own

## The piko info grid. A label is padded to the longest label of the language.

info-field-repository = Repository
info-field-name = Name
info-field-version = Version
info-field-description = Description
info-field-architecture = Architecture
info-field-url = URL
info-field-licenses = Licenses
info-field-groups = Groups
info-field-provides = Provides
info-field-depends-on = Depends On
info-field-optional-deps = Optional Deps
info-field-required-by = Required By
info-field-optional-for = Optional For
info-field-conflicts-with = Conflicts With
info-field-replaces = Replaces
info-field-download-size = Download Size
info-field-installed-size = Installed Size
info-field-packager = Packager
info-field-build-date = Build Date
info-field-install-date = Install Date
info-field-install-reason = Install Reason
info-field-install-script = Install Script
info-field-validated-by = Validated By
info-none = None
info-unknown = Unknown
info-installed-mark = [installed]
info-yes = Yes
info-no = No
info-explicit = Explicitly installed
info-dependency = Installed as a dependency for another package
info-validation-md5 = MD5 Sum
info-validation-sha256 = SHA-256 Sum
info-validation-signature = Signature
info-optional-incomplete = { $package }: the optional dependencies marked { $mark } may be incomplete: { $reason }
info-optional-for-incomplete = Optional For may be incomplete: { $package }: { $reason }

## Signals.

signal-interrupted = Interrupted
signal-terminated = Terminated
signal-forcing-exit = Still stopping -- forcing exit
signal-stopping = Stopping (press Ctrl+C again to force quit)...
signal-stopping-terminate = Stopping: terminate request received...

## Package lookups shared by several commands.

cli-not-installed = package { $name } is not installed
cli-not-in-repository = package { $name } is not in { $path }
cli-not-found-anywhere = package { $name } is not installed and not in any configured repository

## piko check.

check-row = Checking packages
check-clean =
    { $total ->
        [one] 1 package checked, no problems found
       *[other] { $total } packages checked, no problems found
    }
check-problems =
    { $total ->
        [one] 1 package checked
       *[other] { $total } packages checked
    }, { $problems ->
        [one] 1 package with problems
       *[other] { $problems } packages with problems
    }
check-defects-not-shown =
    { $package }: { $count ->
        [one] 1 further files defect
       *[other] { $count } further files defects
    }
check-no-mtree = { $package }: no mtree file
check-altered =
    { $package }: { $total ->
        [one] 1 total file
       *[other] { $total } total files
    }, { $altered ->
        [one] 1 altered file
       *[other] { $altered } altered files
    }

## piko owns.

owns-owned-by = { $path } is owned by { $name } { $version }
owns-no-owner = No package owns { $path }

## piko why.

why-explicit = { $package } was installed explicitly
why-orphan = { $package } is installed as a dependency, and nothing installed requires it
why-orphan-note = (an orphan by hard dependencies; `piko plan -R -s` would sweep it. It may still be an optional dependency of something — `pacman -Qdt` counts those as required, `pacman -Qdtt` does not.)
why-required-by = { $package } is installed as a dependency, required by:
why-group-orphaned = but no explicitly-installed package requires it, directly or indirectly — this whole group is orphaned
why-chain-root = { $package } (explicitly installed)
why-chain-requires = requires { $package }

## Group and provider questions.

group-members =
    { $count ->
        [one] There is 1 member in group { $group }:
       *[other] There are { $count } members in group { $group }:
    }
group-prompt = Enter a selection (default=all):
group-defaults =
    { $count ->
        [one] 1 group target was taken whole (an interactive `piko install` asks which members to install)
       *[other] { $count } group targets were taken whole (an interactive `piko install` asks which members to install)
    }
group-default = { $group }: took all { $count } members, { $sample }
provider-header = There are { $count } providers available for { $relation }:
provider-prompt = Enter a number (default=1):
provider-defaults =
    { $count ->
        [one] 1 dependency requirement has several providers; the first was taken (an interactive `piko install` asks which one to use)
       *[other] { $count } dependency requirements have several providers; the first was taken (an interactive `piko install` asks which one to use)
    }
provider-default = { $package } requires { $relation }: took { $taken }, among { $sample }

## Removal.

removal-held = { $name } is designated as a HoldPkg
removal-held-unattended = HoldPkg was found in the target list, and this run cannot ask confirmation
removal-held-prompt = HoldPkg was found in target list. Do you want to continue? [y/N]
removal-not-installed = no installed package or group named { $name }
removal-cascade-hint = pass -c to remove the dependents too

## Candidate lists and the database lock.

cli-lock-not-removed = could not remove lock file { $path }{ $cause }
cli-origin-repository = Repository { $name }
cli-origin-file = Package file
cli-origin-installed = Installed

## piko list and piko group.

list-installed = { $count } installed
list-listed = { $count } listed
list-explicit = { $count } explicitly installed
list-orphaned = { $count } orphaned
list-foreign = { $count } foreign
list-configured = { $count } configured
list-groups =
    { $count ->
        [one] 1 group
       *[other] { $count } groups
    }
list-group-not-found = group { $name } was not found

## piko search.

search-found = { $count } found
search-installed = { $count } installed
search-desc-unavailable = (desc unavailable)
search-desc-unparsed = <desc could not be parsed>

## piko check-updates and piko resolve.

sync-updates-available =
    { $count ->
        [one] 1 update available
       *[other] { $count } updates available
    }
sync-no-repository = no configured repository could be opened; see warnings above
sync-ignored-candidate = { $package } in { $repository } ({ $reason })

## How fresh a repository database is. $file is a file name, such as core.db.

fresh-behind = { $server } is older than the installed { $file } (last modified { $date }). Piko tried the next server.
fresh-lost-signature = Piko refused the { $file } from { $server }. It has no valid signature, and the installed one is signed ({ $installed }). A mirror can do this to hold back updates.
fresh-refused-older = Piko refused a signed { $file } from { $server } that is older than the installed one ({ $candidate }, installed { $installed }). A mirror can do this to hold back updates.
fresh-older = { $server } has an older { $file } than the installed one ({ $candidate }, installed { $installed }). Piko tried the next server.
fresh-accepted-older = Piko installed an older { $file } from { $server } ({ $candidate }, the previous one { $replaced }), because you gave --accept-older.
fresh-stale = { $file } is { $age } old ({ $publication }). { $checked } A mirror may be out of date, or may hold back updates. The limit is { $limit } (--max-age).
fresh-future-baseline = The installed { $file } is dated { $ahead } in the future ({ $publication }) and is not signed. Piko did not use that date to refuse an older { $file }. Check the system clock.
fresh-kept = No server has a { $file } as new as the installed one ({ $installed }). Piko keeps the installed database.
fresh-stale-local = { $file } is { $age } old ({ $publication }). The limit is { $limit } (--max-age). Run 'piko refresh' to check the mirrors for a newer one.
fresh-future = { $file } is dated { $ahead } in the future ({ $publication }). Check the system clock.
fresh-signed = signed { $date }
fresh-published = published { $date }
fresh-undated = undated
fresh-no-other-server = No other server was available to check it against.
fresh-other-servers =
    { $count ->
        [one] 1 other server has nothing newer.
       *[other] { $count } other servers have nothing newer.
    }
fresh-days =
    { $count ->
        [one] 1 day
       *[other] { $count } days
    }
fresh-hours =
    { $count ->
        [one] 1 hour
       *[other] { $count } hours
    }
fresh-minutes =
    { $count ->
        [one] 1 minute
       *[other] { $count } minutes
    }

## piko refresh.

refresh-keyring-needed = a repository's SigLevel requires a signature, so refreshing cannot continue without a usable keyring
refresh-row = Synchronizing { $repository }
refresh-up-to-date = { $repository } (up to date)
refresh-kept = { $repository } (kept: no newer database)
refresh-unknown-repository = { $repository } is not a configured repository
refresh-not-synced = { $repository } is not refreshed: its Usage does not include Sync

## piko history.

history-empty = No transactions recorded
history-read = read { $log } and { $store }
history-count =
    { $count ->
        [one] 1 transaction
       *[other] { $count } transactions
    }
history-unknown-date = unknown date
history-packages = { $count } packages
history-verb-installed = installed
history-verb-upgraded = upgraded
history-verb-downgraded = downgraded
history-verb-reinstalled = reinstalled
history-verb-removed = removed
history-unfinished = an unfinished transaction is recorded; run `piko report` to see it
history-unfinished-unreadable = an unfinished transaction is recorded, but its journal cannot be read; run `piko report` to see it

## piko key.

key-generated = Generated a new master signing key in { $path }
key-expiry-removed = Removed the expiry date of the master key in { $path }
key-already-initialized = { $path } is already initialized
key-no-keyrings = No keyrings found under { $path }
key-populated = { $name }: imported { $imported }, locally signed { $lsigned }, trusted { $trusted }, disabled { $disabled }
key-imported = { $file }: imported { $imported }, unchanged { $unchanged }
key-prompt-lsign = Locally sign this key? [y/N]
key-prompt-delete = Delete this key? [y/N]
key-skipped = Skipped { $key }
key-lsigned = Locally signed { $key }
key-already-lsigned = { $key } is already locally signed
key-no-match = No matching keys
key-mark-disabled = [disabled]
key-mark-revoked = [revoked]
key-mark-expired = [expired]
key-deleted = Deleted { $key }
key-verify-outcome = { $status } (trust: { $trust })
key-verify-outcome-key = { $status } (trust: { $trust }), key { $key }
key-trustdb-updated = Trust database recomputed

## piko merge, and the files a transaction left to merge.

merge-pending-not-listed =
    { $count ->
        [one] 1 more pending file was not listed
       *[other] { $count } more pending files were not listed
    }
merge-unmatched = { $path } names no pending file
merge-attention = Configuration files need attention:
merge-installed-as = { $target } installed as { $pacfile }
merge-saved-as = { $target } saved as { $pacfile }
merge-run-hint = Run 'piko merge' to resolve them.
merge-unreadable = { $pacfile }: skipped, it could not be read
merge-no-current = ignoring { $path }, it has no current version to merge against
merge-identical-removed = { $pacfile }: removed, it holds the same bytes as { $target }
merge-changed-since = { $pacfile }: kept, it changed since the scan
merge-target-missing = { $target } does not exist. Remove { $pacfile }? [y/N]
merge-differ = { $target } and { $pacfile } differ ({ $package }).
merge-menu = (V)iew, (M)erge, (S)kip, (R)emove { $label }, (O)verwrite with { $label }, (Q)uit:
merge-write-failed = { $path } cannot be written: { $error }
merge-clean = Merged without conflicts.
merge-conflicts = Merged with conflicts. Review them before keeping the result.
merge-keep-prompt = Keep the merged file? [y/N]
merge-read-back-failed = { $path } cannot be read back: { $error }
merge-no-policy = No signature policy can check a cached build, so there is no base to merge against.
merge-base-refused = Not using { $path } as a base: { $reason }
merge-no-base = No signed cached build of { $package } older than { $version } was found, so there is no base to merge against.
merge-not-shipped = { $package } does not ship { $path }, so there is no base to merge against.
merge-no-base-unknown = There is no base to merge against.
merge-scratch-failed = a scratch directory cannot be used: { $error }
merge-not-regular = not a regular file
merge-too-large = larger than { $max } bytes
merge-start-failed = { $program } cannot be started: { $error }
merge-no-keyring = { $error }; no cached build can serve as a merge base
merge-program-unreadable = { $variable } cannot be read: { $error }
merge-outcome-skipped = Left both files in place.
merge-outcome-removed = Removed { $path }.
merge-outcome-overwritten = Overwrote { $path }.
merge-outcome-merged = Wrote the merged file to { $path }.
merge-outcome-done = Done.

## Transactions: install, update, remove.

txn-resolving = Resolving dependencies
txn-nothing-to-do = Nothing to do
txn-fetching = Fetching { $url }
txn-ambiguous-target = { $name } names both a file here and a package in a repository; installing the file (write ./{ $name } to silence this, or move the file to install the package)
txn-creating-cache = no { $path } cache exists, creating...
txn-removing-packages =
    { $count ->
        [one] Removing 1 package:
       *[other] Removing { $count } packages:
    }
txn-prompt-remove = Do you want to remove these packages? [Y/n]
txn-not-a-removal = this is a bug; run `piko plan -R` to see the plan
txn-previous-unfinished = A previous transaction did not finish; run `piko report` to see it
txn-scriptlet-truncated = { $package }'s scriptlet output was truncated
txn-scriptlet-failed = { $package }'s { $kind } scriptlet { $outcome }
txn-hook-truncated = hook { $hook }'s output was truncated
txn-hook-failed = hook { $hook } { $reason }
txn-prompt-download = Proceed with download? [Y/n]
txn-prompt-install = Proceed with installation? [Y/n]
txn-nothing-changed = nothing was changed; no step of the transaction ran
txn-cancelled-recorded = the steps that ran are recorded; run `piko report` to see them, then re-run to finish
txn-stopped-part-way = the transaction stopped part-way; run `piko report` to see what was applied

## piko report: an unfinished transaction.

report-none = No unfinished transaction is recorded
report-never-started = A transaction was recorded but never started; the system is unchanged
report-remove-journal = Remove the journal to clear it:
report-cannot-undo-remove = The applied steps cannot be undone. Remove the journal:
report-run-again = Then run the operation again
report-finish = The applied steps cannot be undone. To finish the transaction, run in order:
report-unreadable-steps = These steps cannot be read from the journal, and are not in the commands:
report-unreadable = An unfinished transaction is recorded, but its journal cannot be read
report-journal = Journal: { $path }
report-reason = Reason:  { $reason }
report-unreadable-help =
    piko refuses every transaction while the journal is there. The system
    can be partly changed. Read the journal, and check the packages it names.
report-then-remove-it = Then remove it:
report-then-remove-them = Then remove them:
report-interrupted = An unfinished transaction was interrupted
report-root = Root:   { $path }
report-dbpath = DBPath: { $path }
report-progress = { $completed } of { $total } steps completed
report-all-completed = Every step completed; only the journal itself was left behind
report-not-applied = Not applied:
report-install = Install { $package }
report-remove = Remove { $package }
report-cut-installs =
    The interruption can have cut the first installs part-way. Then some of their
    files are on disk with no package that owns them. `--overwrite '*'` applies
    to those packages only, and lets them replace these files.
report-lock-present = The database lock { $path } is still there.
report-lock-held = A running piko or pacman also holds it: remove it only if neither runs.

## Further messages of a transaction.

txn-siglevel-never-hint = set SigLevel = Never in pacman.conf to install without checking signatures
txn-questions-withheld =
    { $count ->
        [one] 1 further provider question not asked; the first candidate was taken
       *[other] { $count } further provider questions not asked; the first candidate was taken
    }
conf-unknown-directive = unknown directive '{ $directive }'
history-bad-time = { $time } is not a time this understands; use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS+ZZZZ
plan-url-not-loaded = cannot plan { $url }: previewing a package URL would have to download it; use `piko install` instead

## Progress rows of a download and of a commit.

progress-downloading = Downloading
progress-downloading-names = Downloading { $names }
progress-downloading-more = Downloading { $names } (+{ $rest })
progress-host-skipped = too many errors from { $host }, skipping it for the rest of this run
progress-downloading-packages = Downloading packages
progress-verifying-signatures = Verifying signatures
progress-verifying-packages = Verifying packages
progress-checking-conflicts = Checking file conflicts
progress-checking-space = Checking available disk space
progress-updating = Updating { $package }
progress-installing = Installing { $package }
progress-removing = Removing { $package }
progress-scriptlet = Running { $kind } script
progress-syncing =
    { $count ->
        [one] Syncing 1 package to disk
       *[other] Syncing { $count } packages to disk
    }
progress-unhashed = could not hash { $path }
progress-pacnew = Installed as { $path } -- merge it
progress-pacsave = Saved { $path } as .pacsave

## Privileges.

privilege-root-and-dbpath = --root and --dbpath

## Dates.

output-timestamp-out-of-range = { $timestamp } (timestamp out of range)

## The words clap writes in --help, in a language other than English. See src/help.rs. clap
## writes the colon after a heading.

cli-help-usage = Usage:
cli-help-commands = Commands
cli-help-options = Options
cli-help-arguments = Arguments
cli-help-print-help = Print help (see more with '--help')
cli-help-print-help-long = Print help (see a summary with '-h')
cli-help-print-version = Print version
cli-help-subcommand = Print this message or the help of the given subcommand(s)
cli-help-subcommand-arg = Print help for the subcommand(s)
cli-help-default = [default: { $value }]
cli-help-aliases =
    { $count ->
        [one] [alias: { $aliases }]
       *[other] [aliases: { $aliases }]
    }

## An error in the command line itself. See src/parse_error.rs. Each English message is clap's
## own text, and a value arrives already styled and quoted where clap quotes it.

cli-clap-error = error:
cli-clap-tip = tip:
cli-clap-unknown-cause = unknown cause
# $flag is the help flag, styled.
cli-clap-try-help = For more information, try '{ $flag }'.
cli-clap-kind-invalid-value = one of the values isn't valid for an argument
cli-clap-kind-unknown-argument = unexpected argument found
cli-clap-kind-invalid-subcommand = unrecognized subcommand
cli-clap-kind-no-equals = equal is needed when assigning values to one of the arguments
cli-clap-kind-value-validation = invalid value for one of the arguments
cli-clap-kind-too-many-values = unexpected value for an argument found
cli-clap-kind-too-few-values = more values required for an argument
cli-clap-kind-wrong-number-of-values = too many or too few values for an argument
cli-clap-kind-argument-conflict = an argument cannot be used with one or more of the other specified arguments
cli-clap-kind-missing-required-argument = one or more required arguments were not provided
cli-clap-kind-missing-subcommand = a subcommand is required but one was not provided
cli-clap-kind-invalid-utf8 = invalid UTF-8 was detected in one or more arguments
cli-clap-used-multiple-times = the argument '{ $arg }' cannot be used multiple times
cli-clap-conflict-one = the argument '{ $arg }' cannot be used with '{ $other }'
# $list is each argument on a line of its own.
cli-clap-conflict-many = the argument '{ $arg }' cannot be used with:{ $list }
cli-clap-conflict-other = the argument '{ $arg }' cannot be used with one or more of the other specified arguments
cli-clap-conflict-none = the argument '{ $arg }' cannot be used with
cli-clap-subcommand-conflict-one = the subcommand '{ $subcommand }' cannot be used with '{ $other }'
cli-clap-subcommand-conflict-many = the subcommand '{ $subcommand }' cannot be used with:{ $list }
cli-clap-subcommand-conflict-other = the subcommand '{ $subcommand }' cannot be used with one or more of the other specified arguments
cli-clap-subcommand-conflict-none = the subcommand '{ $subcommand }' cannot be used with
cli-clap-no-equals = equal sign is needed when assigning values to '{ $arg }'
cli-clap-value-required = a value is required for '{ $arg }' but none was supplied
cli-clap-invalid-value = invalid value '{ $value }' for '{ $arg }'
# $reason is the English text of the value parser.
cli-clap-invalid-value-because = invalid value '{ $value }' for '{ $arg }': { $reason }
# $values is a list, separated by commas.
cli-clap-possible-values = [possible values: { $values }]
cli-clap-subcommands-list = [subcommands: { $values }]
cli-clap-unrecognized-subcommand = unrecognized subcommand '{ $subcommand }'
# $list is each argument on a line of its own.
cli-clap-missing-required = the following required arguments were not provided:{ $list }
cli-clap-missing-subcommand = '{ $subcommand }' requires a subcommand but one was not provided
cli-clap-too-many-values = unexpected value '{ $value }' for '{ $arg }' found; no more were expected
# $actual is $count, styled.
cli-clap-too-few-values =
    { $min } values required by '{ $arg }'; only { $actual } { $count ->
        [0] was
        [one] was
       *[other] were
    } provided
cli-clap-wrong-number-of-values =
    { $expected } values required for '{ $arg }' but { $actual } { $count ->
        [0] was
        [one] was
       *[other] were
    } provided
cli-clap-unexpected-argument = unexpected argument '{ $arg }' found
# $values is each name, quoted and separated by commas.
cli-clap-similar-subcommand =
    { $count ->
        [one] a similar subcommand exists: { $values }
       *[other] some similar subcommands exist: { $values }
    }
cli-clap-similar-argument =
    { $count ->
        [one] a similar argument exists: { $values }
       *[other] some similar arguments exist: { $values }
    }
cli-clap-similar-value =
    { $count ->
        [one] a similar value exists: { $values }
       *[other] some similar values exist: { $values }
    }
cli-resolve-path-failed = failed to resolve path '{ $path }': { $reason }
