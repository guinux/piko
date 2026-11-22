# The errors of the database readers (`piko_db::Error` and the types it quotes).
#
# English is the source language. Each message renders exactly as the `Display` of the error,
# and `piko-db`'s tests compare the two.


## Reading a file.

db-error-io-open = failed to open { $path }
db-error-io-read = failed to read { $path }
db-error-io-stat = failed to stat { $path }
db-error-io-read-dir = failed to list directory { $path }
db-error-io-decompress = failed to decompress { $path }
db-error-limit-exceeded = { $path } exceeds the { $limit } size limit of { $max } bytes
db-error-untrusted = refusing { $path }: { $distrust }, so another user could change it
db-error-not-a-regular-file = { $path } is not a regular file
db-error-not-utf8 = { $path } is not valid UTF-8
db-error-parse = failed to parse { $path }
db-error-desc-fields = failed to read { $path }
db-error-quoted = { $text }

## The bounds of a read.

db-error-too-many-entries = database at { $path } has more than { $max } entries
db-error-too-many-relations = repository archive { $path } has more than { $max } relation entries
db-error-too-many-paths = repository archive { $path } has more than { $max } file-list paths
db-error-too-many-entry-paths = the files member of { $entry } in { $path } has more than { $max } lines

## Planning.

db-error-too-many-solvables = planning would consider more than { $max } candidate packages
db-error-too-many-clauses = planning would emit more than { $max } clauses
db-error-solve-budget-exhausted = dependency solving gave up after { $max } conflicts
db-error-solve-inconsistent = dependency solving produced a selection that breaks clause { $clause }; this is a bug
db-error-plan-local-desc = cannot plan: failed to read the installed package { $name }
db-error-update-local-desc = failed to read the installed package { $name }
db-error-plan-repo-depends = cannot plan: failed to read the dependencies of { $name }

## Package files and repository archives.

db-error-repo-desc-fields = failed to read the dependencies of { $package }
db-error-invalid-verify-root = { $path } is not usable as an installation root
db-error-unsafe-mtree-path = { $mtree } lists { $entry }, which is not beneath the installation root
db-error-archive-name = { $path } is not named <repo>.db or <repo>.files
db-error-unsupported-compression = { $path } uses { $format }; piko reads gzip, zstd and uncompressed archives only
db-error-files-unavailable = { $repo } has no { $repo }.files sibling archive; file lists are unavailable
db-error-repo-desc-unparsable = { $entry }: failed to read desc
db-error-files-missing = { $name } is not present in the .files archive
db-error-files-version-skew = { $name } is at { $db_version } in the database but { $files_version } in the .files archive; refusing to serve a file list from a different build
db-error-foreign-package = { $name } was not opened as part of this database

## Configuration files. pacman spells these as conf.c does.

db-error-config-outside-section = { $path } line { $line }: directive must belong to a section
db-error-config-invalid-value = { $path } line { $line }: invalid value for '{ $directive }': '{ $value }' ({ $reason })
db-error-config-path-unresolved = { $path } line { $line }: failed to resolve path '{ $value }' passed to '{ $directive }': { $reason }
db-error-config-include-depth = { $path } line { $line }: Include exceeded the maximum recursion depth of 10
db-error-config-invalid-repo-name = { $path } line { $line }: '{ $name }' is not a valid repository name

## The schema version of the local database.

db-schema-missing = { $path } does not contain an ALPM_DB_VERSION file
db-schema-malformed = ALPM_DB_VERSION contains { $contents }, which is not a version number
db-schema-unsupported = database schema version is { $found }, but piko implements version { $expected }; run pacman-db-upgrade or use a matching piko release

## Repository names.

db-repo-name-empty = a repository name must be at least one character long
db-repo-name-disallowed = repository name { $name } contains the disallowed character { $found }
db-repo-name-leading-dash = repository name { $name } must not start with '-'

## Why a file is not trusted. Shown after "refusing <path>:".

db-distrust-foreign-owner = owned by user { $uid }
db-distrust-writable = writable by its group or others (mode { $mode })

## The name of a size limit. Shown inside "exceeds the <limit> size limit".

db-limit-desc = desc
db-limit-files = files
db-limit-mtree-compressed = compressed mtree
db-limit-mtree-inflated = inflated mtree
db-limit-schema-version = schema version file
db-limit-repo-compressed = compressed repository archive
db-limit-repo-inflated = inflated repository archive
db-limit-repo-entry = repository archive member
db-limit-repo-extension = repository archive extension header
db-limit-pacman-conf = pacman.conf file
db-limit-hook = hook file
db-limit-mount-table = mount table
db-limit-journal = transaction journal
db-limit-keyring-list = keyring trust list
db-limit-time-zone = time zone file

## A compression format piko does not read. Shown after "<path> uses".

db-compression-xz = xz compression
db-compression-bzip2 = bzip2 compression
db-compression-compress = compress (.Z) compression
db-compression-lrzip = lrzip compression
db-compression-lz4 = lz4 compression
db-compression-lzip = lzip compression
db-compression-lzop = lzop compression
db-compression-unrecognized = an unrecognized format
