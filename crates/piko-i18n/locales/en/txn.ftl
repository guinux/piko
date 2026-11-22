# The errors of piko-txn, the commit engine.
#
# A $path, a $member, a $package and a $reason are escaped by the library before they reach
# a message. A $reason is English text the library wrote, or text a hook or a server wrote.

## A filesystem operation that failed.

txn-error-io-stat = failed to stat { $path }
txn-error-io-open = failed to open { $path }
txn-error-io-read = failed to read { $path }
txn-error-io-create-dir = failed to create directory { $path }
txn-error-io-decompress = failed to decompress { $path }
txn-error-io-create = failed to create { $path }
txn-error-io-write = failed to write { $path }
txn-error-io-remove = failed to remove { $path }
txn-error-io-rename = failed to rename onto { $path }
txn-error-io-sync = failed to flush to disk { $path }
txn-error-io-chown = failed to change ownership of { $path }

## The errors.

# $searched is a list of directories, separated by commas.
txn-error-not-available = { $file_name } is not available from any configured source (searched { $searched })
txn-error-not-available-rejected = { $file_name } is not available from any configured source (searched { $searched }; rejected { $rejected })
# $kind is a txn-member message.
txn-error-unsupported-member-type = { $path }: { $member } is a { $kind }; piko installs regular files, directories and links only
txn-error-hard-link-outside-package = { $path }: the hard link { $member } names { $target }, which is not an earlier member of the package
txn-error-unusable-member-owner = { $member } is owned by { $uid }:{ $gid }, which is not a user and group id piko can set
txn-error-unsafe-archive-path = { $path } is not a safe path to extract: { $reason }
# $reason is a txn-obstacle message.
txn-error-path-escapes-root = { $path } would be extracted outside the installation root: { $component } — { $reason }
# $limit is a txn-limit message.
txn-error-package-limit-exceeded = { $path } exceeds the { $limit } limit of { $max }
txn-error-unsupported-compression = { $path } uses { $format }; piko reads gzip, zstd and uncompressed packages only
txn-error-unsupported-package-compression = cannot install { $packages }: piko reads gzip, zstd and uncompressed packages only
txn-error-extraction-refused = cannot extract { $path }: { $reason }
# $list is one conflict per line.
txn-error-file-conflicts =
    the transaction would overwrite { $count ->
        [one] 1 file
       *[other] { $count } files
    } it does not own:
    {"  "}{ $list }
txn-error-unreadable-entry = the installed entry { $entry } cannot be read: { $reason }
# $output is empty, or what the hook printed, each line on a line of its own.
txn-error-hook-aborted = the transaction was stopped by the hook { $hook }, which sets AbortOnFail: it { $reason }{ $output }
# $problems is each problem on a line of its own.
txn-error-hooks-unusable = the transaction was not started, because the PreTransaction hooks could not all be read:{ $problems }
txn-error-cancelled = the transaction was cancelled after { $completed } of { $total } steps
# $reason is a sig-rejection message or txn-refusal-not-base64, and $discarded is a
# txn-discarded message.
txn-error-signature-rejected = { $package }: { $reason }{ $discarded }
# $reason is a sig-error message.
txn-error-signature-uncheckable = cannot check the signature of { $package }: { $reason }
# $found and $published are SHA-256 digests, in hexadecimal.
txn-error-checksum-mismatch = { $package }: its SHA-256 is { $found }, but the repository database publishes { $published }{ $discarded }
txn-error-local-database-unreadable = the local database at { $path } cannot be opened
# $list is one filesystem per line.
txn-error-disk-space =
    the transaction does not fit:
    {"  "}{ $list }
txn-error-mount-table-unreadable = the mount table at { $path } cannot be used: { $reason }
txn-error-no-writable-cache-dir = no configured cache directory can be written into ({ $rejected })
# $planned is a package entry, as name-version, or txn-stale-not-installed.
txn-error-plan-stale = { $name } changed since the plan: the plan expects { $planned }, and { $installed } is installed; plan again
txn-error-plan-stale-nothing-installed = { $name } changed since the plan: the plan expects { $planned }, and nothing is installed; plan again
txn-stale-not-installed = it not to be installed
txn-error-unusable-source = { $path } is not a usable package source: { $reason }
txn-error-plan-inconsistent = the plan names a package the universe does not know (id { $id }) — this is a bug
txn-error-not-a-removal = the removal plan contains a step that is not a removal
txn-error-no-repository-candidate = { $name } has no repository candidate to install from — this is a bug
txn-error-repository-package-unreadable = { $name } could not be read from its repository
# $packages is a list of "name (architecture)", separated by commas.
txn-error-wrong-architecture = not built for { $configured }: { $packages }
txn-error-duplicate-target = { $package } is named twice: { $first } and { $second }
txn-error-invalid-package-url = cannot fetch { $url }: { $reason }
txn-error-url-not-loaded = cannot read { $url } without downloading it
txn-error-keyring-unusable = cannot open the GnuPG keyring at { $path }
txn-error-journal-unreadable = { $path } records a transaction that cannot be read: { $reason }
txn-error-unconfigured-source = { $package } has no configured source: { $reason }
txn-error-unfinished-transaction = { $path } records an unfinished transaction
txn-error-empty-owner-target = an owner query needs a path, and was given an empty string
# A text quoted as it is: an architecture.
txn-error-quoted = { $text }

## The parts of a message.

# Two items of a list.
txn-join-comma = { $head }, { $tail }
txn-join-semicolon = { $head }; { $tail }
txn-join-or = { $head } or { $tail }
txn-join-lines =
    { $head }
    {"  "}{ $tail }
txn-more = ... and { $count } more

# Why a cached package file was not used.
txn-skipped = { $path } ({ $reason })
txn-skip-not-a-regular-file = not a regular file
txn-skip-unreadable = unreadable
txn-skip-symbolic-link = a symbolic link
# $distrust is a db-distrust message.
txn-untrusted = untrusted: { $path } is { $distrust }

# Why a cache directory cannot receive a download.
txn-rejected-cache-dir = skipping cache directory { $path } ({ $reason })
txn-rejection-not-a-directory = not a directory
txn-rejection-not-writable = not writable
txn-rejection-no-write-bits = no write bits set
# $kind is the error of the system, in English.
txn-rejection-create-failed = could not be created: { $kind }
txn-rejection-untestable = its path could not be tested

# Why an archive path was refused.
txn-unsafe-absolute = the path is absolute
txn-unsafe-parent-traversal = the path contains a '..' component
txn-unsafe-current-directory = the path contains a '.' component or a repeated separator
txn-unsafe-empty = the path is empty
txn-unsafe-blank = the path is made of white space only
txn-unsafe-invalid-component = a component is not a usable file name
txn-unsafe-not-utf8 = the path is not UTF-8 text

# Why an archive member cannot be extracted.
txn-refuse-directory-in-the-way = a directory is in the way

# A path a transaction cannot write, and what is in the way.
txn-file-conflict = { $package }: { $path } ({ $blocker })
txn-blocker-target = also in { $other }
txn-blocker-owned = owned by { $owner }
txn-blocker-exists = exists in filesystem
# $reason is a txn-obstacle message.
txn-blocker-unreachable = cannot be reached: { $component } { $reason }

# A filesystem that cannot hold the transaction.
txn-partition-space = { $mount_point } needs { $needed } MiB, { $free } MiB free
txn-read-only = { $path } is mounted read only

# Why a journal file cannot be read.
txn-journal-not-text = it is not text
txn-journal-no-header = it has no `piko-journal` header
txn-journal-unknown-version = it uses format version { $version }, and this build reads only { $supported }
txn-journal-not-a-regular-file = it is not a regular file
txn-journal-too-large = it is larger than a journal can be

# The type of a tar member piko does not extract.
txn-member-character-device = character device
txn-member-block-device = block device
txn-member-fifo = FIFO
txn-member-contiguous-file = contiguous file
txn-member-gnu-sparse-file = GNU sparse file
txn-member-pax-global-header = pax global header
txn-member-unknown = member of an unknown type

# What a path component is, when a walk inside the installation root cannot go through it.
txn-obstacle-symlink = it is a symlink
txn-obstacle-not-a-directory = it is not a directory
txn-obstacle-unexaminable = it could not be examined

# A bound on what one package may hold.
txn-limit-compressed-size = compressed size
txn-limit-inflated-size = inflated size
txn-limit-declared-size = installed size the plan declares
txn-limit-member-count = member count
txn-limit-xattr-count = extended attribute count
txn-limit-xattr-size = extended attribute size
txn-limit-scriptlet-size = scriptlet size
txn-limit-pkginfo-size = .PKGINFO size
txn-limit-merge-base-size = merge base size
txn-limit-backup-file-size = backup file size
txn-limit-signature-size = signature size

# Why a package signature was refused, when no signature rule refused it.
txn-refusal-not-base64 = the repository database's signature is not base64: { $reason }

# What became of a refused package file in the cache: a clause added at the end of the
# refusal, or nothing.
txn-discarded-no = {""}
txn-discarded-removed = ; it was removed from the cache, so the next run downloads it again
txn-discarded-failed = ; it could not be removed from the cache: { $reason }

# A package file and the compression its name declares.
txn-name-format = { $name } ({ $format })
