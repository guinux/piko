# The errors of piko-net, the downloads and the database refresh.
#
# A $file is a file name, a $url a URL with no user information, and a $reason English text the
# library, a server or the download helper wrote.

# $list is one server per line.
net-error-all-servers-failed =
    could not download { $file } from any of { $count ->
        [one] 1 server
       *[other] { $count } servers
    }:
    {"  "}{ $list }
net-attempt = { $url }: { $reason }
net-error-no-servers = repository { $repo } has no Server configured
net-error-keyring-unusable = a repository's SigLevel requires a signature check, and the keyring cannot be used
net-error-duplicate-target = { $file } was listed more than once in a single batch
net-error-wrong-lock = the lock at { $lock } does not belong to the database that holds { $sync_dir }
net-error-too-large = { $file } exceeds the { $max } byte download limit
net-error-larger-than-declared = { $file } is larger than the { $declared } bytes its repository declares
net-error-empty-download = the download of { $file } was empty (nothing was written)
# $reason is a sig-rejection message.
net-error-signature-rejected = the downloaded { $file } was rejected: { $reason } (the existing database is unchanged)
# $reason is a net-uncheckable message or a sig-error message.
net-error-signature-uncheckable = cannot check the signature of the downloaded { $file }: { $reason }
net-error-io-download = failed to download { $path }
net-error-io-create = failed to create { $path }
net-error-io-read-download = failed to read the download of { $path }
net-error-io-write-download = failed to write the download of { $path }
net-error-cancelled = the download was cancelled
net-error-sandbox = the download sandbox failed: { $reason }

# Why the signature of a downloaded database could not be checked. $reason is what the download
# helper reported, in English.
net-uncheckable-unreachable = could not fetch { $url }: { $reason }
net-uncheckable-status = { $url } answered HTTP { $status } rather than 200
net-uncheckable-empty = { $url } returned an empty signature
net-uncheckable-no-keyring = the policy requires a signature but no keyring was given

# Two lines of a list.
net-join-lines =
    { $head }
    {"  "}{ $tail }
