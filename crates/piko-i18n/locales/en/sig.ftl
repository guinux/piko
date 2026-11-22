# The errors of piko-sig and piko-sig-write, and why a signature is refused.

sig-error-keyring-unusable = the keyring at { $home } cannot be used: { $reason }
# $action is a sig-op or sig-admin-op message, and $message what GnuPG said, in English.
sig-error-gpgme = failed to { $action } { $path }: { $message }
sig-error-no-master-key = the keyring at { $home } has no piko master key; run `piko key init` first
sig-error-key-not-found = the key { $keyid } is not in the keyring at { $home }
sig-error-secret-key-refused = the key { $keyid } in the keyring at { $home } has a secret key; pass --secret to delete it too
sig-error-populate-file = failed to use keyring file { $path }: { $reason }

# Why a signature is refused. $key is a fingerprint, or sig-unnamed-key.
sig-unnamed-key = an unnamed key
sig-rejection-missing-required = it is not signed
sig-rejection-marginal-trust = the signature from { $key } is only marginally trusted
sig-rejection-unknown-trust = the signature from { $key } is of unknown trust
sig-rejection-never-trust = the signature from { $key } must never be trusted
sig-rejection-signature-expired = the signature has expired
sig-rejection-key-unknown = the signing key { $key } is not in the keyring
sig-rejection-key-disabled = the signing key { $key } is disabled
sig-rejection-key-revoked = the signing key { $key } has been revoked
# $algorithm is the name of a digest or of a key algorithm.
sig-rejection-weak-digest = the signature from { $key } uses the weak digest { $algorithm }
sig-rejection-weak-key = the signing key { $key } is a { $bits }-bit { $algorithm } key, which is too weak
sig-rejection-invalid = the signature is invalid

# A GnuPG operation that failed, as a verb phrase: "failed to { $action } { $path }".
sig-op-read-signature = read the signature
sig-op-read-signature-of = read the signature of
sig-op-read-signed-file = read the signed file
sig-op-verify = verify
sig-op-look-up-signing-key = look up the signing key of

sig-admin-op-allocate-buffer = allocate a scratch buffer
sig-admin-op-create-conf-file = create a keyring configuration file
sig-admin-op-create-keyring-file = create a keyring file
sig-admin-op-create-keyring-dir = create the keyring directory
sig-admin-op-delete = delete
sig-admin-op-disable = disable
sig-admin-op-generate-master-key = generate the master key
sig-admin-op-import = import
sig-admin-op-list-keys = list keys in
sig-admin-op-locally-sign = locally sign
sig-admin-op-open-conf-file = open a keyring configuration file
sig-admin-op-open-keyring = open the keyring
sig-admin-op-read = read
sig-admin-op-read-key = read a key from
sig-admin-op-read-conf-file = read a keyring configuration file
sig-admin-op-read-fingerprint = read the fingerprint of
sig-admin-op-remove-master-key-expiry = remove the master key's expiry date
sig-admin-op-search-master-key = search for the master key
sig-admin-op-select-signer = select the master key as signer
sig-admin-op-set-conf-file-mode = set a keyring configuration file's permissions
sig-admin-op-set-keyring-file-mode = set a keyring file's permissions
sig-admin-op-set-key-list-mode = set key list mode for
sig-admin-op-set-ownertrust-level = set ownertrust
sig-admin-op-set-ownertrust = set ownertrust on
sig-admin-op-set-keyring-dir-mode = set the keyring directory's permissions
sig-admin-op-set-trust-db-mode = set the trust database's permissions
sig-admin-op-use-keyring-file = use a keyring file
sig-admin-op-write-conf-file = write a keyring configuration file
