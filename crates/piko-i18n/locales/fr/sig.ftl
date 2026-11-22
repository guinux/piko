# Les erreurs de piko-sig et de piko-sig-write, et le refus d'une signature.
#
# Une espace insécable (U+00A0) précède le deux-points et le point-virgule.

sig-error-keyring-unusable = le trousseau { $home } est inutilisable{" "}: { $reason }
sig-error-gpgme = impossible de { $action } { $path }{" "}: { $message }
sig-error-no-master-key = le trousseau { $home } n'a pas de clé maîtresse piko{" "}; lancez d'abord `piko key init`
sig-error-key-not-found = la clé { $keyid } n'est pas dans le trousseau { $home }
sig-error-secret-key-refused = la clé { $keyid } du trousseau { $home } a une clé secrète{" "}; ajoutez --secret pour la supprimer aussi
sig-error-populate-file = impossible d'utiliser le fichier de trousseau { $path }{" "}: { $reason }

sig-unnamed-key = une clé sans nom
sig-rejection-missing-required = il n'est pas signé
sig-rejection-marginal-trust = la signature de { $key } n'a qu'une confiance marginale
sig-rejection-unknown-trust = la signature de { $key } a une confiance inconnue
sig-rejection-never-trust = la signature de { $key } ne doit jamais être acceptée
sig-rejection-signature-expired = la signature a expiré
sig-rejection-key-unknown = la clé de signature { $key } n'est pas dans le trousseau
sig-rejection-key-disabled = la clé de signature { $key } est désactivée
sig-rejection-key-revoked = la clé de signature { $key } a été révoquée
sig-rejection-weak-digest = la signature de { $key } utilise l'empreinte faible { $algorithm }
sig-rejection-weak-key = la clé de signature { $key } est une clé { $algorithm } de { $bits } bits, trop faible
sig-rejection-invalid = la signature est invalide

sig-op-read-signature = lire la signature
sig-op-read-signature-of = lire la signature de
sig-op-read-signed-file = lire le fichier signé
sig-op-verify = vérifier
sig-op-look-up-signing-key = chercher la clé de signature de

sig-admin-op-allocate-buffer = allouer un tampon de travail
sig-admin-op-create-conf-file = créer un fichier de configuration du trousseau
sig-admin-op-create-keyring-file = créer un fichier du trousseau
sig-admin-op-create-keyring-dir = créer le répertoire du trousseau
sig-admin-op-delete = supprimer
sig-admin-op-disable = désactiver
sig-admin-op-generate-master-key = générer la clé maîtresse
sig-admin-op-import = importer
sig-admin-op-list-keys = lister les clés de
sig-admin-op-locally-sign = signer localement
sig-admin-op-open-conf-file = ouvrir un fichier de configuration du trousseau
sig-admin-op-open-keyring = ouvrir le trousseau
sig-admin-op-read = lire
sig-admin-op-read-key = lire une clé de
sig-admin-op-read-conf-file = lire un fichier de configuration du trousseau
sig-admin-op-read-fingerprint = lire l'empreinte de
sig-admin-op-remove-master-key-expiry = retirer la date d'expiration de la clé maîtresse
sig-admin-op-search-master-key = chercher la clé maîtresse
sig-admin-op-select-signer = choisir la clé maîtresse pour signer
sig-admin-op-set-conf-file-mode = changer les droits d'un fichier de configuration du trousseau
sig-admin-op-set-keyring-file-mode = changer les droits d'un fichier du trousseau
sig-admin-op-set-key-list-mode = choisir le mode de listage des clés de
sig-admin-op-set-ownertrust-level = fixer la confiance
sig-admin-op-set-ownertrust = fixer la confiance de
sig-admin-op-set-keyring-dir-mode = changer les droits du répertoire du trousseau
sig-admin-op-set-trust-db-mode = changer les droits de la base de confiance
sig-admin-op-use-keyring-file = utiliser un fichier du trousseau
sig-admin-op-write-conf-file = écrire un fichier de configuration du trousseau
