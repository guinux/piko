# Les erreurs de piko-txn, le moteur de transaction.
#
# Une espace insécable (U+00A0) précède le deux-points et le point-virgule.

## Une opération de fichier qui a échoué.

txn-error-io-stat = impossible d'examiner { $path }
txn-error-io-open = impossible d'ouvrir { $path }
txn-error-io-read = impossible de lire { $path }
txn-error-io-create-dir = impossible de créer le répertoire { $path }
txn-error-io-decompress = impossible de décompresser { $path }
txn-error-io-create = impossible de créer { $path }
txn-error-io-write = impossible d'écrire { $path }
txn-error-io-remove = impossible de supprimer { $path }
txn-error-io-rename = impossible de renommer vers { $path }
txn-error-io-sync = impossible d'écrire sur le disque { $path }
txn-error-io-chown = impossible de changer le propriétaire de { $path }

## Les erreurs.

txn-error-not-available = { $file_name } n'est disponible dans aucune source configurée (recherché dans { $searched })
txn-error-not-available-rejected = { $file_name } n'est disponible dans aucune source configurée (recherché dans { $searched }{" "}; écarté{" "}: { $rejected })
txn-error-unsupported-member-type = { $path }{" "}: { $member } est { $kind }{" "}; piko n'installe que des fichiers ordinaires, des répertoires et des liens
txn-error-hard-link-outside-package = { $path }{" "}: le lien physique { $member } désigne { $target }, qui n'est pas un membre précédent du paquet
txn-error-unusable-member-owner = { $member } appartient à { $uid }:{ $gid }, qui n'est pas un identifiant d'utilisateur et de groupe que piko peut attribuer
txn-error-unsafe-archive-path = { $path } n'est pas un chemin sûr à extraire{" "}: { $reason }
txn-error-path-escapes-root = { $path } serait extrait hors de la racine d'installation{" "}: { $component } — { $reason }
txn-error-package-limit-exceeded = { $path } dépasse la limite de { $limit } ({ $max })
txn-error-unsupported-compression = { $path } utilise { $format }{" "}; piko ne lit que les paquets gzip, zstd et non compressés
txn-error-unsupported-package-compression = impossible d'installer { $packages }{" "}: piko ne lit que les paquets gzip, zstd et non compressés
txn-error-extraction-refused = impossible d'extraire { $path }{" "}: { $reason }
txn-error-file-conflicts =
    la transaction écraserait { $count ->
        [one] 1 fichier qui ne lui appartient pas
       *[other] { $count } fichiers qui ne lui appartiennent pas
    }{" "}:
    {"  "}{ $list }
txn-error-unreadable-entry = l'entrée installée { $entry } est illisible{" "}: { $reason }
txn-error-hook-aborted = la transaction a été arrêtée par le hook { $hook }, qui définit AbortOnFail{" "}: il { $reason }{ $output }
txn-error-hooks-unusable = la transaction n'a pas commencé, car les hooks PreTransaction n'ont pas tous pu être lus{" "}:{ $problems }
txn-error-cancelled =
    la transaction a été annulée après { $completed ->
        [one] { $completed } étape
       *[other] { $completed } étapes
    } sur { $total }
txn-error-signature-rejected = { $package }{" "}: { $reason }{ $discarded }
txn-error-signature-uncheckable = impossible de vérifier la signature de { $package }{" "}: { $reason }
txn-error-checksum-mismatch = { $package }{" "}: son SHA-256 est { $found }, mais la base de données du dépôt publie { $published }{ $discarded }
txn-error-local-database-unreadable = impossible d'ouvrir la base locale { $path }
txn-error-disk-space =
    la transaction ne tient pas{" "}:
    {"  "}{ $list }
txn-error-mount-table-unreadable = la table des montages { $path } est inutilisable{" "}: { $reason }
txn-error-no-writable-cache-dir = aucun répertoire de cache configuré n'est accessible en écriture ({ $rejected })
txn-error-plan-stale = { $name } a changé depuis le plan{" "}: le plan prévoit { $planned }, et { $installed } est installé{" "}; refaites le plan
txn-error-plan-stale-nothing-installed = { $name } a changé depuis le plan{" "}: le plan prévoit { $planned }, et rien n'est installé{" "}; refaites le plan
txn-stale-not-installed = qu'il ne soit pas installé
txn-error-unusable-source = { $path } n'est pas une source de paquets utilisable{" "}: { $reason }
txn-error-plan-inconsistent = le plan nomme un paquet que l'univers ne connaît pas (id { $id }) — c'est un bogue
txn-error-not-a-removal = le plan de suppression contient une étape qui n'est pas une suppression
txn-error-no-repository-candidate = { $name } n'a aucun candidat de dépôt à installer — c'est un bogue
txn-error-repository-package-unreadable = impossible de lire { $name } depuis son dépôt
txn-error-wrong-architecture = non construit pour { $configured }{" "}: { $packages }
txn-error-duplicate-target = { $package } est nommé deux fois{" "}: { $first } et { $second }
txn-error-invalid-package-url = impossible de télécharger { $url }{" "}: { $reason }
txn-error-url-not-loaded = impossible de lire { $url } sans le télécharger
txn-error-keyring-unusable = impossible d'ouvrir le trousseau GnuPG { $path }
txn-error-journal-unreadable = { $path } enregistre une transaction illisible{" "}: { $reason }
txn-error-unconfigured-source = { $package } n'a aucune source configurée{" "}: { $reason }
txn-error-unfinished-transaction = { $path } enregistre une transaction inachevée
txn-error-empty-owner-target = une recherche de propriétaire demande un chemin, et a reçu une chaîne vide
txn-error-quoted = { $text }

## Les parties d'un message.

txn-join-comma = { $head }, { $tail }
txn-join-semicolon = { $head }{" "}; { $tail }
txn-join-or = { $head } ou { $tail }
txn-join-lines =
    { $head }
    {"  "}{ $tail }
txn-more = ... et { $count } de plus

txn-skipped = { $path } ({ $reason })
txn-skip-not-a-regular-file = pas un fichier ordinaire
txn-skip-unreadable = illisible
txn-skip-symbolic-link = un lien symbolique
txn-untrusted = non fiable{" "}: { $path }, { $distrust }

txn-rejected-cache-dir = répertoire de cache { $path } ignoré ({ $reason })
txn-rejection-not-a-directory = pas un répertoire
txn-rejection-not-writable = pas accessible en écriture
txn-rejection-no-write-bits = aucun droit d'écriture
txn-rejection-create-failed = création impossible{" "}: { $kind }
txn-rejection-untestable = son chemin n'a pas pu être vérifié

txn-unsafe-absolute = le chemin est absolu
txn-unsafe-parent-traversal = le chemin contient un composant '..'
txn-unsafe-current-directory = le chemin contient un composant '.' ou un séparateur répété
txn-unsafe-empty = le chemin est vide
txn-unsafe-blank = le chemin n'est fait que d'espaces
txn-unsafe-invalid-component = un composant n'est pas un nom de fichier utilisable
txn-unsafe-not-utf8 = le chemin n'est pas du texte UTF-8

txn-refuse-directory-in-the-way = un répertoire est sur le chemin

txn-file-conflict = { $package }{" "}: { $path } ({ $blocker })
txn-blocker-target = aussi dans { $other }
txn-blocker-owned = appartient à { $owner }
txn-blocker-exists = existe dans le système de fichiers
txn-blocker-unreachable = inaccessible{" "}: { $component } { $reason }

txn-partition-space = { $mount_point } demande { $needed }{" "}Mio, { $free }{" "}Mio libres
txn-read-only = { $path } est monté en lecture seule

txn-journal-not-text = ce n'est pas du texte
txn-journal-no-header = il n'a pas d'en-tête `piko-journal`
txn-journal-unknown-version = il utilise la version de format { $version }, et cette version de piko ne lit que la { $supported }
txn-journal-not-a-regular-file = ce n'est pas un fichier ordinaire
txn-journal-too-large = il est plus grand qu'un journal ne peut l'être

txn-member-character-device = un périphérique caractère
txn-member-block-device = un périphérique bloc
txn-member-fifo = un tube nommé (FIFO)
txn-member-contiguous-file = un fichier contigu
txn-member-gnu-sparse-file = un fichier creux GNU
txn-member-pax-global-header = un en-tête global pax
txn-member-unknown = un membre de type inconnu

txn-obstacle-symlink = c'est un lien symbolique
txn-obstacle-not-a-directory = ce n'est pas un répertoire
txn-obstacle-unexaminable = il n'a pas pu être examiné

txn-limit-compressed-size = taille compressée
txn-limit-inflated-size = taille décompressée
txn-limit-declared-size = taille installée que le plan déclare
txn-limit-member-count = nombre de membres
txn-limit-xattr-count = nombre d'attributs étendus
txn-limit-xattr-size = taille des attributs étendus
txn-limit-scriptlet-size = taille du scriptlet
txn-limit-pkginfo-size = taille du .PKGINFO
txn-limit-merge-base-size = taille de la base de fusion
txn-limit-backup-file-size = taille du fichier sauvegardé
txn-limit-signature-size = taille de la signature

txn-refusal-not-base64 = la signature que publie la base de données du dépôt n'est pas en base64{" "}: { $reason }

txn-discarded-no = {""}
txn-discarded-removed = {" "}; il a été retiré du cache, et la prochaine exécution le téléchargera à nouveau
txn-discarded-failed = {" "}; il n'a pas pu être retiré du cache{" "}: { $reason }

txn-name-format = { $name } ({ $format })
