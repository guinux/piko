# Les erreurs des lecteurs de bases (`piko_db::Error` et les types qu'elle cite).
#
# Une espace insécable (U+00A0) précède le deux-points et le point-virgule.


## Lecture d'un fichier.

db-error-io-open = impossible d'ouvrir { $path }
db-error-io-read = impossible de lire { $path }
db-error-io-stat = impossible d'examiner { $path }
db-error-io-read-dir = impossible de lister le répertoire { $path }
db-error-io-decompress = impossible de décompresser { $path }
db-error-limit-exceeded = { $path } dépasse la limite de taille de { $limit } ({ $max } octets)
db-error-untrusted = { $path } est refusé{"\u00A0"}: { $distrust }, un autre utilisateur pourrait donc le modifier
db-error-not-a-regular-file = { $path } n'est pas un fichier ordinaire
db-error-not-utf8 = { $path } n'est pas de l'UTF-8 valide
db-error-parse = impossible d'analyser { $path }
db-error-desc-fields = impossible de lire { $path }
db-error-quoted = { $text }

## Les limites d'une lecture.

db-error-too-many-entries = la base { $path } a plus de { $max } entrées
db-error-too-many-relations = l'archive de dépôt { $path } a plus de { $max } relations
db-error-too-many-paths = l'archive de dépôt { $path } a plus de { $max } chemins de liste de fichiers
db-error-too-many-entry-paths = le membre files de { $entry } dans { $path } a plus de { $max } lignes

## Planification.

db-error-too-many-solvables = la planification examinerait plus de { $max } paquets candidats
db-error-too-many-clauses = la planification produirait plus de { $max } clauses
db-error-solve-budget-exhausted = la résolution des dépendances a abandonné après { $max } conflits
db-error-solve-inconsistent = la résolution des dépendances a produit une sélection qui viole la clause { $clause }{"\u00A0"}; ceci est un bogue
db-error-plan-local-desc = planification impossible{"\u00A0"}: impossible de lire le paquet installé { $name }
db-error-update-local-desc = impossible de lire le paquet installé { $name }
db-error-plan-repo-depends = planification impossible{"\u00A0"}: impossible de lire les dépendances de { $name }

## Fichiers de paquets et archives de dépôts.

db-error-repo-desc-fields = impossible de lire les dépendances de { $package }
db-error-invalid-verify-root = { $path } n'est pas utilisable comme racine d'installation
db-error-unsafe-mtree-path = { $mtree } liste { $entry }, qui n'est pas sous la racine d'installation
db-error-archive-name = { $path } n'est pas nommé <repo>.db ou <repo>.files
db-error-unsupported-compression = { $path } utilise { $format }{"\u00A0"}; piko ne lit que les archives gzip, zstd et non compressées
db-error-files-unavailable = { $repo } n'a pas d'archive { $repo }.files à côté{"\u00A0"}; les listes de fichiers sont indisponibles
db-error-repo-desc-unparsable = { $entry }{"\u00A0"}: impossible de lire desc
db-error-files-missing = { $name } n'est pas présent dans l'archive .files
db-error-files-version-skew = { $name } est en { $db_version } dans la base mais en { $files_version } dans l'archive .files{"\u00A0"}; refus de fournir la liste de fichiers d'une autre construction
db-error-foreign-package = { $name } n'a pas été ouvert avec cette base

## Fichiers de configuration.

db-error-config-outside-section = { $path } ligne { $line }{"\u00A0"}: une directive doit appartenir à une section
db-error-config-invalid-value = { $path } ligne { $line }{"\u00A0"}: valeur invalide pour '{ $directive }'{"\u00A0"}: '{ $value }' ({ $reason })
db-error-config-path-unresolved = { $path } ligne { $line }{"\u00A0"}: impossible de résoudre le chemin '{ $value }' passé à '{ $directive }'{"\u00A0"}: { $reason }
db-error-config-include-depth = { $path } ligne { $line }{"\u00A0"}: Include dépasse la profondeur maximale de 10
db-error-config-invalid-repo-name = { $path } ligne { $line }{"\u00A0"}: '{ $name }' n'est pas un nom de dépôt valide

## La version du schéma de la base locale.

db-schema-missing = { $path } ne contient pas de fichier ALPM_DB_VERSION
db-schema-malformed = ALPM_DB_VERSION contient { $contents }, qui n'est pas un numéro de version
db-schema-unsupported = la version du schéma de la base est { $found }, mais piko implémente la version { $expected }{"\u00A0"}; lancez pacman-db-upgrade ou utilisez une version de piko adaptée

## Noms de dépôts.

db-repo-name-empty = un nom de dépôt doit comporter au moins un caractère
db-repo-name-disallowed = le nom de dépôt { $name } contient le caractère interdit { $found }
db-repo-name-leading-dash = le nom de dépôt { $name } ne doit pas commencer par '-'

## Pourquoi un fichier n'est pas digne de confiance.

db-distrust-foreign-owner = il appartient à l'utilisateur { $uid }
db-distrust-writable = son groupe ou les autres peuvent y écrire (mode { $mode })

## Le nom d'une limite de taille.

db-limit-desc = desc
db-limit-files = files
db-limit-mtree-compressed = mtree compressé
db-limit-mtree-inflated = mtree décompressé
db-limit-schema-version = fichier de version du schéma
db-limit-repo-compressed = archive de dépôt compressée
db-limit-repo-inflated = archive de dépôt décompressée
db-limit-repo-entry = membre d'archive de dépôt
db-limit-repo-extension = en-tête d'extension d'archive de dépôt
db-limit-pacman-conf = fichier pacman.conf
db-limit-hook = fichier de hook
db-limit-mount-table = table des montages
db-limit-journal = journal de transaction
db-limit-keyring-list = liste de confiance du trousseau
db-limit-time-zone = fichier de fuseau horaire

## Un format de compression que piko ne lit pas.

db-compression-xz = la compression xz
db-compression-bzip2 = la compression bzip2
db-compression-compress = la compression compress (.Z)
db-compression-lrzip = la compression lrzip
db-compression-lz4 = la compression lz4
db-compression-lzip = la compression lzip
db-compression-lzop = la compression lzop
db-compression-unrecognized = un format non reconnu
