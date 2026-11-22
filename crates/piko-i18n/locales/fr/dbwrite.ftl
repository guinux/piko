# Les erreurs de piko-db-write, l'écriture de la base locale.
#
# Une espace insécable (U+00A0) précède le deux-points et le point-virgule.

dbw-error-io-create = impossible de créer { $path }
dbw-error-io-create-dir = impossible de créer le répertoire { $path }
dbw-error-io-write = impossible d'écrire { $path }
dbw-error-io-rename = impossible de renommer vers { $path }
dbw-error-io-remove = impossible de supprimer { $path }
dbw-error-io-open = impossible d'ouvrir { $path }
dbw-error-io-stat = impossible d'examiner { $path }
dbw-error-io-sync = impossible d'écrire sur le disque { $path }
dbw-error-database-locked = impossible de verrouiller la base { $path }{" "}; si aucun gestionnaire de paquets n'est en cours, supprimez-le
dbw-error-wrong-lock = le verrou { $lock } n'appartient pas à la base { $dbpath }
dbw-error-temporary-replaced = { $path } a été remplacé par un autre fichier avant de pouvoir être renommé
dbw-error-record = impossible de représenter { $path } pour le réécrire
dbw-error-invalid-member-name = { $name } ne désigne pas un fichier dans une entrée de la base

dbw-record-value-outside-section = la ligne { $line } n'a pas de section{" "}: { $content }
dbw-record-duplicate-section = la section %{ $keyword }% apparaît plusieurs fois, de nouveau à la ligne { $line }
dbw-record-invalid-keyword = { $keyword } ne peut pas être un mot-clé de section
dbw-record-unrepresentable-value = la section %{ $keyword }% ne peut pas contenir la valeur { $value }{" "}: { $reason }

dbw-unrepresentable-empty = une ligne vide termine une section
dbw-unrepresentable-line-break = un saut de ligne serait relu comme plusieurs valeurs
dbw-unrepresentable-nul = un lecteur de chaînes C s'arrêterait au NUL
dbw-unrepresentable-section-header = elle serait relue comme un en-tête de section
