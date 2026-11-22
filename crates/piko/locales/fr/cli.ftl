# Les messages de la ligne de commande `piko`.
#
# Une espace insécable (U+00A0) précède le deux-points et le point-virgule. Elle est écrite
# {"\u00A0"} pour rester visible.


## Le mot-clé en tête d'une ligne de diagnostic. $text est la suite de la ligne.

cli-error = Erreur{"\u00A0"}: { $text }
cli-warning = Avertissement{"\u00A0"}: { $text }
cli-note = Remarque{"\u00A0"}: { $text }
cli-caused-by = Cause{"\u00A0"}: { $text }
cli-try = Essayez{"\u00A0"}: { $text }

## Questions et réponses.

cli-yes-answers = o oui
cli-invalid-number = Valeur invalide{"\u00A0"}: entrez un nombre entre 1 et { $count }
cli-invalid-selection = Valeur invalide{"\u00A0"}: entrez un nombre ou un intervalle entre 1 et { $count }
cli-invalid-letter = Valeur invalide{"\u00A0"}: entrez une de ces lettres{"\u00A0"}: { $letters }

## Éléments partagés.

cli-write-failed = impossible d'écrire la sortie{"\u00A0"}: { $error }
cli-unknown = <inconnu>
cli-and-more = { $shown }, et { $rest } de plus
cli-problems-not-shown =
    { $count ->
        [one] { $count } autre problème non affiché
       *[other] { $count } autres problèmes non affichés
    }

## Résolution des cibles (piko plan, install, remove).

plan-invalid-dependency = { $target } n'est pas une dépendance valide
plan-not-found = aucun paquet satisfaisant { $target } n'a été trouvé dans les dépôts configurés
plan-closest-candidate = le candidat le plus proche est { $nearest }
plan-pattern-ignored = tous les paquets correspondant à { $pattern } sont ignorés
plan-target-ignored = tous les paquets satisfaisant { $target } sont ignorés
plan-never-installs-ignored = piko n'installe jamais un paquet ignoré{"\u00A0"}; modifiez IgnorePkg ou IgnoreGroup dans pacman.conf pour l'autoriser
plan-ignoring-package = paquet { $package } ignoré
plan-pattern-not-found = aucun paquet ni groupe correspondant à { $pattern } n'a été trouvé dans les dépôts configurés
plan-pattern-not-installed = aucun paquet installé ni groupe ne correspond à { $pattern }
plan-pattern-too-broad = { $pattern } correspond à plus de { $limit } paquets
plan-pattern-too-broad-note = nommez les paquets, ou restreignez le motif
plan-pattern-versioned = { $target } est un motif glob avec une contrainte de version
plan-pattern-versioned-note = un motif ne s'étend qu'à des noms{"\u00A0"}; nommez le paquet pour contraindre sa version

## Mises à jour ignorées.

plan-ignoring-upgrade = { $name }{"\u00A0"}: mise à jour ignorée ({ $old } => { $new })
plan-ignoring-downgrade = { $name }{"\u00A0"}: rétrogradation ignorée ({ $old } => { $new })
plan-ignoring-replacement = remplacement de paquet ignoré ({ $old } => { $new })
plan-lost-file-candidate = Erreur interne{"\u00A0"}: l'univers a perdu un candidat de fichier de paquet

## Motifs glob. $pattern est le motif tel que l'utilisateur l'a tapé.

cli-pattern-matched =
    { $pattern } correspond à { $packages ->
        [one] { $packages } paquet
       *[other] { $packages } paquets
    }
cli-pattern-matched-groups =
    { $pattern } correspond à { $groups ->
        [one] { $groups } groupe
       *[other] { $groups } groupes
    } et { $packages ->
        [one] { $packages } paquet
       *[other] { $packages } paquets
    }
cli-groups-list = Groupes{"\u00A0"}: { $list }
cli-packages-list = Paquets{"\u00A0"}: { $list }

## Pourquoi une demande n'a pas de solution.

cli-explanation-gave-up = l'explication elle-même a dépassé le budget de conflits du solveur
cli-facts-not-shown =
    { $count ->
        [one] ... et { $count } autre fait non affiché
       *[other] ... et { $count } autres faits non affichés
    }
cli-changes-not-tried =
    { $count ->
        [one] ... et { $count } autre changement non essayé
       *[other] ... et { $count } autres changements non essayés
    }

## Ce qu'un plan a remarqué en étant assemblé.

plan-dependency-cycle = { $name } fait partie d'un cycle de dépendances{"\u00A0"}; il peut être installé avant une de ses dépendances
plan-broken-dependency = { $name } dépend de { $relation }, que rien d'installé ne fournit
plan-broken-not-shown =
    { $count ->
        [one] { $count } autre dépendance cassée non affichée
       *[other] { $count } autres dépendances cassées non affichées
    }
plan-divergences =
    { $count ->
        [one] { $count } dépendance a été satisfaite par un candidat que pacman n'aurait pas essayé en premier{"\u00A0"}; le plan est valide et peut différer de `pacman -Sp`
       *[other] { $count } dépendances ont été satisfaites par un candidat que pacman n'aurait pas essayé en premier{"\u00A0"}; le plan est valide et peut différer de `pacman -Sp`
    }
plan-divergence = { $name } dépend de { $relation }{"\u00A0"}: { $taken } a été pris, pacman aurait essayé { $preferred }
cli-requirements-not-shown =
    { $count ->
        [one] { $count } autre dépendance non affichée
       *[other] { $count } autres dépendances non affichées
    }
cli-unknown-failure = { $failure }

## La liste des étapes d'un plan.

plan-verb-install = installer
plan-verb-upgrade = mettre à jour
plan-verb-downgrade = rétrograder
plan-verb-reinstall = réinstaller
plan-verb-remove = supprimer
plan-tally-install = { $count } à installer
plan-tally-upgrade = { $count } à mettre à jour
plan-tally-downgrade = { $count } à rétrograder
plan-tally-reinstall = { $count } à réinstaller
plan-tally-remove = { $count } à supprimer
plan-download-size = { $size } à télécharger
plan-installed-size = { $size } de taille installée

## La ligne de commande elle-même.

main-blank-search = tous les termes de recherche sont vides{"\u00A0"}; indiquez ce que vous cherchez
main-no-targets = aucune cible (utilisez --sysupgrade pour tout mettre à jour)

## Lecture de la configuration et ouverture des bases.

context-repository-unused = le dépôt [{ $name }] n'est pas utilisé{"\u00A0"}: { $reason }
context-config-fallback = impossible de lire { $config } ({ $reason }){"\u00A0"}; { $fallback } est utilisé à la place
context-repository-skipped = dépôt { $name } ignoré{"\u00A0"}: { $reason }
context-config-unavailable = impossible de lire { $path }{"\u00A0"}: { $reason }

## Pourquoi une sous-commande s'est arrêtée.

error-invalid-repo-name = { $name } n'est pas un nom de dépôt valide
error-signature-rejected = la signature de { $archive } a été refusée{"\u00A0"}: { $reason }
error-signature-uncheckable = impossible de vérifier la signature de { $archive }
error-not-root = piko { $command } doit être lancé en root pour modifier { $path }. Lancez-le en root, ou utilisez { $flags } pour désigner des chemins qui vous appartiennent

## La grille de piko info. Les étiquettes sont alignées sur la plus longue de la langue.

info-field-repository = Dépôt
info-field-name = Nom
info-field-version = Version
info-field-description = Description
info-field-architecture = Architecture
info-field-url = URL
info-field-licenses = Licences
info-field-groups = Groupes
info-field-provides = Fournit
info-field-depends-on = Dépend de
info-field-optional-deps = Dépendances opt.
info-field-required-by = Requis par
info-field-optional-for = Optionnel pour
info-field-conflicts-with = Est en conflit avec
info-field-replaces = Remplace
info-field-download-size = Taille du téléchargement
info-field-installed-size = Taille installée
info-field-packager = Paqueteur
info-field-build-date = Date de compilation
info-field-install-date = Date d'installation
info-field-install-reason = Motif d'installation
info-field-install-script = Script d'installation
info-field-validated-by = Validé par
info-none = Aucun
info-unknown = Inconnu
info-installed-mark = [installé]
info-yes = Oui
info-no = Non
info-explicit = Explicitement installé
info-dependency = Installé comme dépendance d'un autre paquet
info-validation-md5 = Somme MD5
info-validation-sha256 = Somme SHA-256
info-validation-signature = Signature
info-optional-incomplete = { $package }{"\u00A0"}: les dépendances optionnelles marquées { $mark } peuvent être incomplètes{"\u00A0"}: { $reason }
info-optional-for-incomplete = « Optionnel pour » peut être incomplet{"\u00A0"}: { $package }{"\u00A0"}: { $reason }

## Signaux.

signal-interrupted = Interrompu
signal-terminated = Terminé sur demande
signal-forcing-exit = Arrêt toujours en cours -- sortie forcée
signal-stopping = Arrêt en cours (appuyez de nouveau sur Ctrl+C pour forcer la sortie)...
signal-stopping-terminate = Arrêt en cours{"\u00A0"}: demande d'arrêt reçue...

## Recherches de paquets communes à plusieurs commandes.

cli-not-installed = le paquet { $name } n'est pas installé
cli-not-in-repository = le paquet { $name } n'est pas dans { $path }
cli-not-found-anywhere = le paquet { $name } n'est ni installé ni dans un dépôt configuré

## piko check.

check-row = Vérification des paquets
check-clean =
    { $total ->
        [one] { $total } paquet vérifié, aucun problème trouvé
       *[other] { $total } paquets vérifiés, aucun problème trouvé
    }
check-problems =
    { $total ->
        [one] { $total } paquet vérifié
       *[other] { $total } paquets vérifiés
    }, { $problems ->
        [one] { $problems } paquet avec des problèmes
       *[other] { $problems } paquets avec des problèmes
    }
check-defects-not-shown =
    { $package }{"\u00A0"}: { $count ->
        [one] { $count } autre défaut du fichier files
       *[other] { $count } autres défauts du fichier files
    }
check-no-mtree = { $package }{"\u00A0"}: pas de fichier mtree
check-altered =
    { $package }{"\u00A0"}: { $total ->
        [one] { $total } fichier au total
       *[other] { $total } fichiers au total
    }, { $altered ->
        [one] { $altered } fichier modifié
       *[other] { $altered } fichiers modifiés
    }

## piko owns.

owns-owned-by = { $path } appartient à { $name } { $version }
owns-no-owner = Aucun paquet ne possède { $path }

## piko why.

why-explicit = { $package } a été installé explicitement
why-orphan = { $package } est installé comme dépendance, et rien d'installé n'en dépend
why-orphan-note = (orphelin au sens des dépendances strictes{"\u00A0"}; `piko plan -R -s` le supprimerait. Il peut encore être une dépendance optionnelle d'un autre paquet — `pacman -Qdt` les compte comme requises, `pacman -Qdtt` non.)
why-required-by = { $package } est installé comme dépendance, requis par{"\u00A0"}:
why-group-orphaned = mais aucun paquet installé explicitement n'en dépend, directement ou indirectement — tout ce groupe est orphelin
why-chain-root = { $package } (installé explicitement)
why-chain-requires = dépend de { $package }

## Questions sur les groupes et les fournisseurs.

group-members =
    { $count ->
        [one] Il y a { $count } membre dans le groupe { $group }{"\u00A0"}:
       *[other] Il y a { $count } membres dans le groupe { $group }{"\u00A0"}:
    }
group-prompt = Entrez une sélection (par défaut{"\u00A0"}: tous){"\u00A0"}:
group-defaults =
    { $count ->
        [one] { $count } groupe cible a été pris en entier (un `piko install` interactif demande quels membres installer)
       *[other] { $count } groupes cibles ont été pris en entier (un `piko install` interactif demande quels membres installer)
    }
group-default = { $group }{"\u00A0"}: les { $count } membres ont été pris, { $sample }
provider-header = Il y a { $count } fournisseurs disponibles pour { $relation }{"\u00A0"}:
provider-prompt = Entrez un numéro (par défaut{"\u00A0"}: 1){"\u00A0"}:
provider-defaults =
    { $count ->
        [one] { $count } dépendance a plusieurs fournisseurs{"\u00A0"}; le premier a été pris (un `piko install` interactif demande lequel utiliser)
       *[other] { $count } dépendances ont plusieurs fournisseurs{"\u00A0"}; le premier a été pris (un `piko install` interactif demande lequel utiliser)
    }
provider-default = { $package } dépend de { $relation }{"\u00A0"}: { $taken } a été pris, parmi { $sample }

## Suppression.

removal-held = { $name } est désigné comme HoldPkg
removal-held-unattended = un HoldPkg figure parmi les cibles, et cette exécution ne peut pas demander de confirmation
removal-held-prompt = Un HoldPkg figure parmi les cibles. Voulez-vous continuer{"\u00A0"}? [o/N]
removal-not-installed = aucun paquet installé ni groupe nommé { $name }
removal-cascade-hint = ajoutez -c pour supprimer aussi les paquets qui en dépendent

## Listes de candidats et verrou de la base.

cli-lock-not-removed = impossible de supprimer le fichier de verrou { $path }{ $cause }
cli-origin-repository = Dépôt { $name }
cli-origin-file = Fichier de paquet
cli-origin-installed = Installé

## piko list et piko group.

list-installed =
    { $count ->
        [one] { $count } installé
       *[other] { $count } installés
    }
list-listed =
    { $count ->
        [one] { $count } listé
       *[other] { $count } listés
    }
list-explicit =
    { $count ->
        [one] { $count } installé explicitement
       *[other] { $count } installés explicitement
    }
list-orphaned =
    { $count ->
        [one] { $count } orphelin
       *[other] { $count } orphelins
    }
list-foreign =
    { $count ->
        [one] { $count } étranger
       *[other] { $count } étrangers
    }
list-configured =
    { $count ->
        [one] { $count } configuré
       *[other] { $count } configurés
    }
list-groups =
    { $count ->
        [one] { $count } groupe
       *[other] { $count } groupes
    }
list-group-not-found = le groupe { $name } n'a pas été trouvé

## piko search.

search-found =
    { $count ->
        [one] { $count } trouvé
       *[other] { $count } trouvés
    }
search-installed =
    { $count ->
        [one] { $count } installé
       *[other] { $count } installés
    }
search-desc-unavailable = (desc indisponible)
search-desc-unparsed = <desc illisible>

## piko check-updates et piko resolve.

sync-updates-available =
    { $count ->
        [one] { $count } mise à jour disponible
       *[other] { $count } mises à jour disponibles
    }
sync-no-repository = aucun dépôt configuré n'a pu être ouvert{"\u00A0"}; voir les avertissements ci-dessus
sync-ignored-candidate = { $package } dans { $repository } ({ $reason })

## Fraîcheur des bases de dépôts. $file est un nom de fichier, comme core.db.

fresh-behind = { $server } est plus ancien que le { $file } installé (dernière modification { $date }). Piko a essayé le serveur suivant.
fresh-lost-signature = Piko a refusé le { $file } de { $server }. Il n'a pas de signature valide, et celui qui est installé est signé ({ $installed }). Un miroir peut faire cela pour retenir des mises à jour.
fresh-refused-older = Piko a refusé un { $file } signé de { $server } plus ancien que celui qui est installé ({ $candidate }, installé { $installed }). Un miroir peut faire cela pour retenir des mises à jour.
fresh-older = { $server } a un { $file } plus ancien que celui qui est installé ({ $candidate }, installé { $installed }). Piko a essayé le serveur suivant.
fresh-accepted-older = Piko a installé un { $file } plus ancien depuis { $server } ({ $candidate }, le précédent { $replaced }), car vous avez donné --accept-older.
fresh-stale = { $file } date de { $age } ({ $publication }). { $checked } Un miroir peut ne pas être à jour, ou retenir des mises à jour. La limite est de { $limit } (--max-age).
fresh-future-baseline = Le { $file } installé est daté de { $ahead } dans le futur ({ $publication }) et n'est pas signé. Piko n'a pas utilisé cette date pour refuser un { $file } plus ancien. Vérifiez l'horloge du système.
fresh-kept = Aucun serveur n'a de { $file } aussi récent que celui qui est installé ({ $installed }). Piko garde la base installée.
fresh-stale-local = { $file } date de { $age } ({ $publication }). La limite est de { $limit } (--max-age). Lancez 'piko refresh' pour chercher une version plus récente sur les miroirs.
fresh-future = { $file } est daté de { $ahead } dans le futur ({ $publication }). Vérifiez l'horloge du système.
fresh-signed = signé le { $date }
fresh-published = publié le { $date }
fresh-undated = non daté
fresh-no-other-server = Aucun autre serveur n'était disponible pour comparer.
fresh-other-servers =
    { $count ->
        [one] { $count } autre serveur n'a rien de plus récent.
       *[other] { $count } autres serveurs n'ont rien de plus récent.
    }
fresh-days =
    { $count ->
        [one] { $count } jour
       *[other] { $count } jours
    }
fresh-hours =
    { $count ->
        [one] { $count } heure
       *[other] { $count } heures
    }
fresh-minutes =
    { $count ->
        [one] { $count } minute
       *[other] { $count } minutes
    }

## piko refresh.

refresh-keyring-needed = le SigLevel d'un dépôt exige une signature, donc la mise à jour ne peut pas continuer sans trousseau utilisable
refresh-row = Synchronisation de { $repository }
refresh-up-to-date = { $repository } (à jour)
refresh-kept = { $repository } (gardée{"\u00A0"}: pas de base plus récente)
refresh-unknown-repository = { $repository } n'est pas un dépôt configuré
refresh-not-synced = { $repository } n'est pas mis à jour{"\u00A0"}: son Usage n'inclut pas Sync

## piko history.

history-empty = Aucune transaction enregistrée
history-read = { $log } et { $store } ont été lus
history-count =
    { $count ->
        [one] { $count } transaction
       *[other] { $count } transactions
    }
history-unknown-date = date inconnue
history-packages = { $count } paquets
history-verb-installed = installé
history-verb-upgraded = mis à jour
history-verb-downgraded = rétrogradé
history-verb-reinstalled = réinstallé
history-verb-removed = supprimé
history-unfinished = une transaction inachevée est enregistrée{"\u00A0"}; lancez `piko report` pour la voir
history-unfinished-unreadable = une transaction inachevée est enregistrée, mais son journal est illisible{"\u00A0"}; lancez `piko report` pour la voir

## piko key.

key-generated = Nouvelle clé maîtresse de signature générée dans { $path }
key-expiry-removed = Date d'expiration de la clé maîtresse retirée dans { $path }
key-already-initialized = { $path } est déjà initialisé
key-no-keyrings = Aucun trousseau trouvé sous { $path }
key-populated = { $name }{"\u00A0"}: { $imported } importées, { $lsigned } signées localement, { $trusted } de confiance, { $disabled } désactivées
key-imported = { $file }{"\u00A0"}: { $imported } importées, { $unchanged } inchangées
key-prompt-lsign = Signer localement cette clé{"\u00A0"}? [o/N]
key-prompt-delete = Supprimer cette clé{"\u00A0"}? [o/N]
key-skipped = { $key } ignorée
key-lsigned = { $key } signée localement
key-already-lsigned = { $key } est déjà signée localement
key-no-match = Aucune clé correspondante
key-mark-disabled = [désactivée]
key-mark-revoked = [révoquée]
key-mark-expired = [expirée]
key-deleted = { $key } supprimée
key-verify-outcome = { $status } (confiance{"\u00A0"}: { $trust })
key-verify-outcome-key = { $status } (confiance{"\u00A0"}: { $trust }), clé { $key }
key-trustdb-updated = Base de confiance recalculée

## piko merge, et les fichiers à fusionner après une transaction.

merge-pending-not-listed =
    { $count ->
        [one] { $count } autre fichier en attente n'a pas été listé
       *[other] { $count } autres fichiers en attente n'ont pas été listés
    }
merge-unmatched = { $path } ne désigne aucun fichier en attente
merge-attention = Des fichiers de configuration demandent votre attention{"\u00A0"}:
merge-installed-as = { $target } installé sous { $pacfile }
merge-saved-as = { $target } sauvegardé sous { $pacfile }
merge-run-hint = Lancez 'piko merge' pour les traiter.
merge-unreadable = { $pacfile }{"\u00A0"}: ignoré, il est illisible
merge-no-current = { $path } ignoré, il n'a pas de version actuelle avec laquelle fusionner
merge-identical-removed = { $pacfile }{"\u00A0"}: supprimé, il contient les mêmes octets que { $target }
merge-changed-since = { $pacfile }{"\u00A0"}: gardé, il a changé depuis l'analyse
merge-target-missing = { $target } n'existe pas. Supprimer { $pacfile }{"\u00A0"}? [o/N]
merge-differ = { $target } et { $pacfile } diffèrent ({ $package }).
merge-menu = (V) voir, (M) fusionner, (S) passer, (R) supprimer le { $label }, (O) écraser avec le { $label }, (Q) quitter{"\u00A0"}:
merge-write-failed = impossible d'écrire { $path }{"\u00A0"}: { $error }
merge-clean = Fusion sans conflit.
merge-conflicts = Fusion avec conflits. Relisez-les avant de garder le résultat.
merge-keep-prompt = Garder le fichier fusionné{"\u00A0"}? [o/N]
merge-read-back-failed = impossible de relire { $path }{"\u00A0"}: { $error }
merge-no-policy = Aucune politique de signature ne peut vérifier une version en cache, il n'y a donc pas de base pour la fusion.
merge-base-refused = { $path } n'est pas utilisé comme base{"\u00A0"}: { $reason }
merge-no-base = Aucune version signée en cache de { $package } antérieure à { $version } n'a été trouvée, il n'y a donc pas de base pour la fusion.
merge-not-shipped = { $package } ne contient pas { $path }, il n'y a donc pas de base pour la fusion.
merge-no-base-unknown = Il n'y a pas de base pour la fusion.
merge-scratch-failed = impossible d'utiliser un répertoire temporaire{"\u00A0"}: { $error }
merge-not-regular = ce n'est pas un fichier ordinaire
merge-too-large = plus grand que { $max } octets
merge-start-failed = impossible de lancer { $program }{"\u00A0"}: { $error }
merge-no-keyring = { $error }{"\u00A0"}; aucune version en cache ne peut servir de base de fusion
merge-program-unreadable = impossible de lire { $variable }{"\u00A0"}: { $error }
merge-outcome-skipped = Les deux fichiers sont restés en place.
merge-outcome-removed = { $path } supprimé.
merge-outcome-overwritten = { $path } écrasé.
merge-outcome-merged = Fichier fusionné écrit dans { $path }.
merge-outcome-done = Terminé.

## Transactions : install, update, remove.

txn-resolving = Résolution des dépendances
txn-nothing-to-do = Rien à faire
txn-fetching = Récupération de { $url }
txn-ambiguous-target = { $name } désigne à la fois un fichier ici et un paquet d'un dépôt{"\u00A0"}; le fichier est installé (écrivez ./{ $name } pour ne plus voir ce message, ou déplacez le fichier pour installer le paquet)
txn-creating-cache = le cache { $path } n'existe pas, création...
txn-removing-packages =
    { $count ->
        [one] Suppression de { $count } paquet{"\u00A0"}:
       *[other] Suppression de { $count } paquets{"\u00A0"}:
    }
txn-prompt-remove = Voulez-vous supprimer ces paquets{"\u00A0"}? [O/n]
txn-not-a-removal = ceci est un bogue{"\u00A0"}; lancez `piko plan -R` pour voir le plan
txn-previous-unfinished = Une transaction précédente ne s'est pas terminée{"\u00A0"}; lancez `piko report` pour la voir
txn-scriptlet-truncated = la sortie du scriptlet de { $package } a été tronquée
txn-scriptlet-failed = scriptlet { $kind } de { $package }{"\u00A0"}: { $outcome }
txn-hook-truncated = la sortie du hook { $hook } a été tronquée
txn-hook-failed = hook { $hook }{"\u00A0"}: { $reason }
txn-prompt-download = Procéder au téléchargement{"\u00A0"}? [O/n]
txn-prompt-install = Procéder à l'installation{"\u00A0"}? [O/n]
txn-nothing-changed = rien n'a été modifié{"\u00A0"}; aucune étape de la transaction n'a été exécutée
txn-cancelled-recorded = les étapes exécutées sont enregistrées{"\u00A0"}; lancez `piko report` pour les voir, puis relancez pour terminer
txn-stopped-part-way = la transaction s'est arrêtée en cours de route{"\u00A0"}; lancez `piko report` pour voir ce qui a été appliqué

## piko report : une transaction inachevée.

report-none = Aucune transaction inachevée n'est enregistrée
report-never-started = Une transaction a été enregistrée mais n'a jamais commencé{"\u00A0"}; le système n'a pas changé
report-remove-journal = Supprimez le journal pour l'effacer{"\u00A0"}:
report-cannot-undo-remove = Les étapes appliquées ne peuvent pas être annulées. Supprimez le journal{"\u00A0"}:
report-run-again = Puis relancez l'opération
report-finish = Les étapes appliquées ne peuvent pas être annulées. Pour terminer la transaction, lancez dans l'ordre{"\u00A0"}:
report-unreadable-steps = Ces étapes ne peuvent pas être lues dans le journal, et ne figurent pas dans les commandes{"\u00A0"}:
report-unreadable = Une transaction inachevée est enregistrée, mais son journal est illisible
report-journal = Journal{"\u00A0"}: { $path }
report-reason = Raison{"\u00A0"}:  { $reason }
report-unreadable-help =
    piko refuse toute transaction tant que le journal est présent. Le système
    peut être partiellement modifié. Lisez le journal, et vérifiez les paquets qu'il nomme.
report-then-remove-it = Puis supprimez-le{"\u00A0"}:
report-then-remove-them = Puis supprimez-les{"\u00A0"}:
report-interrupted = Une transaction inachevée a été interrompue
report-root = Racine{"\u00A0"}: { $path }
report-dbpath = DBPath{"\u00A0"}: { $path }
report-progress = { $completed } étapes terminées sur { $total }
report-all-completed = Toutes les étapes sont terminées{"\u00A0"}; seul le journal est resté
report-not-applied = Non appliqué{"\u00A0"}:
report-install = Installer { $package }
report-remove = Supprimer { $package }
report-cut-installs =
    L'interruption a pu couper les premières installations en cours de route. Certains de leurs
    fichiers sont alors sur le disque sans paquet qui les possède. `--overwrite '*'` s'applique
    à ces paquets seulement, et leur permet de remplacer ces fichiers.
report-lock-present = Le verrou de la base { $path } est toujours présent.
report-lock-held = Un piko ou un pacman en cours d'exécution le détient aussi{"\u00A0"}: supprimez-le seulement si aucun ne tourne.

## Autres messages d'une transaction.

txn-siglevel-never-hint = mettez SigLevel = Never dans pacman.conf pour installer sans vérifier les signatures
txn-questions-withheld =
    { $count ->
        [one] { $count } autre question sur un fournisseur n'a pas été posée{"\u00A0"}; le premier candidat a été pris
       *[other] { $count } autres questions sur un fournisseur n'ont pas été posées{"\u00A0"}; le premier candidat a été pris
    }
conf-unknown-directive = directive inconnue '{ $directive }'
history-bad-time = { $time } n'est pas une date comprise{"\u00A0"}; utilisez YYYY-MM-DD ou YYYY-MM-DDTHH:MM:SS+ZZZZ
plan-url-not-loaded = impossible de planifier { $url }{"\u00A0"}: prévisualiser l'URL d'un paquet obligerait à la télécharger{"\u00A0"}; utilisez `piko install` à la place

## Lignes de progression d'un téléchargement et d'une validation.

progress-downloading = Téléchargement
progress-downloading-names = Téléchargement de { $names }
progress-downloading-more = Téléchargement de { $names } (+{ $rest })
progress-host-skipped = trop d'erreurs de { $host }, il est ignoré jusqu'à la fin de cette exécution
progress-downloading-packages = Téléchargement des paquets
progress-verifying-signatures = Vérification des signatures
progress-verifying-packages = Vérification des paquets
progress-checking-conflicts = Recherche des conflits de fichiers
progress-checking-space = Vérification de l'espace disque disponible
progress-updating = Mise à jour de { $package }
progress-installing = Installation de { $package }
progress-removing = Suppression de { $package }
progress-scriptlet = Exécution du script { $kind }
progress-syncing =
    { $count ->
        [one] Écriture de { $count } paquet sur le disque
       *[other] Écriture de { $count } paquets sur le disque
    }
progress-unhashed = impossible de calculer l'empreinte de { $path }
progress-pacnew = Installé sous { $path } -- à fusionner
progress-pacsave = { $path } sauvegardé en .pacsave

## Privilèges.

privilege-root-and-dbpath = --root et --dbpath

## Dates.

output-timestamp-out-of-range = { $timestamp } (horodatage hors limites)

## Les mots que clap écrit dans --help. clap ajoute le deux-points après un titre.

cli-help-usage = Utilisation{"\u00A0"}:
cli-help-commands = Commandes{"\u00A0"}
cli-help-options = Options{"\u00A0"}
cli-help-arguments = Arguments{"\u00A0"}
cli-help-print-help = Affiche l'aide (plus de détails avec '--help')
cli-help-print-help-long = Affiche l'aide (un résumé avec '-h')
cli-help-print-version = Affiche la version
cli-help-subcommand = Affiche ce message, ou l'aide des sous-commandes données
cli-help-subcommand-arg = Affiche l'aide des sous-commandes
cli-help-default = [défaut{"\u00A0"}: { $value }]
cli-help-aliases =
    { $count ->
        [one] [alias{"\u00A0"}: { $aliases }]
       *[other] [alias{"\u00A0"}: { $aliases }]
    }

## Une erreur dans la ligne de commande elle-même. Voir src/parse_error.rs.

cli-clap-error = erreur{"\u00A0"}:
cli-clap-tip = astuce{"\u00A0"}:
cli-clap-unknown-cause = cause inconnue
cli-clap-try-help = Pour plus d'informations, essayez '{ $flag }'.
cli-clap-kind-invalid-value = une des valeurs n'est pas valide pour un argument
cli-clap-kind-unknown-argument = argument inattendu
cli-clap-kind-invalid-subcommand = sous-commande inconnue
cli-clap-kind-no-equals = un signe égal est nécessaire pour donner une valeur à l'un des arguments
cli-clap-kind-value-validation = valeur invalide pour l'un des arguments
cli-clap-kind-too-many-values = valeur inattendue pour un argument
cli-clap-kind-too-few-values = un argument demande plus de valeurs
cli-clap-kind-wrong-number-of-values = trop ou trop peu de valeurs pour un argument
cli-clap-kind-argument-conflict = un argument ne peut pas être utilisé avec un ou plusieurs des autres arguments donnés
cli-clap-kind-missing-required-argument = un ou plusieurs arguments requis n'ont pas été donnés
cli-clap-kind-missing-subcommand = une sous-commande est requise, et aucune n'a été donnée
cli-clap-kind-invalid-utf8 = de l'UTF-8 invalide a été trouvé dans un ou plusieurs arguments
cli-clap-used-multiple-times = l'argument '{ $arg }' ne peut pas être utilisé plusieurs fois
cli-clap-conflict-one = l'argument '{ $arg }' ne peut pas être utilisé avec '{ $other }'
cli-clap-conflict-many = l'argument '{ $arg }' ne peut pas être utilisé avec{"\u00A0"}:{ $list }
cli-clap-conflict-other = l'argument '{ $arg }' ne peut pas être utilisé avec un ou plusieurs des autres arguments donnés
cli-clap-conflict-none = l'argument '{ $arg }' ne peut pas être utilisé avec un autre argument donné
cli-clap-subcommand-conflict-one = la sous-commande '{ $subcommand }' ne peut pas être utilisée avec '{ $other }'
cli-clap-subcommand-conflict-many = la sous-commande '{ $subcommand }' ne peut pas être utilisée avec{"\u00A0"}:{ $list }
cli-clap-subcommand-conflict-other = la sous-commande '{ $subcommand }' ne peut pas être utilisée avec un ou plusieurs des autres arguments donnés
cli-clap-subcommand-conflict-none = la sous-commande '{ $subcommand }' ne peut pas être utilisée avec un autre argument donné
cli-clap-no-equals = un signe égal est nécessaire pour donner une valeur à '{ $arg }'
cli-clap-value-required = '{ $arg }' demande une valeur, et aucune n'a été donnée
cli-clap-invalid-value = valeur '{ $value }' invalide pour '{ $arg }'
cli-clap-invalid-value-because = valeur '{ $value }' invalide pour '{ $arg }'{"\u00A0"}: { $reason }
cli-clap-possible-values = [valeurs possibles{"\u00A0"}: { $values }]
cli-clap-subcommands-list = [sous-commandes{"\u00A0"}: { $values }]
cli-clap-unrecognized-subcommand = sous-commande '{ $subcommand }' inconnue
cli-clap-missing-required = les arguments requis suivants n'ont pas été donnés{"\u00A0"}:{ $list }
cli-clap-missing-subcommand = '{ $subcommand }' demande une sous-commande, et aucune n'a été donnée
cli-clap-too-many-values = valeur '{ $value }' inattendue pour '{ $arg }'{"\u00A0"}; aucune autre n'était attendue
cli-clap-too-few-values =
    { $min } valeurs requises par '{ $arg }'{"\u00A0"}; seulement { $actual } { $count ->
        [one] donnée
       *[other] données
    }
cli-clap-wrong-number-of-values =
    { $expected } valeurs requises pour '{ $arg }', mais { $actual } { $count ->
        [one] donnée
       *[other] données
    }
cli-clap-unexpected-argument = argument '{ $arg }' inattendu
cli-clap-similar-subcommand =
    { $count ->
        [one] une sous-commande proche existe{"\u00A0"}: { $values }
       *[other] des sous-commandes proches existent{"\u00A0"}: { $values }
    }
cli-clap-similar-argument =
    { $count ->
        [one] un argument proche existe{"\u00A0"}: { $values }
       *[other] des arguments proches existent{"\u00A0"}: { $values }
    }
cli-clap-similar-value =
    { $count ->
        [one] une valeur proche existe{"\u00A0"}: { $values }
       *[other] des valeurs proches existent{"\u00A0"}: { $values }
    }
cli-resolve-path-failed = impossible de résoudre le chemin '{ $path }'{"\u00A0"}: { $reason }
