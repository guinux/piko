# Les erreurs de piko-net, les téléchargements et le rafraîchissement des bases.
#
# Une espace insécable (U+00A0) précède le deux-points.

net-error-all-servers-failed =
    impossible de télécharger { $file } depuis { $count ->
        [one] le seul serveur
       *[other] aucun des { $count } serveurs
    }{" "}:
    {"  "}{ $list }
net-attempt = { $url }{" "}: { $reason }
net-error-no-servers = le dépôt { $repo } n'a aucun Server configuré
net-error-keyring-unusable = le SigLevel d'un dépôt demande une vérification de signature, et le trousseau est inutilisable
net-error-duplicate-target = { $file } figure plusieurs fois dans un même lot
net-error-wrong-lock = le verrou { $lock } n'appartient pas à la base qui contient { $sync_dir }
net-error-too-large = { $file } dépasse la limite de téléchargement de { $max } octets
net-error-larger-than-declared = { $file } dépasse les { $declared } octets que son dépôt déclare
net-error-empty-download = le téléchargement de { $file } était vide (rien n'a été écrit)
net-error-signature-rejected = { $file } téléchargé a été refusé{" "}: { $reason } (la base existante n'a pas changé)
net-error-signature-uncheckable = impossible de vérifier la signature de { $file } téléchargé{" "}: { $reason }
net-error-io-download = impossible de télécharger { $path }
net-error-io-create = impossible de créer { $path }
net-error-io-read-download = impossible de lire le téléchargement de { $path }
net-error-io-write-download = impossible d'écrire le téléchargement de { $path }
net-error-cancelled = le téléchargement a été annulé
net-error-sandbox = le bac à sable de téléchargement a échoué{" "}: { $reason }

net-uncheckable-unreachable = impossible de récupérer { $url }{" "}: { $reason }
net-uncheckable-status = { $url } a répondu HTTP { $status } au lieu de 200
net-uncheckable-empty = { $url } a renvoyé une signature vide
net-uncheckable-no-keyring = la politique exige une signature, mais aucun trousseau n'a été fourni

net-join-lines =
    { $head }
    {"  "}{ $tail }
