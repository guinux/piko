# Le planificateur de transactions : pourquoi une demande n'a pas de solution.
#
# Chaque valeur est déjà échappée par l'interface : un paquet tel que le planificateur
# l'affiche (version et origine comprises), ou une entrée %DEPENDS% telle quelle.

## Fact : une clause du noyau insatisfiable.

solve-fact-requested = { $package } a été demandé
solve-fact-excluded = { $package } ne peut pas être sélectionné
solve-fact-must-remain = { $package } est installé et doit rester
solve-fact-requires = { $package } dépend de { $relation }
solve-fact-conflicts = { $package } est en conflit avec { $other }
solve-fact-replaces = { $package } remplace { $replaced }
solve-fact-ignored = { $candidate } satisferait { $relation }, mais il est ignoré ({ $reason })
solve-fact-no-version = rien ne satisfait { $relation }, le candidat le plus proche est { $nearest }
solve-fact-chose = { $chosen } a été choisi pour satisfaire { $relation }, dont { $package } dépend
solve-fact-same-name = { $first } et { $second } sont deux versions du même paquet

## Shape : la nature de l'échec. L'interface l'affiche après « Erreur : ».

solve-shape-unsatisfied = rien ne satisfait { $relation }
solve-shape-ignored-only = tous les candidats qui satisfont { $relation } sont ignorés
solve-shape-chosen-provider = { $chosen } a été choisi pour satisfaire { $relation }, et ne laisse aucune solution
solve-shape-conflict = { $first } et { $second } ne peuvent pas être installés ensemble
solve-shape-removal = supprimer { $package } laisserait des dépendances non satisfaites
solve-shape-unclassified = la transaction demandée n'a pas de solution

## Remedy : un changement qui rend la demande soluble. L'interface l'affiche après « Essayez : ».

solve-remedy-drop-target = retirer { $package } de la transaction
solve-remedy-allow-removal = accepter la suppression de { $package }
solve-remedy-choose-other = prendre { $provider } pour { $relation } à la place
solve-remedy-unignore = autoriser { $package }, que { $reason } exclut
