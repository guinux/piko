# Le texte de --help, un message par doc comment de src/cli.rs. Voir src/help.rs.
#
# Une espace insécable (U+00A0) précède le deux-points, le point-virgule et le point
# d'interrogation.

help-about =
    Un gestionnaire de paquets ALPM simple et sûr
help-arg-dbpath =
    Chemin du répertoire de la base ALPM. Par défaut, le `DBPath` du pacman.conf lu (voir `--config`){" "}; à défaut, `/var/lib/pacman`, avec un avertissement, s'il ne peut pas être lu. Résolu par `realpath`, comme pacman le résout, il doit donc exister
help-arg-dbpath-long =
    Chemin du répertoire de la base ALPM. Par défaut, le `DBPath` du pacman.conf lu (voir `--config`){" "}; à défaut, `/var/lib/pacman`, avec un avertissement, s'il ne peut pas être lu. Résolu par `realpath`, comme pacman le résout, il doit donc exister.

    Avec `--root` et sans directive `DBPath`, la valeur par défaut est dans cette racine{" "}: `<root>/var/lib/pacman`. Il en va de même pour `--logfile` et `LogFile`.
help-arg-config =
    Chemin du fichier de configuration au format pacman.conf. Chaque sous-commande y lit ses valeurs par défaut{" "}: `DBPath`, `RootDir`, `CacheDir`, `LogFile`, les dépôts et leur `SigLevel`. `conf` l'affiche
help-arg-cache_dir =
    Répertoire où lire et télécharger les fichiers de paquets. Répétable, par priorité décroissante
help-arg-cache_dir-long =
    Répertoire où lire et télécharger les fichiers de paquets. Répétable, par priorité décroissante.

    Chaque répertoire donné ici passe avant la liste `CacheDir` du pacman.conf lu, sans la remplacer. L'option de pacman du même nom se comporte de la même façon. Un paquet est téléchargé dans le premier répertoire, et chaque répertoire est examiné pour un paquet déjà présent. Sans `--cachedir` et sans configuration lisible, c'est `/var/cache/pacman/pkg`. Résolu par `realpath`, comme pacman le résout, il doit donc exister.
help-arg-log_file =
    Chemin du journal des transactions. Par défaut, le `LogFile` du pacman.conf lu (voir `--config`){" "}; à défaut, `/var/log/pacman.log`, avec un avertissement, s'il ne peut pas être lu
help-arg-log_file-long =
    Chemin du journal des transactions. Par défaut, le `LogFile` du pacman.conf lu (voir `--config`){" "}; à défaut, `/var/log/pacman.log`, avec un avertissement, s'il ne peut pas être lu.

    C'est aussi le journal que pacman écrit. piko ajoute au même fichier, dans le même format, sous son propre nom d'appelant `[PIKO]`. `history` le relit.
help-list-about =
    Liste les paquets installés, les paquets d'un dépôt, ou les dépôts eux-mêmes
help-list-long-about =
    Liste les paquets installés, les paquets d'un dépôt, ou les dépôts eux-mêmes.

    Sans `--repos` ni `--repo`, liste chaque paquet installé, comme `--installed`. Seuls les noms de répertoires sont lus{" "}; aucune métadonnée de paquet n'est ouverte. `--repo <NAME>` liste à la place les paquets de ce dépôt. `--repos` liste à la place les dépôts configurés dans pacman.conf, un par ligne, dans l'ordre du fichier. Aucune base n'est ouverte dans ce cas. Se termine par un résumé d'une ligne, sauf avec `--quiet`.

    `-e/--explicit`, `-o/--orphans` et `-m/--foreign` remplacent chacun la liste des paquets installés par un autre filtre{" "}: respectivement `pacman -Qe`, `-Qdtt` et `-Qm`. Chacun est refusé avec `--repos`, avec `--repo` et avec les autres.

    `-g/--groups` liste des groupes plutôt que des paquets. C'est le seul filtre qui lit l'un ou l'autre côté. Il lit les paquets installés par défaut (`pacman -Qg`). Avec `--repos`, il lit chaque dépôt configuré, et avec `--repo <NAME>` ce seul dépôt (`pacman -Sg`).
help-list-arg-installed =
    Liste les paquets installés. C'est le comportement par défaut sans `--repos` ni `--repo`
help-list-arg-repos =
    Liste les dépôts configurés dans pacman.conf au lieu des paquets installés, un par ligne — aucune base n'est ouverte
help-list-arg-repo =
    Liste les paquets de ce dépôt, par exemple `core`
help-list-arg-explicit =
    Liste seulement les paquets installés explicitement — jamais tirés comme dépendance d'un autre paquet, `pacman -Qe`
help-list-arg-orphans =
    Liste les paquets installés seulement comme dépendance et qu'aucun paquet installé ne demande plus par `%DEPENDS%`. `%OPTDEPENDS%` ne compte jamais, comme pour `piko why` et `piko plan -R -s`. Équivaut à `pacman -Qdtt`
help-list-arg-foreign =
    Liste les paquets installés dont le nom n'est dans aucun dépôt configuré, `pacman -Qm`
help-list-arg-groups =
    Liste les membres des groupes donnés. Sans nom, liste à la place chaque nom de groupe. `--repos` et `--repo <NAME>` lisent les dépôts plutôt que les paquets installés, `pacman -Sg` plutôt que `pacman -Qg`
help-list-arg-groups-long =
    Liste les membres des groupes donnés. Sans nom, liste à la place chaque nom de groupe. `--repos` et `--repo <NAME>` lisent les dépôts plutôt que les paquets installés, `pacman -Sg` plutôt que `pacman -Qg`.

    Les noms de groupes doivent suivre `-g` directement, puisqu'il en prend un nombre quelconque{" "}: `list -g alpm --repos`, jamais `list -g --repos alpm`.
help-list-arg-with_members =
    Avec `--groups` et sans nom de groupe, liste chaque groupe *et* ses membres, plutôt que les seuls noms de groupes. `pacman -Qg`, et `pacman -Sgg`
help-list-arg-quiet =
    N'affiche que les noms, un par ligne — sans couleur, sans coche, sans résumé
help-files-about =
    Liste les fichiers que possèdent un ou plusieurs paquets
help-files-long-about =
    Liste les fichiers que possèdent un ou plusieurs paquets.

    Affiche `"{"{"}package{"}"} /{"{"}path{"}"}"` pour chaque fichier de chaque paquet nommé, un par ligne. `--quiet` retire le nom du paquet et n'affiche que `"/{"{"}path{"}"}"`. Cela diffère de la convention de `list`, qui affiche les noms seuls. Une liste de fichiers n'a pas de nom auquel se réduire, puisque le mode silencieux retire lui-même le nom du paquet. Un nom introuvable, ou dont la liste de fichiers est illisible, est signalé sur stderr. Les autres sont quand même traités. Le code de sortie n'est un échec que si quelque chose manquait ou était illisible.

    Sans `--installed` ni `--repo`, chaque nom est d'abord cherché parmi les paquets installés. Il est ensuite cherché dans les dépôts configurés, dans l'ordre du fichier (la priorité). `--installed` limite la recherche aux paquets installés. `--repo <NAME>` cherche à la place les paquets nommés dans l'archive `.files` de ce seul dépôt. Cette archive est parcourue une fois pour tous, plutôt qu'une fois par paquet.
help-files-arg-packages =
    Les paquets dont lister les fichiers
help-files-arg-installed =
    Cherche ces paquets parmi les paquets installés seulement
help-files-arg-repo =
    Cherche ces paquets dans ce seul dépôt, par exemple `core`
help-files-arg-quiet =
    N'affiche que les chemins des fichiers, un par ligne, sans le nom du paquet propriétaire
help-owns-about =
    Nomme le paquet installé qui possède un fichier
help-owns-long-about =
    Nomme le paquet installé qui possède un fichier.

    Affiche `"{"{"}path{"}"} appartient à {"{"}package{"}"} {"{"}version{"}"}"` pour chaque chemin donné. `--quiet` n'affiche que le nom du paquet. C'est l'inverse de `files`, et la commande lit les mêmes données `files`, dans l'autre sens. Elle lit une fois la liste de fichiers de chaque paquet installé, quel que soit le nombre de chemins nommés.

    Un chemin relatif est résolu depuis le répertoire de travail. Une cible sans `/` qui n'existe pas telle quelle est cherchée dans `$PATH`, donc `owns vim` nomme le paquet qui fournit le `vim` du chemin. L'existence est le seul critère{" "}: une entrée plus tôt dans `$PATH` l'emporte, même là où un shell la sauterait.

    Chaque composant sauf le dernier est résolu à travers ses liens symboliques. Le dernier ne l'est jamais. Donc `owns /usr/bin/vi` nomme le paquet qui fournit ce lien symbolique, pas celui qui fournit sa cible. Les deux sont des entrées de la liste de fichiers d'un paquet.

    La racine d'installation vient du `RootDir` de pacman.conf, comme pour `check`. Un chemin hors de cette racine appartient à la base d'une autre racine, donc la réponse ne nomme aucun propriétaire.

    Un répertoire nomme chaque paquet qui le possède, puisque des paquets qui partagent un répertoire, c'est ordinaire. Un fichier ne nomme que le premier propriétaire. Un chemin que rien ne possède est signalé sur stderr, et les chemins restants sont quand même traités. Le code de sortie n'est un échec que si un chemin n'avait pas de propriétaire.
help-owns-arg-paths =
    Les chemins de fichiers dont nommer le paquet propriétaire
help-owns-arg-quiet =
    N'affiche que le nom du paquet propriétaire, sans le chemin ni la version
help-info-about =
    Affiche les métadonnées d'un ou plusieurs paquets, depuis la base installée ou depuis une base de dépôt
help-info-long-about =
    Affiche les métadonnées d'un ou plusieurs paquets, depuis la base installée ou depuis une base de dépôt.

    Sans `--installed` ni `--repo`, chaque paquet est d'abord cherché parmi les paquets installés. Il est ensuite cherché dans les dépôts configurés, dans l'ordre du fichier (la priorité), jusqu'au premier qui l'a. C'est la règle «{" "}la première correspondance configurée l'emporte{" "}» que `resolve` applique à un nom littéral. `--installed` limite la recherche aux paquets installés. `--repo <NAME>` cherche chaque paquet dans ce seul dépôt.

    Les deux formes affichent des champs différents, comme `pacman -Qi` et `-Si`. Un paquet de dépôt ajoute `Dépôt` et `Taille du téléchargement`, et son `Validé par` nomme la somme de contrôle et la signature que publie son dépôt. Un paquet installé ajoute `Requis par`, `Optionnel pour`, `Date d'installation`, `Motif d'installation` et `Script d'installation`, et son `Validé par` nomme la façon dont il a été vérifié à l'installation.

    Plusieurs paquets affichent chaque entrée à son tour, séparées par une ligne vide. Un nom introuvable, ou dont le `desc` est illisible, est signalé sur stderr. Les autres sont quand même traités. Le code de sortie n'est un échec que si quelque chose manquait ou était illisible.
help-info-arg-packages =
    Les noms des paquets
help-info-arg-installed =
    Cherche ces paquets parmi les paquets installés seulement
help-info-arg-repo =
    Cherche ces paquets dans ce seul dépôt, par exemple `core`
help-check-about =
    Vérifie que les entrées concordent avec leurs fichiers `desc`, et que les fichiers installés correspondent à leurs données `ALPM-MTREE`
help-check-long-about =
    Vérifie que les entrées concordent avec leurs fichiers `desc`, et que les fichiers installés correspondent à leurs données `ALPM-MTREE`.

    Pour chaque fichier d'un paquet, la commande compare sept propriétés aux données `mtree` du paquet{" "}: l'existence, le type, le propriétaire, le mode, la date de modification, la taille et l'empreinte SHA-256. Pour un lien symbolique, elle compare la cible du lien au lieu de l'empreinte. Un paquet sans fichier `mtree` est signalé et sauté, pas compté comme un échec. La date de modification, la taille ou l'empreinte d'un fichier `%BACKUP%` peuvent différer, parce qu'un fichier de configuration modifié est censé différer. Toute autre différence reste un échec, fichier de sauvegarde ou non. Un fichier manquant qui correspond à `NoExtract` n'est pas signalé du tout.
help-check-arg-packages =
    Les noms des paquets à vérifier. Vérifie chaque paquet installé si aucun n'est donné
help-search-about =
    Cherche parmi les paquets installés et disponibles
help-search-long-about =
    Cherche parmi les paquets installés et disponibles.

    Chaque terme doit correspondre pour qu'un paquet soit retenu (par exemple, `firefox browser` ne trouve que les paquets qui correspondent aux deux). Mettez une expression de plusieurs mots entre guillemets (`"web browser"`) pour la chercher comme un seul terme. Les résultats sont classés du plus pertinent au moins pertinent. Un nom exact vient en premier, puis un `provides` exact, puis un préfixe du nom. Une sous-chaîne du nom vient ensuite, puis une sous-chaîne de la description, puis un groupe exact. Un paquet qui correspond à plusieurs termes est classé selon la meilleure de ces correspondances. Un paquet dont le `desc` est illisible est sauté, sauf s'il correspond par son seul nom.

    Sans `--installed` ni `--repos`, les deux sont cherchés. Chaque paquet installé qui correspond est affiché d'abord, marqué comme installé, puis chaque paquet de dépôt qui correspond et n'est pas installé. Un paquet à la fois installé et dans un dépôt est affiché une fois, côté installé, jamais deux.

    `--installed` ne cherche que parmi les paquets installés, et n'ouvre aucun dépôt. `--repos` ne cherche que dans les dépôts configurés. Il affiche chaque correspondance, installée ou non, un dépôt après l'autre dans l'ordre du fichier (la priorité), comme `pacman -Ss`.

    `--repo` limite la recherche à un seul dépôt nommé, par exemple `core`, et implique `--repos`. Un dépôt précis est en soi une demande limitée aux dépôts. Sinon, la ligne d'un paquet installé serait la même quel que soit le dépôt nommé. Être installé ne dépend d'aucun dépôt en particulier. Sans `--repo`, chaque dépôt configuré dont le `Usage` comprend `Search` est cherché, dans l'ordre du fichier (la priorité). Il est incompatible avec `--installed`.

    Le code de sortie est non nul quand rien ne correspond, comme pour `pacman -Ss`. Une recherche dont tous les termes sont vides est refusée.
help-search-arg-terms =
    Les termes de recherche{" "}; un paquet doit correspondre à tous
help-search-arg-terms-long =
    Les termes de recherche{" "}; un paquet doit correspondre à tous.

    Un terme qui contient `*`, `?` ou `[` est un motif glob, comparé au nom entier du paquet, à un nom `%PROVIDES%` ou à une entrée `%GROUPS%`. Les descriptions ne sont cherchées que par des termes simples. Mettez un motif entre guillemets, sinon le shell le développe d'abord.
help-search-arg-installed =
    Ne cherche que parmi les paquets installés
help-search-arg-repos =
    Ne cherche que dans les dépôts configurés, pas parmi les paquets installés
help-search-arg-repo =
    Ne cherche que dans ce dépôt, par exemple `core`. Implique `--repos`
help-search-arg-quiet =
    N'affiche que les noms, un par ligne — sans couleur, sans coche, sans préfixe de dépôt, sans résumé. Pour les scripts
help-check-updates-about =
    Cherche des mises à jour pour les paquets installés
help-check-updates-long-about =
    Cherche des mises à jour pour les paquets installés.

    Comme `pacman -Qu`{" "}: affiche `name old -> new` pour chaque paquet installé dont une version strictement plus récente est disponible. Pour un paquet présent dans plusieurs dépôts, le premier listé l'emporte. Un paquet installé mais absent de tous les dépôts (par exemple construit localement ou installé depuis une source étrangère) est sauté.

    Sans chemin d'archive de dépôt, la commande résout les dépôts depuis le pacman.conf lu. Elle prend `<dbpath>/sync/<name>.db` pour chaque dépôt configuré, dans l'ordre où ils apparaissent dans le fichier. Cet ordre est la priorité des dépôts. Un dépôt configuré sans base synchronisée sur le disque est sauté avec un avertissement, plutôt que de faire échouer toute la vérification. Tous les dépôts configurés n'ont pas besoin d'avoir été synchronisés.

    Se termine par un résumé d'une ligne (le nombre de mises à jour disponibles), sauf avec `--quiet`. `--quiet` n'affiche que le nom de chaque paquet, un par ligne, comme le `--quiet` de `list` et de `search`.
help-check-updates-arg-repo_paths =
    Chemins des archives de dépôt, par ordre de priorité. S'ils manquent, résolus depuis le pacman.conf lu
help-check-updates-arg-quiet =
    N'affiche que le nom du paquet installé, un par ligne — sans couleur, sans version, sans flèche, sans résumé
help-check-updates-arg-max_age =
    Avertit pour une base de dépôt publiée il y a plus de ce nombre de jours. 0 désactive l'avertissement
help-check-updates-arg-max_age-long =
    Avertit pour une base de dépôt publiée il y a plus de ce nombre de jours. 0 désactive l'avertissement.

    Un dépôt peu actif et un miroir figé se ressemblent par leur seul âge, donc la commande avertit et ne refuse jamais.
help-resolve-about =
    Résout une chaîne de dépendance vers les noms des paquets de dépôt qui la satisfont, un par ligne
help-resolve-long-about =
    Résout une chaîne de dépendance vers les noms des paquets de dépôt qui la satisfont, un par ligne.

    Ouvre chaque dépôt configuré dans le pacman.conf lu et essaie d'abord une correspondance littérale. Elle parcourt les dépôts dans l'ordre `[repo]` du fichier, à la recherche d'un paquet qui passe trois tests. Le `Usage` de son dépôt doit comprendre `Install` ou `Upgrade`. Il doit s'appeler littéralement `target` et satisfaire une éventuelle contrainte de version. Et il ne doit pas être couvert par le `IgnorePkg` ou le `IgnoreGroup` de la configuration lue. La résolution passe au dépôt suivant, comme dans libalpm. Un paquet présent dans plusieurs dépôts configurés se résout vers le premier listé, même si un dépôt suivant en a une version plus récente.

    Si aucun paquet ne s'appelle littéralement `target`, la commande cherche à la place dans chaque `%PROVIDES%` de chaque dépôt configuré. Elle affiche alors le nom de chaque paquet qui correspond, pas un seul. Un nom peut être fourni par plusieurs paquets{" "}: plusieurs implémentations d'un même paquet virtuel, par exemple, ou un même soname construit pour plusieurs architectures.

    Un nom simple (`foo`, `foo>=1.0`, `foo=1.2.3-1`) correspond à une entrée `%PROVIDES%` comme pour `_alpm_depcmp_provides`. Un nom nu correspond à toute version. Un provide sans version ne satisfait qu'une demande sans contrainte, et un provide de version exacte (`foo=1.2.3`) satisfait une contrainte compatible. Un soname (`lib:libexample.so.1`, `libexample.so=1.0.0-64`) ne correspond à une entrée `%PROVIDES%` que par égalité exacte, selon la règle «{" "}exact match{" "}» de `alpm-soname`.

    Ce n'est pas une résolution complète des dépendances. Elle ne traite ni les conflits ni les remplacements. Et contrairement à une vraie transaction, elle ne préfère pas un fournisseur déjà installé.
help-resolve-arg-target =
    La chaîne de dépendance{" "}: un nom de paquet avec une contrainte de version facultative (`foo`, `foo>=1.0`, `foo=1.2.3-1`), ou un soname (`lib:libexample.so.1`, `libexample.so=1.0.0-64`). Mettez-la entre guillemets dans le shell{" "}: sinon `>`, `>=`, `<` et `<=` sont des redirections
help-plan-about =
    Montre ce que ferait l'installation d'un ou plusieurs paquets, sans la faire
help-plan-long-about =
    Montre ce que ferait l'installation d'un ou plusieurs paquets, sans la faire.

    Résout chaque dépendance, de proche en proche, dans les dépôts configurés, applique `%CONFLICTS%` et `%REPLACES%`, et affiche l'ensemble de paquets obtenu. Rien n'est téléchargé, extrait ni écrit. Cette commande ne fait que planifier.

    Le plan reproduit la résolution de pacman chaque fois que pacman réussit. pacman échoue dans un cas où piko n'échoue pas{" "}: un fournisseur choisi en premier qui se révèle en conflit. Le solveur revient alors en arrière et le signale, plutôt que d'abandonner.
help-plan-arg-targets =
    Les paquets à planifier{" "}: une chaîne de dépendance (`foo`, `foo>=1.0`), un nom de groupe ou le chemin d'un fichier de paquet. Peut être vide avec `--sysupgrade`
help-plan-arg-targets-long =
    Les paquets à planifier{" "}: une chaîne de dépendance (`foo`, `foo>=1.0`), un nom de groupe ou le chemin d'un fichier de paquet. Peut être vide avec `--sysupgrade`.

    Avec `--remove`, une cible nomme un paquet installé, ou un groupe dont prendre chaque membre installé.

    Un nom qui contient `*`, `?` ou `[` est un motif glob, développé exactement comme `piko install` et `piko remove` en développent un. Mettez-le entre guillemets, sinon le shell le développe d'abord.

    Une URL de paquet est refusée ici, puisque la prévisualiser demanderait de la télécharger. Utilisez `piko install` pour cela.
help-plan-arg-needed =
    Saute une cible dont la version installée est déjà celle qui serait installée
help-plan-arg-names =
    N'affiche que les noms des paquets, un par ligne, pour comparer avec `pacman -Sp --print-format '%n'`
help-plan-arg-explain =
    Dit pourquoi chaque étape est dans le plan
help-plan-arg-explain-long =
    Dit pourquoi chaque étape est dans le plan.

    Chaque ligne nomme le paquet qui a tiré celui-ci, et l'entrée `%DEPENDS%` à laquelle il répond. La cause d'une étape est elle-même une étape du même plan, ou un paquet qui reste installé, donc une chaîne complète se lit en remontant la liste.

    Une deuxième ligne nomme un candidat écarté, quand c'est utile à savoir{" "}: un candidat que `IgnorePkg` ou `IgnoreGroup` a retenu, un que pacman aurait préféré, ou l'un de plusieurs fournisseurs sur lesquels personne n'a été interrogé.

    pacman n'a pas d'équivalent. Un plan dit ce qui va se passer{" "}; ceci dit pourquoi.
help-plan-arg-remove =
    Planifie la suppression des cibles au lieu de leur installation
help-plan-arg-recursive =
    Avec --remove, supprime aussi les dépendances dont plus rien n'a besoin
help-plan-arg-cascade =
    Avec --remove, supprime aussi les paquets qui dépendent des cibles, au lieu de refuser
help-plan-arg-sysupgrade =
    Planifie une mise à jour complète du système. Des cibles peuvent aussi être données, comme `pacman -Su foo` le permet{" "}; sans cible, tout est mis à jour
help-plan-arg-downgrade =
    Avec --sysupgrade, accepte aussi une version de dépôt plus ancienne que celle installée (`pacman -Suu`)
help-plan-arg-max_age =
    Avec --sysupgrade, avertit pour une base de dépôt publiée il y a plus de ce nombre de jours. 0 désactive l'avertissement
help-plan-arg-max_age-long =
    Avec --sysupgrade, avertit pour une base de dépôt publiée il y a plus de ce nombre de jours. 0 désactive l'avertissement.

    `plan` ne télécharge rien, donc il ne peut rien demander de plus récent à un miroir. Il dit seulement que le plan repose sur une base ancienne.
help-why-about =
    Explique pourquoi un paquet installé est présent
help-why-long-about =
    Explique pourquoi un paquet installé est présent.

    Parcourt en largeur le graphe des dépendances inverses et affiche la plus courte chaîne d'un paquet installé explicitement jusqu'à la cible. `pacman -Qi` donne une liste «{" "}Required By{" "}», qui répond à «{" "}qu'est-ce qui casserait{" "}?{" "}» plutôt qu'à «{" "}pourquoi est-il là{" "}?{" "}». Suivre cette liste à la main sur plusieurs niveaux, c'est la question à laquelle cette commande répond directement.
help-why-arg-package =
    Le nom du paquet installé
help-install-about =
    Installe un ou plusieurs paquets
help-install-long-about =
    Installe un ou plusieurs paquets.

    Résout une cible qui nomme un paquet exactement comme `piko plan`, dans les dépôts configurés. La commande essaie d'abord un nom littéral ou une chaîne de dépendance (`foo`, `foo>=1.0`), puis les membres d'un `%GROUPS%`. Une cible qui nomme un fichier de paquet est lue dans ce fichier. La commande planifie ensuite toutes les dépendances, de proche en proche, avec les conflits et les remplacements, avant d'en installer quoi que ce soit. `piko install foo`, c'est `piko plan foo` transformé en transaction.

    Un paquet déjà dans un répertoire de cache est utilisé tel quel. Un paquet manquant est téléchargé depuis les serveurs configurés de son propre dépôt, vérifié et mis en cache avant l'installation. C'est le même téléchargement séquentiel, sans reprise, que `piko refresh` fait déjà pour une base.

    Sans `--root`, la commande résout le `RootDir` du pacman.conf lu. Voir `--config`. À défaut, elle prend `/`, avec un avertissement, s'il ne peut pas être lu.

    Les signatures des paquets sont vérifiées selon le `SigLevel` du dépôt d'où chaque paquet a été résolu. Un fichier de paquet nommé par son chemin relève à la place de `LocalFileSigLevel`, et un fichier nommé par une URL de `RemoteFileSigLevel`. Par défaut, un paquet non signé est accepté, et un paquet signé doit être de confiance.

    Un fichier de paquet nommé, c'est `pacman -U`. Ses propres dépendances sont toujours résolues dans les dépôts configurés, et il passe avant toute construction du même paquet dans un dépôt. Une URL est téléchargée avant que le plan s'affiche, donc `piko install <url>` accède au réseau avant de demander confirmation.
help-install-arg-root =
    Où installer. Utilisez `/` pour le système en cours
help-install-arg-packages =
    Les paquets à installer{" "}: une chaîne de dépendance (`foo`, `foo>=1.0`), un nom de groupe, le chemin d'un fichier de paquet, ou son URL
help-install-arg-packages-long =
    Les paquets à installer{" "}: une chaîne de dépendance (`foo`, `foo>=1.0`), un nom de groupe, le chemin d'un fichier de paquet, ou son URL.

    Une cible est lue comme un fichier de paquet dans trois cas. Si elle contient `://`, c'est une URL. Si elle contient `/`, c'est un chemin. Et si elle se termine par `.pkg.tar[.gz|.bz2|.xz|.zst]` et nomme un fichier qui existe ici, c'est ce fichier. Tout le reste est un nom. Écrivez `./foo.pkg.tar.zst` pour dire «{" "}le fichier{" "}» là où les deux lectures sont possibles.

    Un nom qui contient `*`, `?` ou `[` est un motif glob, comparé aux noms entiers des paquets et des groupes. Mettez-le entre guillemets, sinon le shell le développe d'abord. Les lectures comme fichier ci-dessus l'emportent toujours, donc `./foo*` est un chemin plutôt qu'un motif. Un motif ne peut pas porter de contrainte de version.
help-install-arg-needed =
    Saute une cible dont la version installée est déjà celle qui serait installée
help-install-arg-needed-long =
    Saute une cible dont la version installée est déjà celle qui serait installée.

    L'option de pacman du même nom. Elle s'applique aux paquets nommés sur la ligne de commande. Une dépendance n'est pas concernée. piko n'en installe une que là où quelque chose en a besoin, donc ce n'est jamais une réinstallation.
help-install-arg-asdeps =
    Enregistre chaque paquet installé comme dépendance plutôt que comme installé explicitement
help-install-arg-asdeps-long =
    Enregistre chaque paquet installé comme dépendance plutôt que comme installé explicitement.

    L'option de pacman du même nom. Elle couvre toute la transaction, dépendances résolues comprises. Elle remplace aussi la raison qu'un paquet mis à jour portait déjà. Incompatible avec `--asexplicit`.
help-install-arg-asexplicit =
    Enregistre chaque paquet installé comme installé explicitement plutôt que comme dépendance
help-install-arg-asexplicit-long =
    Enregistre chaque paquet installé comme installé explicitement plutôt que comme dépendance.

    L'option de pacman du même nom, l'inverse de `--asdeps`. Elle couvre toute la transaction. Elle remplace aussi la raison qu'un paquet mis à jour portait déjà. Une dépendance installée avec elle n'est pas candidate comme orpheline pour `piko list --orphans`.
help-install-arg-overwrite =
    Écrase les fichiers qu'un autre paquet possède, pour les chemins qui correspondent à ces motifs glob
help-install-arg-overwrite-long =
    Écrase les fichiers qu'un autre paquet possède, pour les chemins qui correspondent à ces motifs glob.

    piko refuse par défaut. Écrire un fichier qu'un autre paquet possède laisse la base déclarer deux propriétaires pour un chemin. Supprimer l'un ou l'autre paquet supprime alors un fichier dont l'autre a encore besoin. Répétable, comparé au chemin sans `/` au début.
help-install-arg-noscriptlet =
    N'exécute pas le scriptlet `.INSTALL` d'un paquet
help-install-arg-noscriptlet-long =
    N'exécute pas le scriptlet `.INSTALL` d'un paquet.

    L'option de pacman du même nom. Un scriptlet est du code shell écrit par l'empaqueteur, exécuté avec les privilèges de piko dans `--root`. Le sauter laisse le paquet installé, mais ce que le scriptlet devait mettre en place reste à faire.
help-install-arg-hookdir =
    Lit les hooks dans ces répertoires au lieu de ceux configurés
help-install-arg-hookdir-long =
    Lit les hooks dans ces répertoires au lieu de ceux configurés.

    L'option de pacman du même nom. Répétable, par priorité croissante. Un nom de fichier de hook trouvé dans un répertoire suivant remplace le même nom dans un répertoire précédent. Indiquez un répertoire vide pour n'exécuter aucun hook.
help-install-arg-noconfirm =
    Répond «{" "}oui{" "}» à la demande de confirmation au lieu de la poser
help-install-arg-noconfirm-long =
    Répond «{" "}oui{" "}» à la demande de confirmation au lieu de la poser.

    L'option de pacman du même nom. Le plan est affiché dans tous les cas. Cette option ne fait que ne pas attendre de réponse, pour un usage scripté ou automatisé.
help-install-arg-download_only =
    Télécharge chaque paquet manquant dans le cache sans rien installer
help-install-arg-download_only-long =
    Télécharge chaque paquet manquant dans le cache sans rien installer.

    Le `-Sw` de pacman. Le plan est affiché et confirmé exactement comme pour une installation ordinaire. Rien n'est extrait, aucune entrée de base n'est écrite, et ni le journal ni le verrou ne sont touchés. Un `install` ultérieur des mêmes cibles trouve alors tout en cache.
help-update-about =
    Met à jour les paquets installés
help-update-long-about =
    Met à jour les paquets installés.

    Résout la mise à jour complète du système exactement comme `piko plan -u`. Pour chaque paquet installé, le premier dépôt configuré qui porte son nom décide du résultat. La commande examine une paire `%REPLACES%` avant le nom littéral, si le `Usage` comprend `Upgrade`. La transaction obtenue est planifiée par le même solveur que celui de `install`. Ainsi, une construction de dépôt en conflit avec un paquet installé le supprime, et une nouvelle dépendance requise est tirée. `install` traite chacun de ces cas de la même façon. `piko plan -u [targets]` est l'aperçu de cette commande, et affiche le même plan que celui qu'elle applique.

    Rafraîchit d'abord chaque dépôt configuré, `pacman -Syu`. `--norefresh` saute cette étape et planifie avec ce qui est déjà sur le disque, `pacman -Su`. Un rafraîchissement qui échoue arrête tout. La mise à jour n'est pas planifiée avec une base dont le rafraîchissement n'a pas pu confirmer qu'elle est à jour.

    Comme pour `install`, sans `--root`, la commande résout le `RootDir` du pacman.conf lu.
help-update-arg-root =
    Où mettre à jour. Utilisez `/` pour le système en cours
help-update-arg-targets =
    Cibles supplémentaires à installer avec la mise à jour, comme `pacman -Su foo` le permet. Sans cible, chaque paquet installé est vérifié. Une cible qui contient `*`, `?` ou `[` est un motif glob, développé exactement comme `piko install` en développe un
help-update-arg-needed =
    Saute une cible nommée dont la version installée est déjà celle qui serait installée
help-update-arg-needed-long =
    Saute une cible nommée dont la version installée est déjà celle qui serait installée.

    L'option de pacman du même nom. Elle s'applique aux cibles nommées sur la ligne de commande. La mise à jour compare les versions d'elle-même. Elle laisse un paquet à jour tel quel, avec ou sans cette option.
help-update-arg-downgrade =
    Accepte une version de dépôt plus ancienne que celle installée (`pacman -Suu`)
help-update-arg-norefresh =
    Ne rafraîchit pas d'abord les bases des dépôts (`pacman -Su`)
help-update-arg-force =
    Rafraîchit même une base que le serveur dit inchangée (`pacman -Syyu`)
help-update-arg-force-long =
    Rafraîchit même une base que le serveur dit inchangée (`pacman -Syyu`).

    Saute entièrement la requête conditionnelle, donc un `304` ne peut jamais revenir. Ignoré avec `--norefresh`, puisque rien n'est téléchargé dans ce cas.

    Contrairement au `-Syy` de pacman, cette option n'accepte pas une base plus ancienne que celle installée. C'est le rôle de `--accept-older`.
help-update-arg-accept_older =
    Installe une base de dépôt même si elle est plus ancienne que celle installée
help-update-arg-accept_older-long =
    Installe une base de dépôt même si elle est plus ancienne que celle installée.

    Utilisez-la pour revenir à un instantané antérieur, comme l'Arch Linux Archive, avec `--downgrade`. Sans elle, une base plus ancienne est refusée et le serveur suivant est essayé.
help-update-arg-max_age =
    Avertit pour une base de dépôt publiée il y a plus de ce nombre de jours. 0 désactive l'avertissement
help-update-arg-max_age-long =
    Avertit pour une base de dépôt publiée il y a plus de ce nombre de jours. 0 désactive l'avertissement.

    Un dépôt peu actif et un miroir figé se ressemblent par leur seul âge, donc la commande avertit et ne refuse jamais.
help-update-arg-overwrite =
    Écrase les fichiers qu'un autre paquet possède, pour les chemins qui correspondent à ces motifs glob
help-update-arg-noscriptlet =
    N'exécute pas le scriptlet `.INSTALL` d'un paquet
help-update-arg-hookdir =
    Lit les hooks dans ces répertoires au lieu de ceux configurés
help-update-arg-noconfirm =
    Répond «{" "}oui{" "}» à la demande de confirmation au lieu de la poser
help-update-arg-download_only =
    Télécharge chaque paquet manquant dans le cache sans rien installer (`pacman -Suw`)
help-remove-about =
    Supprime des paquets installés
help-remove-long-about =
    Supprime des paquets installés.

    Comme pour `install`, sans `--root`, la commande résout le `RootDir` du pacman.conf lu.

    Une cible nomme un paquet installé, ou un groupe, qui prend chacun de ses membres installés. Un paquet l'emporte sur un groupe du même nom.

    L'ensemble des paquets supprimés est décidé par le même planificateur que celui qu'affiche `piko plan -R`. Cette commande en est donc un aperçu exact. Supprimer un paquet dont autre chose dépend encore est refusé. `-c` supprime en cascade à la place. `-s` retire aussi les dépendances dont plus rien n'a besoin.
help-remove-arg-root =
    D'où supprimer. Utilisez `/` pour le système en cours
help-remove-arg-packages =
    Des noms de paquets installés, ou un nom de groupe dont supprimer chaque membre installé
help-remove-arg-packages-long =
    Des noms de paquets installés, ou un nom de groupe dont supprimer chaque membre installé.

    Un nom qui contient `*`, `?` ou `[` est un motif glob, comparé aux noms entiers des paquets et des groupes installés. Mettez-le entre guillemets, sinon le shell le développe d'abord. `--nodeps` ne développe un motif que sur les noms de paquets, puisqu'il n'a jamais pris de groupe.
help-remove-arg-nosave =
    Ne crée pas de fichiers `.pacsave` pour les fichiers de configuration modifiés
help-remove-arg-recursive =
    Supprime aussi les dépendances dont plus rien n'a besoin
help-remove-arg-cascade =
    Supprime les paquets qui dépendent des cibles, au lieu de refuser
help-remove-arg-nodeps =
    Supprime exactement les paquets nommés, sans rien vérifier
help-remove-arg-nodeps-long =
    Supprime exactement les paquets nommés, sans rien vérifier.

    La porte de sortie, équivalente au `-Rdd` de pacman. Elle peut laisser le système avec des dépendances non satisfaites. C'est précisément ce qu'on demande avec elle.
help-remove-arg-noscriptlet =
    N'exécute pas le scriptlet `.INSTALL` d'un paquet
help-remove-arg-hookdir =
    Lit les hooks dans ces répertoires au lieu de ceux configurés
help-remove-arg-noconfirm =
    Répond «{" "}oui{" "}» à la demande de confirmation au lieu de la poser
help-remove-arg-noconfirm-long =
    Répond «{" "}oui{" "}» à la demande de confirmation au lieu de la poser.

    L'option de pacman du même nom. Le plan est affiché dans tous les cas. Cette option ne fait que ne pas attendre de réponse, pour un usage scripté ou automatisé.
help-refresh-about =
    Télécharge les bases des dépôts
help-refresh-long-about =
    Télécharge les bases des dépôts.

    Le `-Sy` de pacman. Avec `--files`, aussi son `-Fy`. La liste `Server` de chaque dépôt configuré est essayée dans l'ordre{" "}; le premier qui répond l'emporte. Grâce à une requête conditionnelle, une base inchangée coûte un aller-retour plutôt qu'un téléchargement.

    {"*"}*La signature est vérifiée avant que le téléchargement ne remplace quoi que ce soit.** Une base qui ne satisfait pas le `SigLevel` de son dépôt est écartée. La base existante reste en place. Ainsi, un miroir hostile ou défaillant ne peut pas dégrader un système qui fonctionne.

    {"*"}*Une base plus ancienne que celle installée est refusée aussi.** Une signature ne prouve pas qu'une base est à jour, et un miroir peut en rejouer une ancienne. Le serveur suivant est essayé à la place. Une base publiée il y a plus longtemps que `--max-age` envoie le rafraîchissement vers quelques serveurs de plus pour en trouver une plus récente, puis avertit.
help-refresh-arg-repos =
    Les dépôts à rafraîchir. Rafraîchit chaque dépôt configuré si aucun n'est donné
help-refresh-arg-force =
    Rafraîchit même une base que le serveur dit inchangée
help-refresh-arg-force-long =
    Rafraîchit même une base que le serveur dit inchangée.

    Saute entièrement la requête conditionnelle, donc un `304` ne peut jamais revenir. Utilisez-la pour une base corrompue localement, ou pour un miroir dont l'horloge contredit son propre `Last-Modified`.

    Contrairement au `-Syy` de pacman, cette option n'accepte pas une base plus ancienne que celle installée. C'est le rôle de `--accept-older`.
help-refresh-arg-accept_older =
    Installe une base même si elle est plus ancienne que celle installée
help-refresh-arg-accept_older-long =
    Installe une base même si elle est plus ancienne que celle installée.

    Une signature valide prouve qui a fait une base, pas qu'elle est à jour. Donc une base plus ancienne que celle installée est refusée, et le serveur suivant est essayé. Utilisez cette option pour revenir volontairement à un instantané antérieur, comme l'Arch Linux Archive.
help-refresh-arg-max_age =
    Avertit pour une base de dépôt publiée il y a plus de ce nombre de jours. 0 désactive l'avertissement
help-refresh-arg-max_age-long =
    Avertit pour une base de dépôt publiée il y a plus de ce nombre de jours. 0 désactive l'avertissement.

    Un dépôt peu actif et un miroir figé se ressemblent par leur seul âge, donc la commande avertit et ne refuse jamais.
help-refresh-arg-files =
    Rafraîchit aussi la base `<repo>.files` de chaque dépôt
help-refresh-arg-files-long =
    Rafraîchit aussi la base `<repo>.files` de chaque dépôt.

    Ce sont les listes de fichiers que lit `piko files --repo <NAME>`. pacman répartit cela sur deux opérations, `-Sy` et `-Fy`. Un seul passage laisse les deux archives décrire les mêmes constructions.
help-report-about =
    Décrit une transaction inachevée, si la base en enregistre une
help-report-long-about =
    Décrit une transaction inachevée, si la base en enregistre une.

    En lecture seule{" "}: la commande décrit ce qui a été interrompu et jusqu'où la transaction est allée, et affiche les commandes qui la terminent. Elle ne peut pas défaire ce qui a été appliqué. piko ne garde aucune copie des fichiers écrasés, il n'y a donc rien vers quoi revenir.
help-history-about =
    Affiche les transactions que ce système a exécutées, la plus récente en dernier
help-history-long-about =
    Affiche les transactions que ce système a exécutées, la plus récente en dernier.

    Lit le journal des transactions (`--logfile`, ou le `LogFile` de pacman.conf), que pacman écrit aussi, donc la commande couvre les transactions de l'un et l'autre outil. Chacune est affichée avec l'outil qui l'a exécutée, la ligne de commande quand le journal l'a enregistrée, et ce qu'elle a fait.

    Les transactions de piko portent plus que ce que le format du journal peut contenir{" "}: la ligne de commande exacte, les fichiers `.pacnew` laissés, et la raison de l'échec d'une transaction. Ce détail vient de `<dbpath>/piko-history`, et il est fusionné là où il existe.

    En lecture seule. La commande décrit, ne change rien, et ne peut pas défaire une transaction.
help-history-arg-last =
    Affiche au plus ce nombre de transactions. Les plus récentes sont gardées
help-history-arg-package =
    N'affiche que les transactions qui ont touché ce paquet. Répétable
help-history-arg-since =
    N'affiche que les transactions commencées à cet instant ou après, sous la forme `YYYY-MM-DD` ou complète `YYYY-MM-DDTHH:MM:SS+ZZZZ`
help-history-arg-since-long =
    N'affiche que les transactions commencées à cet instant ou après, sous la forme `YYYY-MM-DD` ou complète `YYYY-MM-DDTHH:MM:SS+ZZZZ`.

    Une date seule désigne la journée entière, dans l'heure locale de l'affichage, et les deux bornes l'incluent. Ainsi, `--since D --until D` affiche chaque transaction que la liste date du jour D.
help-history-arg-until =
    N'affiche que les transactions commencées à cet instant ou avant, dans les mêmes formes que `--since`. Une date seule va jusqu'à la dernière seconde de ce jour, pas jusqu'à son minuit
help-history-arg-all =
    Affiche chaque transaction, en ignorant `--last`
help-history-arg-quiet =
    Affiche une ligne par transaction, sans détail par paquet
help-merge-about =
    Règle les fichiers .pacnew et .pacsave laissés par les transactions
help-merge-long-about =
    Règle les fichiers .pacnew et .pacsave laissés par les transactions.

    Une transaction qui rencontre un fichier de configuration que vous avez modifié garde les deux copies. La version du paquet est posée à côté de la vôtre sous le nom `<path>.pacnew`, ou la vôtre est gardée sous le nom `<path>.pacsave` quand le paquet disparaît. La commande trouve chacun de ces fichiers et propose une décision par fichier{" "}: voir la différence, fusionner à trois voies avec une construction plus ancienne d'un répertoire de cache, le sauter, le supprimer, ou écraser le fichier installé avec lui. C'est l'équivalent de pacdiff.

    Les fichiers en attente sont trouvés par les entrées %BACKUP% des paquets installés, donc chacun arrive avec le paquet qui l'a déclaré.

    Un fichier en attente identique au fichier installé n'apporte rien, il est donc supprimé sans demander. Un fichier que piko n'a pas pu lire est signalé et sauté{" "}; aucune action destructrice n'est proposée pour une paire qu'il n'a pas pu comparer. Un `.pacsave.N` est listé et signalé, jamais proposé{" "}: c'est une copie historique, sans version actuelle avec laquelle la fusionner.

    Il n'y a pas de --noconfirm. Supprimer un fichier, en écraser un et en fusionner deux sont trois actes irréversibles différents, et aucun n'est un choix par défaut sûr. Utilisez --output pour une liste non interactive.

    Les programmes de différence et de fusion s'exécutent sur l'hôte, avec ce terminal et avec les privilèges de piko. Ils ne s'exécutent jamais dans --root. Un programme qui lit un fichier de configuration lit celui de root sous sudo, donc `DIFFPROG='vim -d'` exécute le vimrc de root.
help-merge-arg-root =
    Où chercher. Par défaut, le RootDir de pacman.conf, ou `/`
help-merge-arg-output =
    Affiche les fichiers en attente, un chemin absolu par ligne, et ne change rien
help-merge-arg-diffprog =
    Le programme qui montre une différence. Par défaut, $DIFFPROG, puis `diff -u`
help-merge-arg-diffprog-long =
    Le programme qui montre une différence. Par défaut, $DIFFPROG, puis `diff -u`.

    Le programme par défaut affiche la différence et rend la main, donc la question est reposée juste après. Indiquez un éditeur, comme `vim -d`, pour modifier les fichiers dedans.

    Découpé sur les espaces, `'` et `"` regroupant une suite de caractères. Aucun shell ne s'exécute, donc rien n'est développé{" "}; une valeur qui en demande un doit le nommer, comme dans `sh -c ...`.
help-merge-arg-mergeprog =
    Le programme qui fusionne trois fichiers. Par défaut, $MERGEPROG, puis `diff3 -m`
help-merge-arg-mergeprog-long =
    Le programme qui fusionne trois fichiers. Par défaut, $MERGEPROG, puis `diff3 -m`.

    Il reçoit le fichier installé, la base et le fichier en attente, dans cet ordre, et sa sortie standard est le résultat de la fusion. Découpé comme --diffprog.
help-merge-arg-threeway =
    Montre une différence à trois voies plutôt qu'à deux, quand une base est disponible
help-merge-arg-threeway-long =
    Montre une différence à trois voies plutôt qu'à deux, quand une base est disponible.

    Cette option passe trois chemins à --diffprog, il lui faut donc un programme qui en lit trois. `diff` en prend deux{" "}; `vim -d` en prend trois.
help-merge-arg-paths =
    Ne règle que ces chemins, au lieu de tout ce qui est en attente. Le fichier installé comme le fichier en attente désigne une paire
help-merge-arg-paths-long =
    Ne règle que ces chemins, au lieu de tout ce qui est en attente. Le fichier installé comme le fichier en attente désigne une paire.

    Un chemin est pris tel que --output l'affiche, ou comme un chemin dans --root. Un chemin qui ne désigne aucun fichier en attente est une erreur.
help-conf-about =
    Analyse et affiche un fichier de configuration au format pacman.conf
help-conf-long-about =
    Analyse et affiche un fichier de configuration au format pacman.conf.

    Affiche `[options]` suivi de chaque directive prise en charge, une fois les valeurs par défaut résolues. Une directive absente du fichier montre quand même sa valeur par défaut, comme le fait `pacman-conf`. Puis la commande affiche un bloc `[reponame]` par dépôt configuré, dans l'ordre où ils apparaissent dans le fichier. Cet ordre est la priorité des dépôts.

    Un nom de directive n'affiche à la place que la valeur de cette directive, sans en-tête `[options]` et sans nom. Une directive à plusieurs valeurs en affiche une par ligne. Une directive booléenne affiche son propre nom si elle est activée, et rien sinon. Le nom est comparé sans tenir compte de la casse, comme `pacman-conf` le compare. Un nom inconnu est une erreur. Une directive de dépôt (`Server`, `Usage`) n'est pas un nom accepté, puisque seule la section `[options]` est interrogée.
help-conf-arg-directive =
    La directive à afficher, par exemple `DBPath`. Affiche chaque directive si aucune n'est donnée
help-key-about =
    Initialise et administre le trousseau GnuPG avec lequel les signatures sont vérifiées
help-key-long-about =
    Initialise et administre le trousseau GnuPG avec lequel les signatures sont vérifiées.

    C'est l'équivalent de pacman-key. Chaque opération passe par GPGME, jamais par un sous-processus `gpg`.
help-key-arg-gpgdir =
    Le répertoire personnel GnuPG à administrer. Par défaut, le `GPGDir` du pacman.conf lu (voir `--config`){" "}; à défaut, `/etc/pacman.d/gnupg`, avec un avertissement, s'il ne peut pas être lu
help-key-arg-keyring_dir =
    Où `populate` lit `<name>.gpg`, `<name>-trusted` et `<name>-revoked`
help-key-init-about =
    Crée le trousseau s'il n'existe pas, et génère la clé maîtresse de signature locale de piko s'il n'y en a pas encore. Peut être relancé{" "}; une deuxième exécution ne change rien
help-key-populate-about =
    Importe et accorde une confiance locale à un ou plusieurs trousseaux nommés de `--keyring-dir`. Sans nom, chaque trousseau qui s'y trouve est importé
help-key-populate-arg-keyrings =
    Les noms des trousseaux (par exemple `archlinux`), qui correspondent à `<name>.gpg` dans `--keyring-dir`
help-key-add-about =
    Importe des clés OpenPGP depuis un ou plusieurs fichiers
help-key-add-arg-files =
    Les fichiers à importer, en ASCII armuré ou en binaire
help-key-lsign-key-about =
    Signe localement (sans exportation) une ou plusieurs clés, pour les établir dans la toile de confiance
help-key-lsign-key-arg-keyids =
    Les empreintes (ou tout identifiant que GnuPG accepte) des clés à signer
help-key-lsign-key-arg-noconfirm =
    Saute la demande de confirmation et continue comme si l'utilisateur avait répondu oui
help-key-list-keys-about =
    Liste les clés du trousseau
help-key-list-keys-arg-keyids =
    Ne liste que les clés qui correspondent à ces identifiants. Sans identifiant, chaque clé est listée
help-key-delete-about =
    Supprime une ou plusieurs clés du trousseau. Ne supprime que les clés publiques, sauf avec `--secret`
help-key-delete-arg-keyids =
    Les empreintes (ou tout identifiant que GnuPG accepte) des clés à supprimer
help-key-delete-arg-secret =
    Supprime aussi la clé secrète d'une clé, y compris la clé maîtresse de piko. Sans cette option, piko refuse une clé qui en a une. La clé maîtresse signe chaque certification locale du trousseau. Une clé maîtresse supprimée laisse ces clés sans confiance
help-key-delete-arg-noconfirm =
    Saute la demande de confirmation et continue comme si l'utilisateur avait répondu oui
help-key-verify-about =
    Vérifie une signature détachée
help-key-verify-arg-signature =
    Le fichier `.sig` ou `.asc`
help-key-verify-arg-file =
    Le fichier signé. Par défaut, `signature` sans son extension
help-key-updatedb-about =
    Force GnuPG à recalculer la validité des clés depuis la base de confiance actuelle
