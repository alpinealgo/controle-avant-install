# Contrôle avant installation : lire le code d'un outil avant de l'installer

Des posts viraux vantent chaque semaine un nouvel outil GitHub « absolument dingue ». Avec n'importe quelle IA, l'installer prend une ligne. Mais un paquet inconnu peut lire vos clés, envoyer vos fichiers ailleurs ou s'installer pour de bon dans votre machine, dès l'installation et avant même que vous l'ayez lancé.

Ce script lit le code d'un paquet et de toutes ses dépendances avant que vous l'installiez, sans jamais l'exécuter, puis écrit un rapport en français. Il ne décide pas à votre place : il vous dit où regarder.

L'histoire complète, avec ce qui a raté en route : [Ma méthode pour tester un outil GitHub avant de l'installer](https://alpinealgo.substack.com/p/ma-methode-pour-tester-un-outil-github).

## Ce qu'il fait

- **Télécharge le paquet et tout son arbre de dépendances** (npm, PyPI, Composer) dans une quarantaine, ou lit un dossier déjà présent (serveur MCP, plugin, skill, dépôt cloné).
- **Résout les dépendances sans rien exécuter** : aucun script d'installation, un domicile vide, et sur macOS un enfermement `sandbox-exec` qui interdit au résolveur de lire ou d'écrire dans votre vrai dossier personnel.
- **Relève tout ce qui peut faire tourner du code ou faire sortir des données** : scripts d'installation, démarrage automatique (Python, Claude Code, éditeur, git), commandes système, exécution dynamique, code assemblé ou encodé, lecture de l'environnement et de fichiers sensibles (clés SSH, portefeuilles, mots de passe du navigateur), persistance, hôtes réseau, binaires illisibles.
- **Ouvre les archives imbriquées**, signale ce qu'il n'a pas pu lire au lieu de le sauter en silence, et vérifie les empreintes.
- **Interroge OSV.dev** sur les failles connues de tout l'arbre, et signale une publication très récente ; pour npm, aussi un changement d'éditeur entre deux versions.
- **Écrit un rapport Markdown.** Ce qu'il n'a pas pu faire (arbre non résolu, base de failles injoignable, fichier illisible) apparaît en alerte forte ; si le contrôle s'arrête en route, le rapport s'intitule « Contrôle incomplet » ou « Contrôle échoué ». Dans les deux cas, ne pas installer avant d'avoir compris pourquoi.

## Le banc d'essai : 99 pièges sur 99

Les pièges sont désarmés autant que le permet un test : les fichiers de code s'arrêtent à leur première ligne, les adresses visées n'existent pas et rien ne se télécharge depuis un registre. Quelques fichiers de réglages et de skills ne peuvent pas être arrêtés sans perdre leur intérêt : au pire, ils créent un fichier témoin, lancent `id` ou demandent quelque chose à une IA. La liste exacte est dans `banc/cases/LISEZ-MOI.md`. N'ouvrez pas ces dossiers dans un éditeur qui lance les tâches tout seul, et ne donnez pas leurs fichiers `SKILL.md` à une IA.

Le dossier `banc/cases` contient 99 faux paquets piégés (scripts d'installation détournés, code caché dans les tests, base64 exécuté, exfiltration vers un webhook, consignes cachées dans un skill pour une IA…) et des cas propres qui ne doivent rien lever de fort. La première version n'en repérait qu'un sur 29. Chaque contournement trouvé, souvent par une autre IA chargée de piéger le script, est devenu un nouveau cas.

```bash
python3 -I banc/run.py          # les pièges, sans réseau
python3 -I banc/run.py --dore   # de vrais paquets déjà acceptés, avec réseau
```

## L'utiliser

Prérequis : Python 3.11 ou plus récent ; `npm`, `uv` ou `composer` selon l'écosystème contrôlé. La résolution des dépendances demande macOS (`sandbox-exec`) : ailleurs, le script refuse de résoudre plutôt que de lancer un résolveur sans enfermement. La lecture d'un dossier marche partout.

```bash
python3 -I controle.py npm left-pad 1.3.0
python3 -I controle.py pypi requests 2.32.3
python3 -I controle.py composer monolog/monolog 3.8.1
python3 -I controle.py dir ./un-depot-clone
```

La version doit être figée : jamais `latest` ni une branche.

Limites connues : au-delà de 400 dépendances, seules les 400 premières sont lues (le rapport le signale) ; pour PyPI, l'arbre est résolu pour un Mac à puce Apple (arm64) et la version de Python du script ; pour Composer et PyPI, les empreintes des dépendances ne figurent pas toujours dans le rapport. Les rapports vont dans `~/controle-installs/` (ou dans le dossier donné par la variable `CONTROLE_RAPPORTS`) ; la quarantaine dans `~/Library/Caches/precheck/quarantaine`.

## Lire le rapport, pas le compteur

Le script signale ; c'est à vous de juger. Une alerte n'est pas une preuve : un outil en ligne de commande appelle `git` sans être malveillant. Ce qui doit vous arrêter, c'est le décalage : une librairie de graphiques qui lit vos variables d'environnement ou cite `~/.ssh`. Pour une faille annoncée, ouvrez l'avis et vérifiez que votre version est vraiment touchée.

## Avec Claude Code

`SKILL.md` est un skill prêt à copier dans `~/.claude/skills/controle-avant-install/` : Claude lance le contrôle avant chaque installation, vous montre le verdict en cinq lignes et attend votre accord.

## Ce que ce n'est pas

Pas une garantie. Un code malveillant bien caché peut passer un contrôle statique. Le contrôle réduit le risque ; une version figée et une installation isolée limitent les dégâts.

## Licence

MIT : vous pouvez le reprendre, le modifier et le partager, en gardant la mention de licence.
