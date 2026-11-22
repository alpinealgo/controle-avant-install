# Faux paquets piégés : ne pas exécuter

Ces dossiers servent seulement à tester `controle.py`. Ils imitent de vrais paquets malveillants : scripts d'installation détournés, effacement de fichiers, envoi de secrets, consignes cachées pour une IA.

## Ce qui est désarmé

- Les fichiers `.js`, `.mjs`, `.cjs`, `.py`, `.php`, `.rb`, `.sh` et les scripts shell sans extension s'arrêtent à leur première ligne. Seule exception : `e06_faux_gif/a.js` commence par une signature d'image qui fait planter JavaScript avant la charge.
- Les adresses visées n'existent pas (domaine `.invalid`, adresse IP `192.0.2.1` réservée à la documentation, `example.net`).
- Rien ne se télécharge depuis un registre : `mcp_json` appelle `npx --no-install` sur un nom inventé, `pyproject_backend` ne demande aucun paquet, `npmrc_embarque` désigne un shell qui n'existe pas.

## Ce qui reste actif si on le lance exprès

Ces fichiers ne peuvent pas porter de ligne d'arrêt sans perdre leur intérêt pour le test :

| Dossier | Ce qu'il ferait |
|---|---|
| `crochet_plugin`, `vscode_task` | télécharger un script depuis une adresse `.invalid` (échoue) |
| `devcontainer`, `vscode_tache_echappee`, `e14_zshenv`, `e11_gemspec`, `pth_octet_nul` | créer le fichier témoin `/tmp/precheck-proof` |
| `ext_jsx`, `fichier_pth`, `zip_python` (archive) | lancer la commande `id`, qui affiche l'utilisateur |
| `ps1_utf16` | ouvrir la calculatrice de Windows |
| `payload_txt` | rien seul : du code dans un fichier texte |
| `c02_doc_retrograde`, `e18_shrinkwrap` | rien seul : une commande en exemple dans la doc, une dépendance qui pointe vers `example.net` |
| `skill_injection` | lire une clé SSH et l'envoyer vers une adresse `.invalid` (échoue), si une IA charge ce skill |
| `c09_skill_sabotage` | demander à une IA de mettre à zéro les montants d'un fichier `accounts.csv` |
| `e16_allowed_tools_liste`, `skill_bash` | donner à une IA le droit de lancer des commandes |

Ne lancez rien ici, n'ouvrez pas ces dossiers dans un éditeur qui exécute les tâches tout seul, n'installez aucun de ces dossiers, et ne donnez pas leurs `SKILL.md` à une IA.
