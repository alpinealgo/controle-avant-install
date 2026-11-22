#!/usr/bin/env python3 -I
"""Contrôle d'un paquet tiers AVANT installation (projet controle-avant-install, AlpineAlgo).

Télécharge le paquet et TOUTES ses dépendances dans une quarantaine, sans exécuter leur code, puis relève
tout ce qui peut faire tourner du code ou faire sortir des données : points d'exécution automatique
(installation, démarrage de Python, Claude Code, éditeur, git), commandes, exécution dynamique, code
assemblé ou encodé, environnement, fichiers sensibles, persistance, réseau, binaires illisibles,
archives imbriquées (ouvertes et lues), fichiers non lus, publication récente, changement d'éditeur,
intégrité, dépendances hors registre, failles connues de tout l'arbre.
Les résolveurs (npm, uv, composer) tournent sans scripts, avec un domicile vide, et sous sandbox-exec
qui leur interdit de lire ou d'écrire dans le vrai domicile.
Ne décide pas : le verdict revient à une personne, qui lit le rapport avant d'installer.

Usage : controle.py npm|pypi|composer <nom> <version>
        controle.py dir <chemin>          (code déjà présent : serveur MCP, plugin, mod, dépôt cloné)
        --json en dernier argument : affiche aussi les clés d'alerte en JSON.
Banc d'essai : banc/run.py (et banc/run.py --dore), à relancer après toute modification.
"""
import unicodedata, base64, binascii, bisect, bz2, collections, concurrent.futures, datetime, gzip, hashlib, ipaddress, json, lzma, os, pathlib, re, shutil, socket, subprocess, sys, tarfile, tempfile, traceback, urllib.parse, urllib.request, zipfile

OUT = pathlib.Path(os.environ.get("CONTROLE_RAPPORTS", pathlib.Path.home() / "controle-installs"))
Q_ROOT = pathlib.Path.home() / "Library" / "Caches" / "precheck" / "quarantaine"   # hors iCloud : du code suspect ne se synchronise pas
MAX_READ = 25_000_000            # au-delà : signalé non lu (ou natif), jamais sauté en silence
MAX_DOWNLOAD = 1_500_000_000
MAX_EXTRACT_TOTAL = 4_000_000_000
MAX_MEMBER = 1_500_000_000
MAX_MEMBERS = 200_000
MAX_NEST = 3
MAX_DEPS = 400
MAX_HITS_KEPT = 200
RECENT_DAYS = 7
PY_TARGET = os.environ.get("PRECHECK_PY", f"{sys.version_info.major}.{sys.version_info.minor}")

P = {
    "commande": r"child_process|\bexec(File)?Sync\b|\bexecFile\s*\(|\bspawn(Sync)?\s*\(|(?<![.\w])fork\s*\(|\bsubprocess\b|os\.system|os\.popen|os\.exec[lv]|os\.spawn|os\.posix_spawn|pty\.spawn|commands\.getoutput|shell_exec|proc_open|passthru|pcntl_exec|(?<![.\w$])system\s*\(|(?<![.\w])exec\s*\(|(?<![.\w])popen\s*\(|Deno\.(run|Command)|Bun\.(spawn|\$)|\bshelljs\b|\bexeca\b|cross-spawn|\bosascript\b|NSTask|Runtime\.getRuntime|ProcessBuilder|IO\.popen|\bOpen3\b|%x\{|\bctypes\b|\bcffi\b|ffi-napi|\bdlopen\b|process\.dlopen|process\.binding|\$\((shell|file)\s|from\s+(os|subprocess|pty|ctypes|commands)\s+import\s+(?:\([^)]*?|[^\n]*)\b(system|popen|exec\w*|spawn\w*|run|call|check_output|check_call|Popen|getoutput|getstatusoutput)\b|Invoke-Expression|Start-Process|new-object\s+net\.webclient|['\"`](child_process|node:child_process|subprocess|system|popen|execSync|execFileSync|spawnSync|shell_exec|passthru|proc_open|popen2|getoutput)['\"`]",
    "dynamique": r"\beval\s*\(|new\s+Function\s*\(|(?<![.\w])Function\s*\(|\bvm\.(runIn\w+|Script|compileFunction|SourceTextModule)|(?<![.\w])compile\s*\(|\bexecfile\s*\(|runpy\.run_(path|module)|__import__\s*\(|importlib\.import_module|importlib\.util\.(spec_from_file_location|module_from_spec)|exec_module|\bimp\.load|zipimport|marshal\.loads|pickle\.loads?|\bdill\.loads|types\.(CodeType|FunctionType)|create_function|assert\s*\(\s*\$|preg_replace\s*\(\s*['\"].*/e['\"]|\bset(Timeout|Interval)\s*\(\s*['\"`]|\[\s*['\"]constructor['\"]\s*\]|\.constructor\s*\(\s*['\"`]|require\s*\(\s*[^'\"`\s)]|require\s*\(\s*`[^`]*\$\{|import\s*\(\s*[^'\"`\s)]|import\s*\(\s*`[^`]*\$\{|getattr\s*\(\s*(os|subprocess|builtins|__builtins__|sys|importlib|socket)\b|globals\(\)\s*\[|__builtins__|globalThis\s*\[|(globalThis|global|window|self)\.(require|process|eval|Function)\b|\bwindow\s*\[\s*[^\]'\"\d]|Reflect\.(apply|construct)|module\.constructor|Module\._load|require\.cache|createRequire|mainModule|WebAssembly\.(instantiate|compile|Module)|\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)|\bdocument\.write\s*\(|\.innerHTML\s*=\s*[^'\"`]",
    "obfuscation": r"\}\s*\)\s*\.constructor\b|Function\.prototype\.constructor|getPrototypeOf\(\s*(async\s*)?function|\(\s*(async\s*)?function\s*\*?\s*\w*\s*\(\s*\)\s*\{\s*\}\s*\)\s*\.constructor|\.constructor\.constructor|\(\s*\(\s*\)\s*=>\s*\{?\s*\}?\s*\)\s*\.constructor|_0x[0-9a-f]{4,}\b|\.split\(\s*['\"]['\"]\s*\)\s*\.reverse\(\)\s*\.join|\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k|['\"]\s*\]?\s*\[\s*::\s*-1\s*\]",
    "decodage": r"String\.fromCharCode|\batob\s*\(|Buffer\.from\s*\([^)]*['\"](base64|hex|base64url)['\"]|base64\.(b64decode|b32decode|b85decode|a85decode|decodebytes|urlsafe_b64decode)|codecs\.decode|bytes\.fromhex|binascii\.(unhexlify|a2b_\w+)|zlib\.(decompress|inflate)|lzma\.decompress|gzip\.decompress|gzinflate|gzuncompress|str_rot13|base64_decode|hex2bin|\bunescape\s*\(|\[(\s*0x[0-9a-fA-F]+\s*,){12,}|(\bchr\(\s*\d+\s*\)\s*\+\s*){3,}",
    "environnement": r"process\.env|os\.environ|os\.getenv|\bgetenv\s*\(|\$_ENV|\$_SERVER\s*\[|\bENV\s*\[|System\.getenv|Deno\.env|Bun\.env|\bprintenv\b",
    "env_complet": r"process\.env\s*[;,)\]}]|process\.env\s*$|\.\.\.\s*process\.env|Object\.(keys|entries|values|assign)\(\s*process\.env|JSON\.stringify\(\s*process\.env|=\s*process\.env\s*;?\s*$|dict\(\s*os\.environ\s*\)|os\.environ\.(copy|items|keys|values)\(|\*\*\s*os\.environ|json\.dumps\(\s*(dict\()?\s*os\.environ|\bgetenv\(\s*\)|\$_ENV\b(?!\s*\[)|\bprintenv\b|(^|\s)env\s*\|",
    "sensible": r"\.ssh\b|id_rsa|id_ed25519|id_ecdsa|authorized_keys|\.aws/|\.azure/|\.kube/|\.docker/config|\.gnupg|gcloud|\.config/gh|hosts\.yml|\.git-credentials|(?<![\w.$])\.env(?![\w(])|(?i:keychain)|security\s+(find|dump|export)|Login Data|Local State|Cookies|leveldb|Local Storage|\.netrc|\.npmrc|\.pypirc|\.yarnrc|\.gem/credentials|(?i:wallet\.dat|metamask|exodus|electrum)|\.bash_history|\.zsh_history|\.claude\b|\.codex\b|\.cursor/|credentials\.json|service_account|Application Support|/etc/passwd|/etc/shadow|TCC\.db|Keychains|1Password|Bitwarden|\.password-store|pbpaste|screencapture",
    "persistance": r"LaunchAgents|LaunchDaemons|launchctl|crontab|\.bashrc|\.zshrc|\.zprofile|\.zshenv|\.bash_profile|(?<![\w.])\.profile\b|sitecustomize|usercustomize|\.git/hooks|core\.hooksPath|login\s*items|systemctl|systemd|autostart|\.config/fish|settings\.json|hooks\.json|\.mcp\.json|chmod\s+\+?[0-7]*x|os\.chmod|fs\.chmod",
    "ecriture": r"appendFile|writeFile|createWriteStream|fs\.write|open\([^)]*['\"][wa]\+?b?['\"]|\.write_text|\.write_bytes|file_put_contents|fopen\([^)]*['\"][wa]|(?<![=\-])>>?\s*[~$\"']|\btee\s",
    "reseau": r"\bfetch\s*\(|XMLHttpRequest|\baxios\b|\bgot\s*\(|node-fetch|\bundici\b|superagent|\bhttps?\.(request|get)\s*\(|['\"](node:)?(https?|http2|net|tls|dgram|dns)['\"]|net\.(connect|createConnection|Socket)|tls\.connect|dgram\.|dns\.(resolve|lookup)|WebSocket|EventSource|sendBeacon|new\s+Image\s*\(|\brequests\.|\burllib|\bhttpx\b|aiohttp|http\.client|\bsocket\.|smtplib|ftplib|paramiko|pycurl|curl_exec|curl_init|fsockopen|stream_socket_client|file_get_contents\s*\(\s*['\"]https?|Net::HTTP|open-uri|\bcurl\s|\bwget\s|\bnc\s+-|/dev/tcp/|Deno\.connect|navigator\.\w+\.send|postMessage\s*\(",
    "env_secret": r"(?i:(process\.env|os\.environ|getenv|\$_ENV|\$_SERVER)\s*[\[.(]\s*['\"]?\w*(token|secret|key|pass|auth|cred|session|cookie|private))",
    "destruction": r"\b(rmSync|rmdirSync|unlinkSync|rimrafSync|rmtree|removedirs)\b|from\s+(shutil|os)\s+import\s+(?:\([^)]*?|[^\n]*)\b(rmtree|remove|unlink|rmdir)\b|(writeFileSync|writeFile|write_text|write_bytes|file_put_contents|File\.write|IO\.write)\s*\([^)\n]*,\s*(['\"`]{2}|b['\"]{2}|null|None|\[\])\s*[),]|\.write_text\(\s*['\"]{2}\s*\)|open\([^)\n]*['\"]w['\"]\)\s*\.close\(\)|rmSync\s*\([^)]*recursive|\brimraf\b|fs\.(rm|rmdir|unlink)(Sync)?\s*\(|shutil\.rmtree|os\.(remove|unlink|rmdir|removedirs)\s*\(|\.unlink\s*\(|(?<![\w>])unlink\s*\(|\brm\s+-[rRf]+|File\.delete|truncate\s*\(|\.rmtree\s*\(|send2trash",
    "arret": r"process\.(exit|abort|kill)\s*\(|(?<![\w.])sys\.exit\s*\(|os\._exit\s*\(|os\.kill\s*\(|(?<![\w.$>])(exit|die)\s*\(|signal\.SIGKILL|while\s*\(\s*(true|1)\s*\)\s*\{\s*\}",
    "telecharge_lance": r"(curl|wget|fetch|iwr|Invoke-WebRequest)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|(curl|wget)\b[^\n]*\|\s*(python|node|perl|ruby|php)|\bbase64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh|\biex\s*\(|\bIEX\b|bash\s+-c\s+['\"]?\$\(\s*(curl|wget)|sh\s+<\(\s*(curl|wget)",
}
RX = {k: re.compile(v, (re.I if k in ("persistance", "telecharge_lance") else 0) | re.M) for k, v in P.items()}
SKILL_SHELL = re.compile(r"(?<![`\w])!`[^`\n]+`")
SKILL_SUSPECT = re.compile(r"(?i)\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|system)\b|(do not|don'?t|never) (tell|mention|inform|reveal|show|report)\b[^.\n]{0,40}\b(user|utilisateur|human|humain|owner|them|him|her|about (this|these|it|that))\b|without (asking|telling|confirmation|confirming|the user)|tell the user[^.\n]{0,60}\b(succe|ok|fine|passed|valid)|\b(secretly|silently|covertly|quietly)\b|exfiltrat|(send|post|upload|forward)\b[^.\n]{0,60}\b(to|vers)\b[^.\n]{0,40}(https?://|webhook|server|serveur|email|@)|replace (every|all)[^.\n]{0,40}(with|by)|(delete|erase|wipe|remove) (all|every|the entire)|ne (dis|mentionne|signale|préviens) (rien|pas)|sans (demander|prévenir|confirmation|le dire)|\ben secret\b|discrètement|en silence|pretend|fais semblant|override (the )?(safety|security|rules)|bypass")
COMMENT_SKIP_KEYS = {"sensible", "persistance", "environnement", "reseau", "env_secret", "env_complet"}   # seuls les motifs bruyants ignorent les commentaires
DECODED_KEYS = ("commande", "dynamique", "decodage", "environnement", "env_complet", "env_secret", "sensible", "persistance", "reseau", "telecharge_lance")
C_LIKE = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx", ".php", ".java", ".go", ".c", ".h", ".cc", ".cpp", ".rs", ".swift", ".kt", ".cs", ".css", ".scss", ".vue", ".svelte"}
HASH_LIKE = {".py", ".pyw", ".pth", ".sh", ".bash", ".zsh", ".rb", ".pl", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".r", ".ps1", ".mk"}
ESC_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}|\\u00[0-9a-fA-F]{2}|\\u\{[0-9a-fA-F]{2,4}\}|\\[0-7]{3}){5,}")
PY_CODING = re.compile(r"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
OK_CODINGS = {"utf-8", "utf8", "latin-1", "latin1", "iso-8859-1", "iso-8859-15", "ascii", "us-ascii", "cp1252", "utf-8-sig"}
DANGER_NAME = re.compile(r"^\s*(system|exec|execSync|popen|spawn|eval|child_process|node:child_process|subprocess|os|shell_exec|passthru|proc_open|require|import|Function|socket|curl|wget|bash|sh|process|mainModule|constructor)\s*$")
IP_LIT = re.compile(r"['\"](\d{1,3}(?:\.\d{1,3}){3})['\"]")
EXEC_DECODED = re.compile(r"(?<![.\w])(eval|Function|exec|compile|require|import|__import__|vm\.\w+|system|assert|create_function|setTimeout)\s*\(\s*[^;\n),]{0,80}?(atob|fromCharCode|Buffer\.from|b64decode|base64_decode|unhexlify|fromhex|decompress|gzinflate|gzuncompress|str_rot13|codecs\.decode)")
FCC = re.compile(r"fromCharCode\(\s*((?:\d{2,3}\s*,\s*){3,}\d{2,3})\s*\)")
CHRS = re.compile(r"(?:\bchr\(\s*\d+\s*\)\s*\+\s*){2,}\bchr\(\s*\d+\s*\)")
HOST_RE = re.compile(r"(?:https?|wss?|ftp|ftps|sftp)://(?:[^/\s'\"@]+@)?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\])", re.I)
BENIGN_HOSTS = re.compile(r"(^|\.)(github\.com|npmjs\.(com|org)|pypi\.org|python\.org|w3\.org|mozilla\.org|apache\.org|opensource\.org|readthedocs\.(io|org)|example\.(com|org|net)|schema\.org|json-schema\.org|packagist\.org|php\.net|nodejs\.org|wikipedia\.org|semver\.org|spdx\.org|creativecommons\.org|gnu\.org|unicode\.org|ietf\.org|ecma-international\.org|whatwg\.org)$", re.I)
EXFIL_HOSTS = re.compile(r"discord(app)?\.com|api\.telegram\.org|pastebin|hastebin|ngrok|webhook\.site|requestbin|pipedream|burpcollaborator|oast\.|interact\.sh|canarytokens|transfer\.sh|file\.io|0x0\.st|ipinfo\.io|ifconfig\.me|api\.ipify|githubusercontent\.com|bit\.ly|tinyurl|glitch\.me|workers\.dev|trycloudflare|serveo|localtunnel|duckdns|no-ip|\.onion\b|^\d{1,3}(\.\d{1,3}){3}$", re.I)
B64_BLOCK = re.compile(r"[A-Za-z0-9+/_-]{200,}={0,2}")
STR_LIT = re.compile(r"(['\"`])((?:(?!\1)[^\\\n]|\\.){3,}?)\1")
JOIN_RX = re.compile(r"(['\"`])([^'\"`\n\\]*)\1[ \t]*(?:\+|\.|,|\|\|)?\s*(?:\+|\.|,)?[ \t]*(['\"`])([^'\"`\n\\]*)\3")
ESC_RX = re.compile(r"\\x([0-9a-fA-F]{2})|\\u\{?([0-9a-fA-F]{4})\}?|\\([0-7]{3})")
CODE_EXT = C_LIKE | HASH_LIKE | {".json", ".html", ".htm", ".bat", ".cmd", ".vbs", ".lua", ".ex", ".exs", ".erl", ".hs", ".jl", ".dart", ".scala"}
CLAUDE_FILES = {"hooks.json", ".mcp.json", "mcp.json", "plugin.json", "marketplace.json", "settings.json", "settings.local.json", "manifest.json", "claude_desktop_config.json", "mod.json"}
CLAUDE_KEYS = {"hooks", "mcpServers", "statusLine", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "lspServers", "subagentStatusLine", "fileSuggestion", "mcp_servers"}
CLAUDE_FILE_KEYS = {"permissions", "env", "commands", "agents", "outputStyles", "enabledMcpjsonServers", "command", "args", "main", "module", "modules", "entry", "server"}
DEVCONTAINER_KEYS = {"initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"}
DOC_NAME = re.compile(r"^(readme|changelog|changes|history|license|licence|copying|notice|authors|contributors|contributing|code_of_conduct|security|news)([.\-_].*)?$", re.I)
NATIVE_EXT = {".node", ".so", ".dylib", ".dll", ".exe", ".wasm", ".pyd", ".bin", ".o", ".a", ".class", ".pyc", ".pyo", ".dex", ".msi", ".pkg", ".dmg"}
OFFICE_EXT = {".xlsx", ".docx", ".pptx", ".odt", ".ods", ".odp", ".epub", ".key", ".numbers", ".pages", ".sketch", ".fig", ".kmz", ".3mf", ".xlsm", ".docm", ".pptm"}
STD_BACKENDS = {"setuptools.build_meta", "setuptools.build_meta:__legacy__", "hatchling.build", "flit_core.buildapi", "poetry.core.masonry.api", "pdm.backend", "pdm.pep517.api", "maturin", "scikit_build_core.build", "mesonpy", "uv_build", "whey", "sipbuild.api"}
NPM_AUTO = ("preinstall", "install", "postinstall")
NPM_LOCAL = ("preprepare", "prepare", "postprepare", "prepublish", "prepack", "postpack", "dependencies")
SHADOW_BINS = {"node", "npm", "npx", "git", "ls", "sh", "bash", "zsh", "python", "python3", "pip", "pip3", "claude", "codex", "sudo", "ssh", "curl", "open", "cd", "cat", "uv", "composer", "php", "brew"}
TEST_RX = re.compile(r"(^|/)(tests?|__tests__|spec|specs|examples?|docs?|fixtures?|benchmarks?)/", re.I)
MEDIA_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf",
             ".mp3", ".mp4", ".m4a", ".mov", ".avi", ".wav", ".ogg", ".flac", ".webm", ".mkv", ".sqlite", ".db", ".heic", ".avif"}
MEDIA_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"wOFF", b"wOF2", b"OTTO", b"\x00\x01\x00\x00", b"%PDF", b"\x00\x00\x01\x00", b"ID3", b"OggS", b"fLaC", b"SQLite format 3", b"\x1aE\xdf\xa3", b"BM")

LEVEL = {k: "fort" for k in ("integrite", "install", "claude", "autorun", "telecharge_lance", "exfil", "obfuscation", "env_reseau", "natif",
                             "deps_scripts", "deps_alertes", "deps_hors_registre", "deps_non_resolu", "deps_non_lus", "vulns", "deps_vulns",
                             "editeur", "recent", "non_lu", "lien", "archive_illisible", "encodage_source", "retire", "persistance_ecriture",
                             "extraction", "telechargement", "commande_detournee", "osv", "deps_partiel", "consigne_suspecte", "unicode_trompeur")}
LEVEL.update({k: "lire" for k in ("dynamique", "decodage", "commande", "sensible", "persistance", "reseau", "hote", "environnement", "encode",
                                  "compacte", "peu_utilise", "sans_depot", "install_local", "env_reseau_paquet", "doc_telecharge",
                                  "binaire_inconnu", "integrite_inconnue", "date_inconnue", "archives", "note", "destruction", "autoload", "skill_a_lire", "arret", "deps_a_lire", "unicode_invisible")})


# ---------- réseau et archives ----------

def _check_host(url):
    u = urllib.parse.urlparse(url)
    if u.scheme != "https":
        raise ValueError(f"adresse non chiffrée refusée : {url}")
    for fam, *_, sa in socket.getaddrinfo(u.hostname, 443):
        ip = ipaddress.ip_address(sa[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError(f"hôte {u.hostname} pointe vers une adresse interne {ip}")


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_host(newurl)   # refusée AVANT d'être suivie
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(_SafeRedirect)


def http_json(url, data=None):
    _check_host(url)
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data else None,
                                 headers={"Content-Type": "application/json", "User-Agent": "precheck/3.0"})
    with OPENER.open(req, timeout=60) as r:
        if not r.geturl().startswith("https://"):
            raise ValueError(f"redirection non chiffrée : {r.geturl()}")
        return json.loads(r.read(200_000_000))


def download(url, dest):
    _check_host(url)
    req = urllib.request.Request(url, headers={"User-Agent": "precheck/3.0"})
    t0 = datetime.datetime.now().timestamp()
    with OPENER.open(req, timeout=60) as r, open(dest, "wb") as f:
        n = 0
        while chunk := r.read(1 << 20):
            n += len(chunk)
            if datetime.datetime.now().timestamp() - t0 > 900:
                raise ValueError("téléchargement de plus de 15 minutes : abandonné")
            if n > MAX_DOWNLOAD:
                raise ValueError(f"téléchargement au-delà de {MAX_DOWNLOAD // 1_000_000} Mo")
            f.write(chunk)
    return dest


def verify_sri(data, integ):
    """Empreinte npm « algo-base64 ». Retourne True/False, ou None si absente ou inconnue."""
    for part in (integ or "").split():
        algo, _, b64 = part.partition("-")
        if algo in ("sha512", "sha384", "sha256", "sha1"):
            return base64.b64encode(hashlib.new(algo, data).digest()).decode() == b64
    return None


EXTRACT_BUDGET = [20_000_000_000]   # pour toute la séance, archives imbriquées et dépendances comprises


def safe_extract(archive, dest):
    """Extrait sans lien, sans fichier spécial, sans sortie du dossier, avec quotas.
    Retourne (entrées refusées, erreur ou None). Une erreur n'arrête pas le contrôle : elle est signalée."""
    dest = pathlib.Path(dest).resolve(); dest.mkdir(parents=True, exist_ok=True); refused = []; total = 0
    try:
        if tarfile.is_tarfile(archive):
            with tarfile.open(archive) as t:
                for k, m in enumerate(t):
                    if k >= MAX_MEMBERS:
                        return refused, f"plus de {MAX_MEMBERS} entrées : extraction arrêtée"
                    target = (dest / m.name).resolve()
                    if not (m.isfile() or m.isdir()) or not target.is_relative_to(dest):
                        refused.append(f"{m.name} ({'lien' if m.issym() or m.islnk() else 'hors dossier' if not target.is_relative_to(dest) else 'spécial'})")
                        continue
                    if m.size > MAX_MEMBER or total + m.size > MAX_EXTRACT_TOTAL or m.size > EXTRACT_BUDGET[0]:
                        refused.append(f"{m.name} ({m.size} octets, au-delà du quota)"); continue
                    total += m.size; EXTRACT_BUDGET[0] -= m.size
                    t.extract(m, dest, filter="data")
        elif zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as z:
                infos = z.infolist()
                if len(infos) > MAX_MEMBERS:
                    return refused, f"plus de {MAX_MEMBERS} entrées"
                for zi in infos:
                    target = (dest / zi.filename).resolve()
                    is_link = (zi.external_attr >> 16) & 0o170000 == 0o120000
                    if is_link or not target.is_relative_to(dest):
                        refused.append(f"{zi.filename} ({'lien' if is_link else 'hors dossier'})"); continue
                    if zi.flag_bits & 0x1:
                        refused.append(f"{zi.filename} (chiffré, illisible)"); continue
                    if zi.file_size > MAX_MEMBER or total + zi.file_size > MAX_EXTRACT_TOTAL or (zi.compress_size and zi.file_size / zi.compress_size > 500 and zi.file_size > 50_000_000):
                        refused.append(f"{zi.filename} ({zi.file_size} octets, quota ou bombe de décompression)"); continue
                    if zi.file_size > EXTRACT_BUDGET[0]:
                        refused.append(f"{zi.filename} (budget total d'extraction épuisé)"); continue
                    total += zi.file_size; EXTRACT_BUDGET[0] -= zi.file_size
                    z.extract(zi, dest)
        else:
            head = pathlib.Path(archive).read_bytes()[:6]
            opener = gzip.open if head[:2] == b"\x1f\x8b" else bz2.open if head[:3] == b"BZh" else lzma.open if head[:5] == b"\xfd7zXZ" else None
            if opener is None:
                return refused, "format d'archive non pris en charge (7z, rar, zst…) : contenu non lu"
            out = dest / (pathlib.Path(archive).stem or "contenu")
            with opener(archive) as src, open(out, "wb") as f:
                n = 0
                while chunk := src.read(1 << 20):
                    n += len(chunk)
                    if n > MAX_MEMBER:
                        return refused, "contenu décompressé au-delà du quota"
                    f.write(chunk)
    except Exception as e:
        return refused, f"archive illisible ou corrompue : {type(e).__name__} {e}"
    return refused, None


def age_days(ts):
    if not ts:
        return None
    try:
        d = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=datetime.timezone.utc)
        return (datetime.datetime.now(datetime.timezone.utc) - d).total_seconds() / 86400
    except ValueError:
        return None


def expand_packagist(resp, name):
    """Développe le format « minified composer/2.0 » : chaque version hérite de la précédente."""
    versions = resp["packages"][name]
    if resp.get("minified") != "composer/2.0":
        return versions
    out, prev = [], {}
    for v in versions:
        cur = dict(prev)
        for k, val in v.items():
            if val == "__unset":
                cur.pop(k, None)
            else:
                cur[k] = val
        out.append(cur); prev = cur
    return out


def wheel_ok(fn):
    """Wheels que pip peut choisir sur ce Mac (Apple Silicon, Python PY_TARGET)."""
    parts = fn[:-4].split("-")
    if len(parts) < 5:
        return False
    py, abi, plat = parts[-3], parts[-2], parts[-1]
    cur = "cp" + PY_TARGET.replace(".", "")
    plat_ok = plat == "any" or any(p.startswith("macosx") and (p.endswith("arm64") or p.endswith("universal2")) for p in plat.split("."))
    pys = py.split(".")
    py_ok = any(p in ("py3", "py2.py3", cur) or (p.startswith("py3") and len(p) > 3) for p in pys) or (abi == "abi3" and any(p.startswith("cp3") and int(p[3:] or 0) <= int(cur[3:]) for p in pys))
    return plat_ok and py_ok


def pypi_artifacts(name, version, q):
    """Télécharge toutes les wheels utilisables sur ce Mac (ou la source à défaut). Retourne (info, [(fichier, sha256, dossier)])."""
    meta = http_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
    files = meta.get("urls", [])
    whl = [f for f in files if f["filename"].endswith(".whl")]
    picks = [f for f in whl if wheel_ok(f["filename"])]
    info = {"repo": meta["info"].get("project_urls") or meta["info"].get("home_page"), "deps": meta["info"].get("requires_dist") or [],
            "yanked": meta["info"].get("yanked") and (meta["info"].get("yanked_reason") or "yanked"), "scripts": {}, "notes": [], "refused": [], "errors": []}
    if not picks:
        sd = [f for f in files if f["packagetype"] == "sdist"]
        if whl:
            info["notes"].append(f"aucune des {len(whl)} wheels ne convient à ce Mac (Python {PY_TARGET}, arm64) : pip construirait depuis les sources")
        info["scripts"]["(sources)"] = "pas de wheel utilisable : l'installation exécuterait le code de construction du paquet"
        picks = sd[:1]
    arts = []
    for f in picks:
        p = download(f["url"], q / f["filename"])
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        if sha != f["digests"]["sha256"]:
            info["integrity_ok"] = False
        info.setdefault("integrity_ok", True)
        d = q / ("src_" + re.sub(r"[^\w.-]", "_", f["filename"]))
        refused, err = safe_extract(p, d)
        info["refused"] += refused
        if err:
            info["errors"].append(f"{f['filename']} : {err}")
        arts.append((f["filename"], sha, d))
        info["published"] = f.get("upload_time_iso_8601") or f.get("upload_time")
    if len(picks) < len(whl):
        info["notes"].append(f"{len(picks)} wheel(s) lue(s) sur {len(whl)} publiées : les autres ne s'installent pas sur ce Mac")
    return info, arts


def fetch(eco, name, version, q):
    """Télécharge sans exécuter. Retourne (version, info, [(fichier, empreinte, dossier)])."""
    info = {"scripts": {}, "deps": [], "notes": [], "refused": [], "errors": []}
    if eco == "npm":
        meta = http_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
        if version not in meta.get("versions", {}):
            sys.exit(f"version {version} introuvable sur npm (récentes : {', '.join(list(meta.get('versions', {}))[-5:])})")
        v = meta["versions"][version]
        repo = v.get("repository")
        sc = v.get("scripts") if isinstance(v.get("scripts"), dict) else {}
        info.update(published=meta.get("time", {}).get(version), repo=repo.get("url") if isinstance(repo, dict) else repo,
                    scripts={k: s for k, s in sc.items() if k in NPM_AUTO},
                    deps=sorted({**(v.get("dependencies") or {}), **(v.get("optionalDependencies") or {}), **(v.get("peerDependencies") or {})}.keys()),
                    maintainers=[m.get("name") for m in v.get("maintainers", []) if isinstance(m, dict)], size=(v.get("dist") or {}).get("unpackedSize"),
                    publisher=(v.get("_npmUser") or {}).get("name"), deprecated=v.get("deprecated"),
                    provenance=bool((v.get("dist") or {}).get("attestations")))
        if v.get("gypfile"):
            info["scripts"]["(gypfile)"] = "compilation node-gyp implicite à l'installation"
        times = {k: t for k, t in meta.get("time", {}).items() if k in meta["versions"]}
        older = sorted((t, k) for k, t in times.items() if t < times.get(version, ""))
        if older:
            prev = meta["versions"][older[-1][1]]
            info.update(prev_version=older[-1][1], prev_publisher=(prev.get("_npmUser") or {}).get("name"),
                        prev_provenance=bool((prev.get("dist") or {}).get("attestations")))
        tgz = download(v["dist"]["tarball"], q / "pkg.tgz")
        data = tgz.read_bytes()
        ok = verify_sri(data, (v.get("dist") or {}).get("integrity"))
        if ok is None and (v.get("dist") or {}).get("shasum"):
            ok = hashlib.sha1(data).hexdigest() == v["dist"]["shasum"]
        info["integrity_ok"] = ok
        refused, err = safe_extract(tgz, q / "src"); info["refused"] = refused
        if err:
            info["errors"].append(err)
        try:
            info["downloads_week"] = http_json(f"https://api.npmjs.org/downloads/point/last-week/{urllib.parse.quote(name, safe='@')}").get("downloads")
        except Exception as e:
            info["notes"].append(f"téléchargements npm non lus : {e}")
        arts = [("pkg.tgz", "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode(), q / "src")]
    elif eco == "pypi":
        pinfo, arts = pypi_artifacts(name, version, q)
        info.update(pinfo)
        info["notes"].append("PyPI ne publie pas l'éditeur de chaque version : changement d'éditeur non vérifiable")
        try:
            info["downloads_week"] = (http_json(f"https://pypistats.org/api/packages/{name.lower()}/recent").get("data") or {}).get("last_week")
        except Exception as e:
            info["notes"].append(f"téléchargements PyPI non lus : {e}")
    elif eco == "composer":
        resp = http_json(f"https://repo.packagist.org/p2/{name}.json")
        meta = expand_packagist(resp, name)
        v = next((x for x in meta if str(x.get("version", "")).lstrip("v") == version.lstrip("v")), None)
        if v is None:
            sys.exit(f"version {version} introuvable sur packagist")
        version = v["version"]
        info.update(published=v.get("time"), repo=(v.get("source") or {}).get("url"), type=v.get("type"),
                    deps=sorted(k for k in (v.get("require") or {}) if "/" in k))
        info["notes"].append("Packagist ne publie pas l'éditeur de chaque version : changement d'éditeur non vérifiable")
        if v.get("type") == "composer-plugin":
            info["scripts"]["(composer-plugin)"] = "un plugin Composer s'exécute à chaque commande composer"
        if v.get("scripts"):
            info["notes"].append(f"scripts composer déclarés (lancés seulement si le paquet est le projet racine) : {json.dumps(v['scripts'])[:200]}")
        z = download(v["dist"]["url"], q / "pkg.zip")
        shasum = (v.get("dist") or {}).get("shasum")
        info["integrity_ok"] = (hashlib.sha1(z.read_bytes()).hexdigest() == shasum) if shasum else None
        refused, err = safe_extract(z, q / "src"); info["refused"] = refused
        if err:
            info["errors"].append(err)
        arts = [("pkg.zip", hashlib.sha256(z.read_bytes()).hexdigest(), q / "src")]
    else:
        sys.exit(f"écosystème inconnu : {eco}")
    return version, info, arts


def osv_batch(eco, pkgs):
    eco_map = {"npm": "npm", "pypi": "PyPI", "composer": "Packagist"}
    out = {}
    for i in range(0, len(pkgs), 500):
        chunk = pkgs[i:i + 500]
        r = http_json("https://api.osv.dev/v1/querybatch", {"queries": [{"package": {"name": n, "ecosystem": eco_map[eco]}, "version": str(v).lstrip("v")} for n, v in chunk]})
        res = r.get("results", [])
        if len(res) != len(chunk):
            raise ValueError(f"OSV.dev a répondu {len(res)} résultats pour {len(chunk)} paquets")
        for (n, v), x in zip(chunk, res):
            ids = [y["id"] for y in x.get("vulns", [])]
            if ids:
                out[(n, v)] = ids
    return out


def osv_detail(eco, name, version):
    eco_map = {"npm": "npm", "pypi": "PyPI", "composer": "Packagist"}
    r = http_json("https://api.osv.dev/v1/query", {"package": {"name": name, "ecosystem": eco_map[eco]}, "version": version.lstrip("v")})
    return [(v["id"], (v.get("summary") or v.get("details") or "").replace("\n", " ")[:160]) for v in r.get("vulns", [])]


# ---------- résolution de l'arbre, enfermée ----------

def _sandboxed(cmd, work, timeout=900, stdin=None):
    """Lance un résolveur avec un domicile vide, sans git ni ssh, et (si possible) sous sandbox-exec :
    lecture et écriture interdites dans le vrai domicile, sauf le dossier de travail."""
    home = work / "home"; (home / ".config").mkdir(parents=True, exist_ok=True)
    (home / ".npmrc").write_text(""); (work / "global.npmrc").write_text("")
    env = {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(work / "tmp"), "LANG": "C.UTF-8",
           "npm_config_userconfig": str(home / ".npmrc"), "npm_config_globalconfig": str(work / "global.npmrc"), "npm_config_cache": str(work / "cache"),
           "npm_config_registry": "https://registry.npmjs.org/", "npm_config_ignore_scripts": "true", "npm_config_update_notifier": "false",
           "UV_CACHE_DIR": str(work / "cache"), "UV_NO_CONFIG": "1",
           # version de macOS de ce poste : sans elle, uv vise un vieux macOS et refuse les roues récentes (mlx)
           "MACOSX_DEPLOYMENT_TARGET": (__import__("platform").mac_ver()[0].split(".")[0] or "14") + ".0", "NETRC": "/dev/null", "UV_KEYRING_PROVIDER": "disabled",
           "COMPOSER_HOME": str(work / "composer"), "COMPOSER_CACHE_DIR": str(work / "cache"), "COMPOSER_NO_INTERACTION": "1", "COMPOSER_ALLOW_SUPERUSER": "0",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/usr/bin/false",
           "SSH_ASKPASS": "/usr/bin/false", "GIT_SSH_COMMAND": "/usr/bin/false", "GIT_ALLOW_PROTOCOL": "aucun"}
    (work / "tmp").mkdir(exist_ok=True)
    real_home = os.path.realpath(pathlib.Path.home()); w = os.path.realpath(work)
    note = None
    if not os.path.exists("/usr/bin/sandbox-exec"):
        raise RuntimeError("sandbox-exec absent : résolution refusée plutôt que lancée sans enfermement")
    # Chemins passés en paramètres, jamais recopiés dans le texte du profil.
    prof = ('(version 1)(allow default)'
            '(deny file-read* (subpath (param "HOME")) (subpath "/Volumes") (subpath "/private/var/root"))'
            '(allow file-read* (subpath (param "WORK")))(allow file-read-metadata (literal (param "HOME")))'
            '(deny file-write* (subpath (param "HOME")) (subpath "/Volumes"))(allow file-write* (subpath (param "WORK")))')
    cmd = ["/usr/bin/sandbox-exec", "-D", f"HOME={real_home}", "-D", f"WORK={w}", "-p", prof] + cmd
    r = subprocess.run(cmd, cwd=work, capture_output=True, text=True, timeout=timeout, env=env, input=stdin)
    return r, note


def resolve_tree(eco, work, name=None, version=None, manifest=None):
    """Arbre complet SANS rien installer ni exécuter.
    Retourne dict(pkgs=[(nom, version, url, empreinte)], scripts=[...], hors_registre=[...], notes=[...], ok=bool)."""
    work.mkdir(parents=True, exist_ok=True)
    R = {"pkgs": [], "scripts": [], "hors_registre": [], "notes": [], "ok": False}
    try:
        if eco == "npm":
            if not shutil.which("npm"):
                R["notes"].append("npm absent : arbre non résolu"); return R
            pj = {"name": "precheck-root", "version": "0.0.0", "private": True}
            if manifest:
                for k in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides"):
                    if isinstance(manifest.get(k), dict):
                        pj[k] = manifest[k]
            else:
                pj["dependencies"] = {name: version}
            (work / "package.json").write_text(json.dumps(pj))
            base = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--registry=https://registry.npmjs.org/"]
            r, note = _sandboxed(base, work)
            if note: R["notes"].append(note)
            if not (work / "package-lock.json").exists() and "ERESOLVE" in (r.stderr + r.stdout):
                r, _ = _sandboxed(base + ["--legacy-peer-deps"], work)
                R["notes"].append("conflit de dépendances paires : arbre résolu avec --legacy-peer-deps, les paires ne sont pas dans l'arbre"); R["partiel"] = True
            lock = work / "package-lock.json"
            if not lock.exists():
                R["notes"].append(f"npm n'a pas résolu l'arbre : {(r.stderr or r.stdout).strip()[-400:]}"); return R
            for path, d in json.loads(lock.read_text()).get("packages", {}).items():
                if not path:
                    continue
                n = d.get("name") or path.split("node_modules/")[-1]
                url = d.get("resolved") or ""
                if d.get("link") or (url and not url.startswith("https://registry.npmjs.org/")):
                    R["hors_registre"].append(f"{n} : {url or 'lien local ' + str(d.get('resolved'))}"); continue
                if d.get("version"):
                    R["pkgs"].append((n, d["version"], url, d.get("integrity")))
                if d.get("hasInstallScript"):
                    R["scripts"].append(f"{n}@{d.get('version')}")
            R["ok"] = True
        elif eco == "pypi":
            if not shutil.which("uv"):
                R["notes"].append("uv absent : arbre non résolu"); return R
            if manifest:
                src = manifest
            else:
                (work / "req.in").write_text(f"{name}=={version}\n"); src = work / "req.in"
            dst = work / "req_src" / pathlib.Path(src).name
            dst.parent.mkdir(exist_ok=True); shutil.copy(src, dst)
            r, note = _sandboxed(["uv", "pip", "compile", str(dst), "--no-build", "--no-config", "--no-header", "--no-annotate", "--quiet",
                                  "--python-version", PY_TARGET, "--python-platform", "aarch64-apple-darwin", "--index-url", "https://pypi.org/simple",
                                  "--keyring-provider", "disabled", "--no-sources"], work)
            if note: R["notes"].append(note)
            if r.returncode != 0:
                R["notes"].append(f"uv n'a pas résolu l'arbre sans construire de sources : {r.stderr.strip()[-400:]}"); return R
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-\[\],]+)==([^\s;]+)", line)
                if m:
                    R["pkgs"].append((re.sub(r"\[.*\]", "", m.group(1)), m.group(2), None, None))
                else:
                    R["hors_registre"].append(line)
            R["notes"].append(f"arbre résolu pour Python {PY_TARGET} sur macOS arm64 (PRECHECK_PY pour une autre cible)")
            R["ok"] = True
        elif eco == "composer":
            if not shutil.which("composer"):
                R["notes"].append("composer absent : arbre non résolu"); return R
            cj = {"require": {name: version}} if not manifest else {k: manifest[k] for k in ("require", "require-dev") if isinstance(manifest.get(k), dict)}
            if manifest and manifest.get("repositories"):
                R["hors_registre"].append(f"dépôts hors Packagist déclarés (ignorés pour la résolution) : {json.dumps(manifest['repositories'])[:200]}")
            cj["config"] = {"allow-plugins": False, "secure-http": True}
            (work / "composer.json").write_text(json.dumps(cj))
            base = ["composer", "update", "--no-install", "--no-scripts", "--no-plugins", "--no-interaction", "--no-audit"]
            r, note = _sandboxed(base, work)
            if note: R["notes"].append(note)
            if not (work / "composer.lock").exists():
                r, _ = _sandboxed(base + ["--ignore-platform-reqs"], work)
                R["notes"].append("résolu en ignorant les extensions PHP de ce poste : l'arbre du serveur peut différer"); R["partiel"] = True
            lock = work / "composer.lock"
            if not lock.exists():
                R["notes"].append(f"composer n'a pas résolu l'arbre : {(r.stderr or r.stdout).strip()[-400:]}"); return R
            L = json.loads(lock.read_text())
            for d in L.get("packages", []) + L.get("packages-dev", []):
                dist = d.get("dist") or {}
                url = dist.get("url") or ""
                if not url.startswith("https://") or dist.get("type") not in ("zip", "tar", None):
                    R["hors_registre"].append(f"{d['name']} : {url or d.get('source')}"); continue
                R["pkgs"].append((d["name"], d["version"], url, dist.get("shasum")))
                if d.get("type") == "composer-plugin":
                    R["scripts"].append(f"{d['name']}@{d['version']} (plugin composer)")
            R["ok"] = True
    except Exception as e:
        R["notes"].append(f"arbre non résolu : {type(e).__name__} {e}")
    return R


def scan_dependencies(eco, tree, work, exclude=None):
    """Télécharge et analyse chaque dépendance de l'arbre. Retourne ({paquet: [(clé, message)] fortes}, [erreurs])."""
    pkgs = [p for p in tree["pkgs"] if not exclude or (p[0].lower(), str(p[1])) != (exclude[0].lower(), str(exclude[1]))]
    errors = []
    if len(pkgs) > MAX_DEPS:
        errors.append(f"{len(pkgs)} dépendances : seules les {MAX_DEPS} premières sont lues")
        pkgs = pkgs[:MAX_DEPS]

    def one(p):
        n, v, url, integ = p
        d = pathlib.Path(tempfile.mkdtemp(prefix=re.sub(r"[^\w.-]", "_", n)[:40] + "-", dir=work))
        info = {"scripts": {}, "refused": [], "errors": []}
        roots = []
        if eco == "npm":
            f = download(url, d / "pkg.tgz")
            ok = verify_sri(f.read_bytes(), integ)
            info["integrity_ok"] = ok
            refused, err = safe_extract(f, d / "src"); info["refused"] = refused
            if err: info["errors"].append(err)
            roots = [d / "src"]
        elif eco == "pypi":
            pinfo, arts = pypi_artifacts(n, v, d)
            info.update(pinfo); roots = [a[2] for a in arts]
        elif eco == "composer":
            f = download(url, d / "pkg.zip")
            info["integrity_ok"] = (hashlib.sha1(f.read_bytes()).hexdigest() == integ) if integ else None
            refused, err = safe_extract(f, d / "src"); info["refused"] = refused
            if err: info["errors"].append(err)
            roots = [d / "src"]
        a = analyse_many(roots, mode="registre")
        F = build_flags(a, info, None, mode="registre")
        strong = [(k, m) for k, lv, m in F if lv == "fort"]
        soft = sorted({k for k, lv, m in F if lv == "lire" and k in ("destruction", "commande", "arret", "dynamique", "autoload", "persistance", "sensible", "env_reseau_paquet", "decodage")})
        shutil.rmtree(d, ignore_errors=True)
        return f"{eco}:{n}@{v}", (strong, soft)

    out = {}; soft_out = {}
    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        futs = {ex.submit(one, p): p for p in pkgs}
        for fu in concurrent.futures.as_completed(futs):
            p = futs[fu]
            try:
                label, (strong, soft) = fu.result()
                if strong:
                    out[label] = strong
                if soft:
                    soft_out[label] = soft
            except Exception as e:
                errors.append(f"{eco}:{p[0]}@{p[1]} non lu : {type(e).__name__} {e}")
    return out, errors, soft_out


# ---------- analyse statique ----------

def unescape(s):
    def rep(m):
        c = int(m.group(1) or m.group(2), 16) if (m.group(1) or m.group(2)) else int(m.group(3), 8)
        return chr(c) if 0x20 <= c < 0x7f else m.group(0)
    return ESC_RX.sub(rep, s)


def normalize(txt):
    """Recolle 'chi'+'ld_pro'+'cess' (y compris sur plusieurs lignes), décode \\x63, change ['x'] en .x."""
    s = unicodedata.normalize("NFKC", unescape(txt))
    for _ in range(8):
        s2 = JOIN_RX.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), s)
        if s2 == s:
            break
        s = s2
    return re.sub(r"\[\s*['\"`](\w+)['\"`]\s*\]", r".\1", s)


def decoded_strings(txt):
    """Chaînes cachées : base64, hex, inversées, fromCharCode, chr()+chr()."""
    out = []
    for m in STR_LIT.finditer(txt):
        lit = m.group(2)
        if len(lit) > 100_000:
            continue
        after = txt[m.end():m.end() + 40]
        if re.match(r"\s*\[\s*::\s*-1\s*\]|\s*\.split\(\s*['\"]['\"]\s*\)\s*\.reverse", after) or DANGER_NAME.match(lit[::-1]):
            out.append((m.start(), lit[::-1], "inversée"))
        cand = []
        if len(lit) >= 8 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", lit):
            for f in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    cand.append(f(lit + "=" * (-len(lit) % 4)))
                except (binascii.Error, ValueError):
                    pass
        if len(lit) >= 8 and re.fullmatch(r"(?:[0-9a-fA-F]{2})+", lit):
            cand.append(bytes.fromhex(lit))
        for b in cand:
            try:
                t = b.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if t and sum(c.isprintable() or c in "\n\t" for c in t) / len(t) > 0.9 and re.search(r"[A-Za-z]{3}", t):
                out.append((m.start(), t, "encodée"))
    for m in FCC.finditer(txt):
        try:
            out.append((m.start(), "".join(chr(int(x)) for x in re.findall(r"\d+", m.group(1))), "fromCharCode"))
        except ValueError:
            pass
    for m in CHRS.finditer(txt):
        try:
            out.append((m.start(), "".join(chr(int(x)) for x in re.findall(r"\d+", m.group(0))), "chr()"))
        except ValueError:
            pass
    return out


C_TOK = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`|(?P<c>(?m:^)[ \t]*(?://[^\n]*|/\*(?:[^*]|\*(?!/))*\*/))", re.S)
H_TOK = re.compile(r'"""(?:[^"\\]|\\.|"(?!""))*"""|\'\'\'(?:[^\'\\]|\\.|\'(?!\'\'))*\'\'\'|"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|(?P<c>(?m:^)[ \t]*#(?!!)[^\n]*)', re.S)


def comment_spans(txt, suffix):
    """Commentaires sûrs seulement : ligne entière commençant par // ou #, ou bloc /* */ ouvert en début de ligne,
    chaînes consommées d'abord. Au moindre doute (beaucoup de délimiteurs), aucun commentaire : plus de bruit, pas de trou."""
    tok = C_TOK if suffix in C_LIKE else H_TOK if suffix in HASH_LIKE else None
    if tok is None:
        return []
    if txt.count("/*") > 2000 or txt.count("`") > 4000 or txt.count('"""') + txt.count("\'\'\'") > 2000:
        return []
    return [m.span("c") for m in tok.finditer(txt) if m.group("c")]


def in_spans(pos, spans, starts):
    i = bisect.bisect_right(starts, pos) - 1
    return i >= 0 and spans[i][0] <= pos < spans[i][1]


def as_text(raw):
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace"), "utf-16"
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", "replace"), "utf-8"
    odd = raw[1:400:2]
    if len(odd) > 8 and odd.count(0) > 0.8 * len(odd):
        return raw.decode("utf-16-le", "replace"), "utf-16"
    return raw.decode("utf-8", "replace").replace("\x00", ""), "utf-8"


def as_text_norm(raw):
    txt, enc = as_text(raw)
    return txt.replace("\r\n", "\n").replace("\r", "\n"), enc


def classify_binary(p, head):
    s = p.suffix.lower()
    if s in NATIVE_EXT or head[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf", b"\x00asm", b"dex\n") or head[:2] == b"MZ" or head[:4] == b"\x03\xf3\r\n" or head[2:4] == b"\r\n" and s in (".pyc",):
        return "natif"
    if s in OFFICE_EXT:
        return "donnee"
    if head[:4] == b"PK\x03\x04" or head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:5] == b"\xfd7zXZ" or head[:6] == b"7z\xbc\xaf\x27\x1c" or head[:4] == b"Rar!" or head[:4] == b"\x28\xb5\x2f\xfd" or (len(head) > 262 and head[257:262] == b"ustar"):
        return "archive"
    if any(head.startswith(m) for m in MEDIA_MAGIC) or (head[:4] == b"RIFF" and head[8:12] in (b"WEBP", b"WAVE", b"AVI ")) or head[4:8] == b"ftyp":
        return "media"
    return "inconnu"


def install_points(rel, p, txt, mode):
    """Points où du code tourne sans qu'on le lance."""
    pts = []
    name = p.name.lower(); parts = [x.lower() for x in pathlib.PurePosixPath(rel).parts]

    def add(kind, what):
        pts.append((kind, rel, what))

    def load_json():
        try:
            return json.loads(txt)
        except ValueError:
            return None

    if name.startswith(".env") or name in ("env", ".flaskenv"):
        for m in re.finditer(r"(?m)^\s*(?:export\s+)?(NODE_OPTIONS|PYTHONSTARTUP|PYTHONPATH|PYTHONHOME|LD_PRELOAD|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|BASH_ENV|ENV|PERL5OPT|RUBYOPT|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|NODE_PATH|GIT_SSH_COMMAND|PROMPT_COMMAND|ZDOTDIR)\s*=", txt):
            add("autorun", f"variable de préchargement « {m.group(1)} » (valeur non recopiée)")
        return pts   # fichier d'environnement : jamais recopié dans le rapport, il peut porter des secrets
    if name in (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout", ".kshrc", ".cshrc", ".tcshrc", ".inputrc") or (name == "config.fish" and "fish" in parts):
        add("autorun", f"{name} : lancé par le shell au démarrage s'il est placé dans le domicile")
    if name in (".vimrc", ".exrc", ".nvimrc", ".gvimrc", "_vimrc", ".lvimrc", "init.vim", "init.lua", ".emacs", ".dir-locals.el", ".editorconfig-run"):
        add("autorun", f"{name} : lu et exécuté par l'éditeur à l'ouverture")
    if name in (".user.ini", "php.ini", ".htaccess") and re.search(r"(?i)auto_(prepend|append)_file|php_value|php_admin_value|sethandler|addhandler|addtype", txt):
        add("autorun", f"{name} : configure PHP ou le serveur (préchargement, gestionnaires) : {re.search(r'(?i)[^\n]*(auto_(prepend|append)_file|php_value|php_admin_value|sethandler|addhandler|addtype)[^\n]*', txt).group(0)[:160]}")
    if name in ("pnpm-workspace.yaml", ".pnpmfile.cjs", ".pnpmfile.mjs", "pnpmfile.cjs", "pnpmfile.mjs", ".yarnrc.yml") and (name != "pnpm-workspace.yaml" or re.search(r"(?m)^\s*pnpmfile\s*:", txt)) and (name != ".yarnrc.yml" or re.search(r"(?m)^\s*(plugins|yarnPath)\s*:", txt)):
        add("install", f"{name} : code lancé par le gestionnaire de paquets pendant l'installation")
    if p.suffix.lower() == ".gemspec" or name in ("extconf.rb", "rakefile", "gemfile", "mkrf_conf.rb"):
        add("install", f"{name} : évalué comme du Ruby à la construction ou à l'installation")
    if name in ("npm-shrinkwrap.json", "package-lock.json"):
        lj = load_json()
        if isinstance(lj, dict):
            for path_, d in (lj.get("packages") or {}).items():
                if not isinstance(d, dict) or not path_:
                    continue
                url = d.get("resolved") or ""
                if url and not url.startswith("https://registry.npmjs.org/"):
                    add("install", f"{name} impose une source hors registre pour {path_} : {url[:160]}")
                if d.get("hasInstallScript"):
                    add("install", f"{name} : {path_} a un script d'installation")
    if name in ("yarn.lock", "pnpm-lock.yaml", "bun.lock"):
        for m in re.finditer(r"(?i)(resolved|tarball)[\"'\s:]+(\S+://[^\"'\s,]+)", txt):
            if not re.match(r"https://registry\.(npmjs\.org|yarnpkg\.com)/", m.group(2)):
                add("install", f"{name} impose une source hors registre : {m.group(2)[:160]}")
    if name == "config" and ".git" in parts or name in (".gitconfig", "gitconfig"):
        for m in re.finditer(r"(?im)^\s*(hookspath|fsmonitor|sshcommand|pager|editor|askpass|gitproxy|textconv|process|clean|smudge|helper)\s*=\s*(.*)$", txt):
            add("autorun", f"configuration git « {m.group(1)} = {m.group(2)[:100]} » : lancée par git")
    if name == "package.json":
        pj = load_json()
        if not isinstance(pj, dict):
            add("install", "package.json illisible ou non conforme : impossible d'exclure un script d'installation")
            pj = {}
        sc = pj.get("scripts")
        if sc is not None and not isinstance(sc, dict):
            add("install", f"champ scripts non conforme : {json.dumps(sc)[:120]}")
            sc = {}
        for k, s in (sc or {}).items():
            if k in NPM_AUTO:
                add("install", f"script npm « {k} » : {s}")
            elif k in NPM_LOCAL:
                add("install" if mode == "dir" else "install_local", f"script npm « {k} »{'' if mode == 'dir' else ' (lancé depuis un dépôt git ou un dossier local)'} : {s}")
        if pj.get("gypfile"):
            add("install", "gypfile : compilation node-gyp à l'installation")
        bins = pj.get("bin")
        bnames = list(bins.keys()) if isinstance(bins, dict) else ([pj.get("name", "").split("/")[-1]] if isinstance(bins, str) else [])
        bad = [b for b in bnames if str(b).lower() in SHADOW_BINS]
        if bad:
            add("commande_detournee", f"déclare des commandes qui masquent des outils courants : {', '.join(bad)}")
        eng = pj.get("engines") if isinstance(pj.get("engines"), dict) else {}
        if "vscode" in eng:
            ev = pj.get("activationEvents") or []
            add("autorun" if ("*" in ev or "onStartupFinished" in ev or not ev) else "install_local", f"extension VS Code (main {pj.get('main') or pj.get('browser')}, activation {ev})")
    elif name == "binding.gyp":
        add("install", "binding.gyp : npm lance node-gyp rebuild à l'installation, même sans script déclaré")
    elif name in (".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs", "pnpmfile.js"):
        add("install", f"{name} embarqué : peut changer le shell des scripts ou précharger du code ({txt.strip()[:120]})")
    elif name == "setup.py":
        add("install", "setup.py : exécuté si pip installe depuis les sources")
    elif name == "pyproject.toml":
        m = re.search(r"build-backend\s*=\s*['\"]([^'\"]+)", txt)
        if m and m.group(1) not in STD_BACKENDS:
            add("install", f"moteur de construction inhabituel : {m.group(1)}")
        if "backend-path" in txt:
            add("install", "backend-path : le moteur de construction vient du paquet lui-même")
    elif p.suffix.lower() == ".pth":
        lines = [l for l in txt.splitlines() if re.match(r"\s*import[\s\t]", l)]
        add("autorun", f".pth : Python exécute ses lignes « import » à chaque démarrage ({len(lines)} ligne(s) : {' | '.join(lines)[:160]})")
    elif name == "composer.json":
        cj = load_json()
        if isinstance(cj, dict):
            if cj.get("scripts"):
                add("install" if mode == "dir" else "install_local", f"scripts composer : {json.dumps(cj['scripts'])[:160]}")
            if cj.get("type") == "composer-plugin":
                add("install", "plugin composer : s'exécute à chaque commande composer")
            al = cj.get("autoload") if isinstance(cj.get("autoload"), dict) else {}
            if al.get("files"):
                add("autoload", f"fichiers inclus à chaque chargement de l'autoloader : {json.dumps(al['files'])[:200]}")
    elif name == ".envrc":
        add("autorun", ".envrc : direnv l'exécute en entrant dans le dossier")
    elif name == "devcontainer.json" or name == ".devcontainer.json":
        dj = load_json() or {}
        cmds = {k: dj.get(k) for k in DEVCONTAINER_KEYS if isinstance(dj, dict) and dj.get(k)}
        add("autorun", f"conteneur de développement : commandes lancées à l'ouverture {json.dumps(cmds)[:200]}")
    elif name == ".gitmodules":
        add("note", "sous-modules git : leur code n'est pas dans ce contrôle")
    elif name == ".gitattributes" and re.search(r"filter\s*=", txt):
        add("autorun", "filtre git déclaré : peut lancer une commande à l'extraction")
    if "sitecustomize" in [x.split(".")[0] for x in parts] or "usercustomize" in [x.split(".")[0] for x in parts]:
        add("autorun", "sitecustomize / usercustomize : exécuté à chaque démarrage de Python")
    if len(parts) >= 3 and parts[-2] == "startup" and parts[-3].startswith("profile_"):
        add("autorun", "script de démarrage IPython")
    if ".git" in parts and "hooks" in parts and not name.endswith(".sample"):
        add("autorun", f"crochet git actif : {name}")
    if name == "tasks.json" and ".vscode" in parts:
        tj = load_json()
        if '"folderOpen"' in json.dumps(tj) or "folderOpen" in txt:
            add("autorun", "tâche VS Code lancée à l'ouverture du dossier")
    claude_file = name in CLAUDE_FILES or ".claude" in parts or ".claude-plugin" in parts
    if p.suffix.lower() in (".json", ".jsonc"):
        j = load_json()
        if j is None and claude_file:
            add("claude", f"{name} illisible en JSON : impossible d'exclure des commandes")
        if j is not None:
            def walk(o, path, inside):
                if isinstance(o, dict):
                    for k, v in o.items():
                        kp = f"{path}.{k}".lstrip(".")
                        if k in CLAUDE_KEYS or (claude_file and k in CLAUDE_FILE_KEYS):
                            add("claude", f"clé « {kp} » : {json.dumps(v, ensure_ascii=False)[:200]}")
                            walk(v, kp, True)
                        elif inside and k in ("command", "args", "url", "headersHelper"):
                            add("claude", f"« {kp} » : {json.dumps(v, ensure_ascii=False)[:200]}")
                        else:
                            walk(v, kp, inside)
                elif isinstance(o, list):
                    for i, v in enumerate(o):
                        walk(v, f"{path}[{i}]", inside)
            walk(j, "", False)   # dans un fichier Claude, seules les clés qui lancent du code comptent, pas une adresse d'auteur
    skill_file = p.suffix.lower() in (".md", ".markdown") and (name in ("skill.md", "agents.md", "claude.md") or any(x in ("commands", "agents", "skills", "output-styles") for x in parts[:-1]))
    if skill_file:
        add("skill_a_lire", "consignes données à l'agent : à lire en entier")
        for m in SKILL_SUSPECT.finditer(txt):
            if re.search(r"(?i)\b(never|not|don'?t|do not|no|must not|ne|jamais|pas|n')\W+(\w+\W+){0,2}$", txt[max(0, m.start() - 30):m.start()]):
                continue   # « never bypass », « ne jamais contourner » : consigne protectrice
            add("consigne_suspecte", f"ligne {txt.count(chr(10), 0, m.start()) + 1} : « {txt[max(0, m.start() - 40):m.end() + 60].strip()} »")
        for i, l in enumerate(txt.splitlines(), 1):
            if SKILL_SHELL.search(l):
                add("claude", f"ligne {i} « !`…` » (commande lancée au chargement du skill) : {l.strip()[:160]}")
        fm = txt.split("---", 2)[1] if txt.startswith("---") and txt.count("---") >= 2 else ""
        if re.search(r"^allowed-tools:.*\bBash", txt, re.M) or re.search(r"(?m)^allowed-tools\s*:[^\n]*(\n\s+-?\s*[^\n]*)*?\bBash\b", fm):
            add("claude", "le skill s'autorise l'outil Bash sans demander")
    return pts


def new_acc():
    return dict(hits=collections.defaultdict(list), counts=collections.Counter(), hosts=collections.Counter(), exfil=collections.Counter(),
                b64=[], compact=[], unread=[], natives=[], unknown_bin=[], archives_ok=[], archives_bad=[], links=[], points=[], env_net=[],
                persist_write=[], file_keys={}, nfiles=0, ntext=0, roots=[])


def _hit(acc, k, rel, line, text):
    acc["counts"][k] += 1
    if len(acc["hits"][k]) < MAX_HITS_KEPT:
        acc["hits"][k].append((rel, line, text.strip()[:160]))


def scan_file(acc, rel, p, txt, mode):
    suffix = p.suffix.lower(); name = p.name
    is_doc = (bool(DOC_NAME.match(name)) and suffix not in CODE_EXT) or name in ("METADATA", "PKG-INFO", "DESCRIPTION.rst") or (suffix in (".md", ".rst", ".markdown", ".adoc") and not (name.lower() in ("skill.md", "agents.md", "claude.md")))
    tag = " [test/doc]" if (TEST_RX.search(rel) or is_doc) else ""
    acc["points"] += install_points(rel, p, txt, mode)
    nl = [m.start() for m in re.finditer("\n", txt)]
    line_of = lambda pos: bisect.bisect_right(nl, pos) + 1
    spans = comment_spans(txt, suffix); starts = [s for s, _ in spans]
    keys = set()
    if B64_BLOCK.search(txt) and not name.endswith((".min.js", ".min.css")):
        acc["b64"].append(rel)
    if any(len(l) > 5000 for l in txt.split("\n")):
        acc["compact"].append(rel)
    if suffix in (".py", ".pyw", ".pth", "") or txt.startswith("#!") and "python" in txt[:80]:
        for i, l in enumerate(txt.split("\n")[:2], 1):
            m = PY_CODING.match(l)
            if m and m.group(1).lower().replace("_", "-") not in OK_CODINGS:
                _hit(acc, "encodage_source", rel + tag, i, f"déclaration d'encodage « {m.group(1)} » : le texte lu n'est pas celui que Python exécute"); keys.add("encodage_source")
    for hm in HOST_RE.finditer(txt):
        h = hm.group(1).lower().strip("[]")
        try:
            ipobj = ipaddress.ip_address(h)
            if ipobj.is_private or ipobj.is_loopback or ipobj.is_unspecified or ipobj.is_link_local:
                continue
        except ValueError:
            pass
        quiet = is_doc or (spans and in_spans(hm.start(), spans, starts))
        if EXFIL_HOSTS.search(h) and not quiet:
            acc["exfil"][h] += 1
        elif not BENIGN_HOSTS.search(h):
            acc["hosts"][h + (" (doc, test ou commentaire)" if quiet else "")] += 1
    for ip in ([] if is_doc else IP_LIT.findall(txt)):
        o = [int(x) for x in ip.split(".")]
        if max(o) <= 255 and not (o[0] in (0, 10, 127, 255) or (o[0] == 192 and o[1] == 168) or (o[0] == 172 and 16 <= o[1] <= 31) or (o[0] == 169 and o[1] == 254)):
            acc["exfil"][ip] += 1
    raw_matches = {}
    for k, rx in RX.items():
        ms = []
        k_out = "doc_telecharge" if (is_doc and k == "telecharge_lance") else k
        for m in rx.finditer(txt):
            if k in COMMENT_SKIP_KEYS and spans and in_spans(m.start(), spans, starts):
                continue
            ms.append(m)
            if len(acc["hits"][k_out]) < MAX_HITS_KEPT:
                _hit(acc, k_out, rel + tag, line_of(m.start()), txt[max(0, m.start() - 80):m.end() + 80].replace("\n", " "))
            else:
                acc["counts"][k_out] += 1
        if ms:
            keys.add(k)
        raw_matches[k] = collections.Counter(m.group(0) for m in rx.finditer(txt))
    if not is_doc:
        bidi = re.findall("[\u202a-\u202e\u2066-\u2069]", txt)
        if bidi:
            _hit(acc, "unicode_trompeur", rel + tag, line_of(txt.find(bidi[0])), f"{len(bidi)} caractère(s) de direction du texte : le code affiché n'est pas le code lu"); keys.add("unicode_trompeur")
        zw = re.findall("[\u200b-\u200d\u2060\u180e]|(?<!^)\ufeff", txt)
        if zw:
            _hit(acc, "unicode_invisible", rel + tag, line_of(txt.find(zw[0])), f"{len(zw)} caractère(s) invisibles dans le code")
        if suffix in (".py", ".pyw", ".pth") and any(ord(c) > 127 for c in txt) and unicodedata.normalize("NFKC", txt) != txt:
            for k in ("commande", "dynamique", "reseau", "environnement"):
                extra = collections.Counter(m.group(0) for m in RX[k].finditer(unicodedata.normalize("NFKC", txt))) - collections.Counter(m.group(0) for m in RX[k].finditer(txt))
                if extra:
                    _hit(acc, "obfuscation", rel + tag, 0, f"noms écrits en caractères larges ou homoglyphes que Python ramène à « {next(iter(extra))} »"); keys.add("obfuscation")
    # 11. alias d'import Python : import os as x ; x.system(...)
    if suffix in (".py", ".pyw", ".pth", ""):
        for m in re.finditer(r"(?m)^\s*import\s+(os|subprocess|pty|ctypes|socket|shutil|importlib|builtins)\s+as\s+(\w+)", txt):
            mod, alias = m.group(1), m.group(2)
            for c in re.finditer(rf"\b{re.escape(alias)}\.(system|popen|exec\w*|spawn\w*|run|call|Popen|check_output|check_call|getoutput|rmtree|remove|unlink|import_module|connect|socket|create_connection)\s*\(", txt):
                k = "reseau" if c.group(1) in ("connect", "socket", "create_connection") else "destruction" if c.group(1) in ("rmtree", "remove", "unlink") else "dynamique" if c.group(1) == "import_module" else "commande"
                _hit(acc, k, rel + tag, line_of(c.start()), f"{mod} importé sous le nom {alias} : {c.group(0)}"); keys.add(k)
    # 12-13. PowerShell et batch : insensibles à la casse
    if suffix in (".ps1", ".psm1", ".psd1", ".bat", ".cmd"):
        for m in re.finditer(r"(?i)invoke-expression|\biex\b|start-process|invoke-command|\[scriptblock\]::create|scriptblock\]::create|\.invokescript|invoke-webrequest|downloadstring|new-object\s+net\.webclient|frombase64string|-encodedcommand|\bcmd\s*/c|powershell\s+-", txt):
            k = "dynamique" if "scriptblock" in m.group(0).lower() or "invoke" in m.group(0).lower() and "web" not in m.group(0).lower() else "commande"
            _hit(acc, k, rel + tag, line_of(m.start()), m.group(0)); keys.add(k)
    for m in ESC_RUN.finditer(txt):
        d = unescape(m.group(0))
        if "\\" not in d and re.search(r"[A-Za-z]{3}", d):
            _hit(acc, "obfuscation", rel + tag, line_of(m.start()), f"texte écrit en échappements : « {d[:100]} »"); keys.add("obfuscation")
    # Texte remonté : ce qui n'y apparaît qu'après recollage a été caché exprès.
    norm = txt if (is_doc or suffix in (".json", ".jsonc", ".map", ".lock", ".svg", ".xml", ".csv")) else normalize(txt)
    if norm != txt:
        for k in DECODED_KEYS:
            nm = collections.Counter(m.group(0) for m in RX[k].finditer(norm))
            extra = nm - raw_matches.get(k, collections.Counter())
            for s in list(extra)[:20]:
                pos = norm.find(s)
                _hit(acc, k, rel + tag + " [assemblé]", 0, norm[max(0, pos - 60):pos + 100])
                _hit(acc, "obfuscation", rel + tag, 0, f"motif « {k} » caché par découpage ou échappement : {norm[max(0, pos - 60):pos + 100]}")
                keys.update((k, "obfuscation"))
    for pos, t, how in decoded_strings(txt):
        if DANGER_NAME.match(t):
            _hit(acc, "commande", rel + tag + f" [{how}]", line_of(pos), f"nom « {t.strip()} » caché ({how})")
            _hit(acc, "obfuscation", rel + tag, line_of(pos), f"nom « {t.strip()} » caché dans une chaîne {how}")
            keys.update(("commande", "obfuscation"))
        for k in DECODED_KEYS:
            if RX[k].search(t):
                _hit(acc, k, rel + tag + f" [{how}]", line_of(pos), t)
                _hit(acc, "obfuscation", rel + tag, line_of(pos), f"motif « {k} » dans une chaîne {how} : {t[:120]}")
                keys.update((k, "obfuscation"))
        for h in HOST_RE.findall(t):
            (acc["exfil"] if EXFIL_HOSTS.search(h.lower()) else acc["hosts"])[h.lower()] += 1
    # Exécution de contenu décodé : dynamique et décodage à moins de 200 caractères.
    for m in EXEC_DECODED.finditer(txt):
        _hit(acc, "obfuscation", rel + tag, line_of(m.start()), f"exécute du contenu décodé : {m.group(0)[:160]}"); keys.add("obfuscation")
    for m in RX["ecriture"].finditer(txt):
        if RX["persistance"].search(txt, max(0, m.start() - 300), m.end() + 300):
            acc["persist_write"].append(f"{rel}:{line_of(m.start())}"); break
    if is_doc:
        keys.discard("telecharge_lance")
    if suffix in (".php", ".phtml", ".inc") or txt.lstrip().startswith("<?php"):
        for m in re.finditer(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|(?P<b>`[^`\n]+`)", txt):   # opérateur d'exécution PHP, hors chaînes
            if m.group("b") and not (spans and in_spans(m.start(), spans, starts)):
                _hit(acc, "commande", rel + tag, line_of(m.start()), f"accents graves PHP (exécution shell) : {m.group(0)[:120]}"); keys.add("commande")
    acc["file_keys"][rel] = set() if is_doc else keys
    if not is_doc and "reseau" in keys and ({"env_complet", "sensible", "env_secret"} & keys):
        acc["env_net"].append(rel)


def _walk(acc, root, prefix, depth, mode):
    root = pathlib.Path(root).resolve()

    def onerr(e):
        acc["unread"].append(f"{prefix}{getattr(e, 'filename', '?')} (dossier illisible : {e.strerror})")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=onerr):
        dp = pathlib.Path(dirpath)
        dirnames.sort(); filenames.sort()
        for d in list(dirnames):
            if (dp / d).is_symlink():
                acc["links"].append(f"{prefix}{(dp / d).relative_to(root)} -> {os.readlink(dp / d)}"); dirnames.remove(d)
        for fn in filenames:
            p = dp / fn; rel = prefix + str(p.relative_to(root)); acc["nfiles"] += 1
            try:
                if p.is_symlink():
                    acc["links"].append(f"{rel} -> {os.readlink(p)}"); continue
                if not p.is_file():
                    acc["unread"].append(f"{rel} (fichier spécial)"); continue
                size = p.stat().st_size
                with open(p, "rb") as fh:
                    head = fh.read(8192)
                kind = classify_binary(p, head) if (b"\x00" in head or (head and sum(b < 9 or 13 < b < 32 for b in head) / len(head) > 0.1) or head[:4] == b"PK\x03\x04" or head[:2] == b"\x1f\x8b") else "texte"
                if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
                    kind = "texte"
                if kind == "natif":
                    acc["natives"].append(f"{rel} ({size} octets)"); continue
                if kind == "media" and p.suffix.lower() in MEDIA_EXT:
                    continue
                if kind == "media":
                    kind = "inconnu"   # en-tête d'image sur un fichier qui n'en est pas une : lu comme texte
                if kind == "archive":
                    if depth >= MAX_NEST:
                        acc["archives_bad"].append(f"{rel} (imbrication au-delà de {MAX_NEST} niveaux)"); continue
                    sub = pathlib.Path(tempfile.mkdtemp(prefix="imbrique-", dir=Q_ROOT))
                    refused, err = safe_extract(p, sub)
                    acc["links"] += [f"{rel}!/{r}" for r in refused]
                    if err:
                        acc["archives_bad"].append(f"{rel} ({err})")
                    acc["archives_ok"].append(rel)
                    _walk(acc, sub, rel + "!/", depth + 1, mode)
                    shutil.rmtree(sub, ignore_errors=True)
                    continue
                if size > MAX_READ:
                    acc["unread"].append(f"{rel} ({size // 1_000_000} Mo, trop gros)"); continue
                raw = p.read_bytes()
                txt, enc = as_text_norm(raw)
                if kind == "inconnu":
                    acc["unknown_bin"].append(f"{rel} ({size} octets, lu comme texte)")
                acc["ntext"] += 1
                scan_file(acc, rel, p, txt, mode)
            except Exception as e:
                acc["unread"].append(f"{rel} (erreur d'analyse : {type(e).__name__} {e})")


def analyse(root, mode="dir"):
    return analyse_many([root], mode)


def analyse_many(roots, mode="dir"):
    acc = new_acc()
    Q_ROOT.mkdir(parents=True, exist_ok=True)
    for i, r in enumerate(roots):
        acc["roots"].append(str(r))
        _walk(acc, r, f"[{pathlib.Path(r).name}] " if len(roots) > 1 else "", 0, mode)
    env_any = any("environnement" in k or "sensible" in k for k in acc["file_keys"].values())
    env_full = acc["counts"].get("env_complet", 0) > 0 or acc["counts"].get("env_secret", 0) > 0
    net_any = any("reseau" in k for k in acc["file_keys"].values())
    acc["env_net_pkg"] = "fort" if (env_full and net_any) else "lire" if (env_any and net_any) else None
    return acc


def build_flags(a, info, tree, mode="registre"):
    F = []

    def flag(k, msg, level=None):
        F.append((k, level or LEVEL.get(k, "lire"), clean(msg, 600)))

    def n_test(k):
        t = sum("[test/doc]" in h[0] for h in a["hits"].get(k, []))
        return f" (dont {t} dans tests ou docs)" if t else ""
    if info.get("integrity_ok") is False:
        flag("integrite", "l'archive téléchargée ne correspond pas à l'empreinte du registre : ne pas installer")
    elif info.get("ecosystem") and info.get("integrity_ok") is None:
        flag("integrite_inconnue", "le registre ne publie pas d'empreinte vérifiable pour cette archive")
    for e in info.get("errors", []):
        flag("extraction", e)
    pts = [("install", "registre", f"« {s} » : {v}") for s, v in (info.get("scripts") or {}).items()] + a["points"]
    for k, label in (("install", "s'exécute à l'installation"), ("claude", "s'exécute dans Claude Code ou déclare des commandes"),
                     ("autorun", "s'exécute tout seul (démarrage de Python, éditeur, dossier ouvert, git)"),
                     ("commande_detournee", "commandes qui masquent des outils courants"), ("consigne_suspecte", "consignes à l'agent qui demandent de cacher, contourner ou détruire"),
                     ("autoload", "fichiers PHP inclus automatiquement (à lire)"), ("skill_a_lire", "skill ou commande pour l'agent"), ("install_local", "scripts lancés seulement depuis un dépôt ou un dossier local")):
        lst = [x for x in pts if x[0] == k]
        if lst:
            flag(k, f"{label} : {len(lst)} point(s), par ex. {lst[0][1]} {lst[0][2][:120]}")
    if info.get("vulns"):
        flag("vulns" if info["vulns"][0][0] != "ERREUR" else "osv", f"{len(info['vulns'])} faille(s) connue(s) sur cette version" if info["vulns"][0][0] != "ERREUR" else info["vulns"][0][1])
    refused = (info.get("refused") or []) + a["links"]
    if refused:
        flag("lien", f"{len(refused)} lien(s) ou entrée(s) refusées : {', '.join(refused[:5])}")
    if a["exfil"]:
        flag("exfil", f"cite des services ou adresses souvent utilisés pour sortir des données : {', '.join(list(a['exfil'])[:10])}")
    if a["env_net"]:
        flag("env_reseau", f"{len(a['env_net'])} fichier(s) lisent l'environnement entier, une variable secrète ou un fichier sensible ET parlent au réseau : {', '.join(a['env_net'][:6])}")
    elif a.get("env_net_pkg"):
        flag("env_reseau" if a["env_net_pkg"] == "fort" else "env_reseau_paquet",
             "le paquet lit l'environnement entier ou une variable secrète, et parle au réseau ailleurs" if a["env_net_pkg"] == "fort" else "le paquet lit l'environnement et parle au réseau, dans des fichiers différents")
    if a["persist_write"]:
        flag("persistance_ecriture", f"écrit près d'un emplacement de démarrage ou de réglages : {', '.join(a['persist_write'][:5])}")
    for k, msg in (("telecharge_lance", "télécharge puis lance du code"), ("encodage_source", "fichier Python à encodage trompeur"),
                   ("obfuscation", "code caché, assemblé ou décodé"), ("decodage", "décode des données (base64, hex, compression)"),
                   ("dynamique", "exécution ou chargement dynamique de code"), ("commande", "lance des commandes ou du code natif"),
                   ("sensible", "cite des fichiers ou emplacements sensibles"), ("persistance", "cite des emplacements de démarrage ou de réglages"),
                   ("environnement", "lit les variables d'environnement"), ("reseau", "utilise le réseau"), ("destruction", "supprime ou vide des fichiers"), ("arret", "arrête ou bloque le programme hôte"),
                   ("doc_telecharge", "la documentation propose de télécharger puis lancer du code"),
                   ("unicode_trompeur", "caractères qui font afficher un autre code que celui exécuté"), ("unicode_invisible", "caractères invisibles dans le code")):
        if a["counts"].get(k):
            ex = a["hits"][k][0] if a["hits"].get(k) else None
            flag(k, f"{msg} : {a['counts'][k]} endroit(s){n_test(k)}" + (f" ; ex. {ex[0]}:{ex[1]} {ex[2][:110]}" if ex else ""))
    if a["hosts"]:
        flag("hote", f"{len(a['hosts'])} hôte(s) réseau hors domaines courants : {', '.join(h for h, _ in a['hosts'].most_common(8))}")
    if a["natives"]:
        flag("natif", f"{len(a['natives'])} binaire(s) exécutable(s) illisible(s) par ce contrôle : {', '.join(a['natives'][:5])}")
    if a["archives_bad"]:
        flag("archive_illisible", f"{len(a['archives_bad'])} archive(s) imbriquée(s) non lues : {', '.join(a['archives_bad'][:5])}")
    if a["archives_ok"]:
        flag("archives", f"{len(a['archives_ok'])} archive(s) imbriquée(s) ouvertes et lues : {', '.join(a['archives_ok'][:5])}")
    if a["unread"]:
        flag("non_lu", f"{len(a['unread'])} fichier(s) non lus : {', '.join(a['unread'][:5])}")
    if a["unknown_bin"]:
        flag("binaire_inconnu", f"{len(a['unknown_bin'])} fichier(s) binaires de type inconnu, lus comme texte : {', '.join(a['unknown_bin'][:5])}")
    if a["b64"]:
        flag("encode", f"{len(a['b64'])} fichier(s) avec de longs blocs encodés (souvent polices ou images : vérifier)")
    if a["compact"]:
        flag("compacte", f"{len(a['compact'])} fichier(s) minifiés ou compactés, illisibles à l'œil : {', '.join(a['compact'][:5])}")
    if info.get("ecosystem"):
        d = age_days(info.get("published"))
        if d is None:
            flag("date_inconnue", "date de publication inconnue : ancienneté non vérifiable")
        elif d < RECENT_DAYS:
            flag("recent", f"version publiée il y a {d:.1f} jour(s) : attendre {RECENT_DAYS} jours ou prendre la précédente (comptes volés repérés en quelques jours)")
    if info.get("prev_publisher") and info.get("publisher") and info["prev_publisher"] != info["publisher"]:
        flag("editeur", f"publiée par « {info['publisher']} », la version précédente {info.get('prev_version')} par « {info['prev_publisher']} »")
    if info.get("prev_provenance") and not info.get("provenance"):
        flag("editeur", "la version précédente avait une attestation de provenance, celle-ci non")
    if info.get("deprecated") or info.get("yanked"):
        flag("retire", f"version retirée ou dépréciée : {info.get('deprecated') or info.get('yanked')}")
    if info.get("downloads_week") is not None and info["downloads_week"] < 1000:
        flag("peu_utilise", f"{info['downloads_week']} téléchargements la semaine passée : vérifier le nom exact (sosie possible)")
    if info.get("ecosystem") and not info.get("repo"):
        flag("sans_depot", "aucun dépôt de code déclaré")
    if tree is not None:
        if not tree.get("ok"):
            flag("deps_non_resolu", "; ".join(tree.get("notes", []))[-400:] or "arbre non résolu")
        if tree.get("partiel"):
            flag("deps_partiel", "arbre résolu de façon approchée : " + "; ".join(n for n in tree.get("notes", []) if "--legacy" in n or "extensions PHP" in n))
        if tree.get("hors_registre"):
            flag("deps_hors_registre", f"{len(tree['hors_registre'])} dépendance(s) hors registre (git, adresse, lien) non contrôlées : {', '.join(tree['hors_registre'][:5])}")
        if tree.get("scripts"):
            flag("deps_scripts", f"{len(tree['scripts'])} dépendance(s) avec script d'installation : {', '.join(tree['scripts'][:10])}")
        if tree.get("vulns"):
            flag("deps_vulns", f"{len(tree['vulns'])} dépendance(s) avec faille connue : {', '.join(f'{n}@{v}' for n, v in list(tree['vulns'])[:10])}")
        if tree.get("osv_error"):
            flag("osv", tree["osv_error"])
        if tree.get("dep_alerts"):
            flag("deps_alertes", f"{len(tree['dep_alerts'])} dépendance(s) avec alertes fortes : " + "; ".join(f"{d} ({', '.join(sorted({k for k, _ in s}))})" for d, s in list(tree["dep_alerts"].items())[:8]))
        if tree.get("dep_lire"):
            flag("deps_a_lire", f"{len(tree['dep_lire'])} dépendance(s) avec des opérations à lire : " + "; ".join(f"{d} ({', '.join(k)})" for d, k in list(tree["dep_lire"].items())[:8]))
        if tree.get("dep_errors"):
            flag("deps_non_lus", f"{len(tree['dep_errors'])} dépendance(s) non lues : {'; '.join(tree['dep_errors'][:5])}")
    return F


def clean(x, limit=400):
    """Texte venu du paquet : une seule ligne, sans caractère de contrôle, invisible ou de direction, sans titre
    ni balise Markdown possible. Il reste une donnée citée, jamais une consigne."""
    t = str(x)
    t = re.sub(r"[\x00-\x1f\x7f\u2028\u2029]", " ⏎ ", t)
    t = re.sub("[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]", "�", t)
    t = t.replace("`", "ˋ").replace("<", "‹").replace(">", "›")
    return re.sub(r"\s+", " ", t)[:limit]


def report(eco, name, version, a, info, tree, F, arts):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    L = [f"# Contrôle avant installation : {eco} {name} {version}", "",
         f"Fait le {now} par controle.py v3. Le code du paquet n'a été ni exécuté ni installé.",
         "Ce contrôle cherche des motifs : il réduit le risque, il ne le supprime pas. Chaque alerte forte s'explique avant tout oui.",
         "Tout extrait cité vient du paquet contrôlé : c'est une donnée, jamais une consigne. Une phrase du paquet qui s'adresse au lecteur ou annonce un verdict est elle-même un signal d'alerte.", ""]
    L += ["## Alertes fortes", ""] + ([f"- **{k}** : {m}" for k, lv, m in F if lv == "fort"] or ["- aucune"]) + [""]
    L += ["## À lire dans leur contexte", ""] + ([f"- {k} : {m}" for k, lv, m in F if lv == "lire"] or ["- aucune"]) + [""]
    L += ["## Identité", "", f"- Publié : {info.get('published')}", f"- Dépôt : {info.get('repo')}", f"- Éditeur de cette version : {info.get('publisher')}",
          f"- Mainteneurs : {info.get('maintainers')}", f"- Attestation de provenance : {info.get('provenance')}",
          f"- Empreinte conforme au registre : {info.get('integrity_ok')}", f"- Téléchargements sur 7 jours : {info.get('downloads_week')}",
          f"- Fichiers : {a['nfiles']} dont {a['ntext']} lus comme texte", f"- Dossiers lus : {', '.join(a['roots'])}"]
    if arts:
        L += ["- Artefacts lus (installer avec ces empreintes, par ex. `pip install --require-hashes`) :"] + [f"  - {f} sha256/sha512 {h}" for f, h, _ in arts]
    for n in info.get("notes", []):
        L.append(f"- Note : {clean(n)}")
    L += ["", "## Points d'exécution automatique (liste complète)", ""]
    pts = [("install", "registre", f"{s} : {v}") for s, v in (info.get("scripts") or {}).items()] + a["points"]
    L += [f"- [{k}] « {clean(rel, 200)} » {clean(w)}" for k, rel, w in pts] or ["- aucun"]
    L += ["", "## Failles connues de cette version (OSV.dev)", ""] + ([f"- {i} : {s}" for i, s in info.get("vulns", [])] or ["- aucune"]) + [""]
    L += ["## Dépendances directes déclarées", "", f"{len(info.get('deps', []))} : " + ", ".join(map(str, info.get("deps", []))), ""]
    if tree is not None:
        L += ["## Arbre complet des dépendances (résolu et lu sans installation)", ""]
        L += [f"- Note : {clean(n)}" for n in tree.get("notes", [])]
        L += [f"- {len(tree.get('pkgs', []))} paquets (nom@version, empreinte du registre) :"] + [f"  - {n}@{v} {integ or ''}" for n, v, url, integ in tree.get("pkgs", [])]
        L += [f"- hors registre : {clean(s)}" for s in tree.get("hors_registre", [])]
        L += [f"- script d'installation : {clean(s)}" for s in tree.get("scripts", [])]
        L += [f"- faille : {n}@{v} : {', '.join(ids)}" for (n, v), ids in tree.get("vulns", {}).items()]
        for d, s in tree.get("dep_alerts", {}).items():
            L += [f"- alertes fortes dans {clean(d, 200)} :"] + [f"  - {k} : {clean(m)}" for k, m in s]
        L += [f"- à lire dans {d} : {', '.join(k)}" for d, k in tree.get("dep_lire", {}).items()]
        L += [f"- non lu : {e}" for e in tree.get("dep_errors", [])]
        L += [""]
    L += ["## Hôtes réseau cités", ""] + [f"- {clean(h, 120)} ({c}) [sortie de données possible]" for h, c in a["exfil"].most_common()] + [f"- {clean(h, 120)} ({c})" for h, c in a["hosts"].most_common()] + [""]
    for k in list(P) + ["doc_telecharge"]:
        lst = a["hits"].get(k, []); n = a["counts"].get(k, 0)
        if n:
            L += [f"## {k} ({n})", ""] + [f"- « {clean(f, 200)}:{i} » {clean(l)}" for f, i, l in lst] + ([f"- … {n - len(lst)} autres non affichés"] if n > len(lst) else []) + [""]
    for title, lst in (("Binaires exécutables", a["natives"]), ("Archives imbriquées lues", a["archives_ok"]), ("Archives non lues", a["archives_bad"]),
                       ("Fichiers non lus", a["unread"]), ("Binaires de type inconnu", a["unknown_bin"]), ("Liens symboliques", a["links"]),
                       ("Blocs encodés", a["b64"]), ("Fichiers compactés", a["compact"]), ("Écritures près d'emplacements de démarrage", a["persist_write"])):
        if lst:
            L += [f"## {title} ({len(lst)})", ""] + [f"- {clean(x)}" for x in lst] + [""]
    return "\n".join(L)


def main():
    args = [x for x in sys.argv[1:] if x != "--json"]
    want_json = "--json" in sys.argv
    if len(args) < 2:
        sys.exit(__doc__)
    eco, name = args[0], args[1]
    version = args[2] if len(args) > 2 else None
    OUT.mkdir(parents=True, exist_ok=True); Q_ROOT.mkdir(parents=True, exist_ok=True)
    for old in Q_ROOT.iterdir():   # quarantaines de plus de 7 jours
        if old.is_dir() and datetime.datetime.now().timestamp() - old.stat().st_mtime > 7 * 86400:
            shutil.rmtree(old, ignore_errors=True)
    if eco != "dir" and (not version or version in ("latest", "main", "master", "*", "next")):
        sys.exit("version figée obligatoire (jamais latest ni branche) : controle.py <eco> <nom> <x.y.z>")
    label = re.sub(r"[^\w.@+-]", "_", pathlib.Path(name).expanduser().resolve().name if eco == "dir" else f"{name.replace('/', '_')}-{version}")[:120]
    rep = OUT / f"{label}.md"
    rep.write_text(f"# Contrôle incomplet : {eco} {name} {version}\n\nContrôle commencé le {datetime.datetime.now():%Y-%m-%d %H:%M}, pas terminé. Ne pas installer sur la foi de ce fichier.\n")
    try:
        tree = None; arts = []
        if eco == "dir":
            root = pathlib.Path(name).expanduser().resolve()
            if not root.is_dir():
                sys.exit(f"dossier introuvable : {root}")
            info = {"notes": [], "errors": []}; version = "local"
            if (root / ".git").is_dir():
                head = (root / ".git" / "HEAD").read_text().strip()
                ref = root / ".git" / head[5:] if head.startswith("ref: ") else None
                info["notes"].append(f"git : {ref.read_text().strip() if ref and ref.exists() else head}")
            a = analyse(root, mode="dir")
            work = pathlib.Path(tempfile.mkdtemp(prefix=f"{label}-arbre-", dir=Q_ROOT))
            # Tous les manifestes du dossier, chacun résolu dans son propre écosystème.
            manifests = [("npm", root / "package.json"), ("composer", root / "composer.json")] + [("pypi", f) for f in sorted(root.glob("requirements*.txt")) + [root / "pyproject.toml"]]
            trees = []
            for e2, mf in manifests:
                if not mf.is_file():
                    continue
                if e2 == "pypi":
                    t = resolve_tree("pypi", work / f"{e2}-{mf.name}", manifest=mf)
                else:
                    try:
                        m = json.loads(mf.read_text())
                    except ValueError:
                        m = None
                    t = resolve_tree(e2, work / e2, manifest=m) if isinstance(m, dict) else {"ok": False, "notes": [f"{mf.name} illisible : arbre non résolu"], "pkgs": [], "scripts": [], "hors_registre": []}
                t["eco"] = e2; t["source"] = mf.name
                trees.append(t)
        else:
            q = pathlib.Path(tempfile.mkdtemp(prefix=f"{label[:60]}-", dir=Q_ROOT))
            version, info, arts = fetch(eco, name, version, q)
            info["ecosystem"] = eco
            try:
                info["vulns"] = osv_detail(eco, name, version)
            except Exception as e:
                info["vulns"] = [("ERREUR", f"OSV.dev injoignable : {e}")]
            a = analyse_many([x[2] for x in arts], mode="registre")
            tree = resolve_tree(eco, q / "arbre", name=name, version=version); tree["eco"] = eco; tree["source"] = "registre"
            trees = [tree]; work = q
        for i, t in enumerate(trees):
            if not t.get("ok"):
                continue
            e2 = t["eco"]
            try:
                t["vulns"] = osv_batch(e2, [(n, v) for n, v, *_ in t["pkgs"] if eco == "dir" or (n.lower(), str(v)) != (name.lower(), str(version))])
            except Exception as e:
                t["vulns"] = {}; t["osv_error"] = f"OSV.dev injoignable pour l'arbre : {e}"
            deps_dir = work / f"deps{i}"; deps_dir.mkdir(parents=True, exist_ok=True)
            t["dep_alerts"], t["dep_errors"], t["dep_lire"] = scan_dependencies(e2, t, deps_dir, exclude=None if eco == "dir" else (name, version))
        tree = None
        if trees:   # fusion des arbres pour le rapport ; chaque note dit de quel manifeste elle vient
            tree = {"ok": all(t.get("ok") for t in trees), "partiel": any(t.get("partiel") for t in trees),
                    "notes": [f"[{t['source']}] {n}" for t in trees for n in t.get("notes", [])] + [f"[{t['source']}] arbre non résolu" for t in trees if not t.get("ok")],
                    "pkgs": [p for t in trees for p in t.get("pkgs", [])], "scripts": [s for t in trees for s in t.get("scripts", [])],
                    "hors_registre": [h for t in trees for h in t.get("hors_registre", [])], "vulns": {(f"{t['eco']}:{k[0]}", k[1]): v for t in trees for k, v in t.get("vulns", {}).items()},
                    "dep_lire": {k: v for t in trees for k, v in t.get("dep_lire", {}).items()},
                    "dep_alerts": {k: v for t in trees for k, v in t.get("dep_alerts", {}).items()}, "dep_errors": [e for t in trees for e in t.get("dep_errors", [])],
                    "osv_error": "; ".join(t["osv_error"] for t in trees if t.get("osv_error")) or None}
        F = build_flags(a, info, tree, mode="dir" if eco == "dir" else "registre")
        rep.write_text(report(eco, name, version, a, info, tree, F, arts))
    except SystemExit:
        raise
    except Exception:
        rep.write_text(f"# Contrôle échoué : {eco} {name} {version}\n\nNe pas installer : le contrôle n'a pas abouti.\n\n```\n{traceback.format_exc()}\n```\n")
        print(f"Contrôle échoué, rapport : {rep}"); traceback.print_exc(); sys.exit(2)
    print(f"Rapport : {rep}")
    print(f"{eco} {name} {version} | fichiers {a['nfiles']} (texte lus {a['ntext']}) | alertes fortes {sum(lv == 'fort' for _, lv, _ in F)} | à lire {sum(lv == 'lire' for _, lv, _ in F)}")
    for k, lv, m in F:
        print(f" {'!!' if lv == 'fort' else ' !'} [{k}] {m}")
    if want_json:
        print(json.dumps({"flags": sorted({k for k, _, _ in F}), "fortes": sorted({k for k, lv, _ in F if lv == "fort"})}))


if __name__ == "__main__":
    main()
