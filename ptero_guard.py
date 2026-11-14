#!/usr/bin/env python3
"""ptero-guard : détection d'activité illégale ou anormale sur les serveurs Pterodactyl.

Lecture seule par défaut : aucun accès au socket Docker, ni à la base ou aux
identifiants du panel. Sources lues :
  - /var/lib/docker/containers/*/config.v2.json, hostconfig.json (inventaire)
  - cgroups v2 (processus, CPU), /proc/<pid> (exe, cmdline, net/dev)
  - /proc/net/nf_conntrack (connexions sortantes des conteneurs)
  - /var/lib/pterodactyl/volumes (fichiers des serveurs, + clamd facultatif)
  - /var/log/pterodactyl/wings.log, /var/log/nginx/pterodactyl.access.log

Niveaux : critique (Discord immédiat), alerte (Discord immédiat), info (résumé quotidien).
"""
import argparse
import collections
import datetime as dt
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import struct
import tarfile
import zlib
import sys
import threading
import time
import tomllib
import urllib.request
import zipfile

VERSION = "1.2.0"
log = logging.getLogger("ptero-guard")

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
DEFAULTS = {
    "state_dir": "/var/lib/ptero-guard",
    "log_dir": "/var/log/ptero-guard",
    "webhook_file": "/etc/ptero-guard/webhook",
    "panel_url": "",              # ex. https://panel.exemple.fr (lien dans les alertes)
    "docker_dir": "/var/lib/docker/containers",
    "volumes_dir": "/var/lib/pterodactyl/volumes",
    "wings_log": "/var/log/pterodactyl/wings.log",
    "panel_access_log": "/var/log/nginx/pterodactyl.access.log",
    "clamd_container": "clamav",  # conteneur Docker clamd (facultatif)
    "clamd_port": 3310,
    "digest_hour": 9,
    "cooldown_alert_s": 6 * 3600,
    "cooldown_critique_s": 3600,
    # Réaction : gel (cgroup.freeze, réversible) du conteneur sur alerte critique.
    "freeze_on_critique": False,
    # Gel automatique limité aux détections quasi certaines (mineur identifié, processus
    # camouflé en thread noyau, malware ClamAV hors PUA, .jar infecté).
    "auto_freeze": True,
    "intervals": {"process": 15, "network": 10, "traffic": 10, "cpu": 30,
                  "files": 300, "logs": 30, "intel": 6 * 3600, "web": 900},
    "thresholds": {
        "cpu_pct": 90,               # % de la limite du conteneur
        "cpu_minutes": 20,           # durée soutenue
        "tx_mbps": 150,              # débit sortant soutenu
        "tx_pps": 40000,
        "traffic_seconds": 60,
        "distinct_dst_5min": 300,    # IP distinctes contactées en 5 min
        "sensitive_dst_5min": 15,    # IP distinctes sur ports SSH/RDP/DB... en 5 min
        "same_port_dst_5min": 100,   # IP distinctes sur un même port en 5 min
        "sftp_scan_per_hour": 60,
        "panel_4xx_10min": 40,
        "file_max_mb": 30,           # analyse des signatures
        "clamav_max_mb": 100,        # ClamAV seul au-delà (StreamMaxLength par défaut de clamd)
        "proc_cpu_pct": 80,          # % d'un cœur pour un seul processus
        "proc_cpu_minutes": 10,
        "media_warez_mb": 300,
        "tx_gb_hour": 15,            # volume sortant sur 1 h (diffusion de fichiers)
        "combo_lines": 500,          # lignes email:motdepasse dans un fichier texte
    },
    "allow": {
        # Exceptions : "uuid" ou "uuid:regle" (ex. "d8caabc2-...:cpu_soutenu")
        "rules": [],
        "dst_ips": [],
    },
}


def deep_merge(base, extra):
    out = dict(base)
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path):
    cfg = DEFAULTS
    if path and os.path.exists(path):
        with open(path, "rb") as f:
            cfg = deep_merge(DEFAULTS, tomllib.load(f))
    return cfg


# --------------------------------------------------------------------------
# Signatures
# --------------------------------------------------------------------------
MINER_PROC = re.compile(
    r"\b(xmrig|xmr-stak|minerd|cpuminer|ccminer|t-rex|lolminer|nbminer|gminer|srbminer"
    r"|phoenixminer|nanominer|teamredminer|ethminer|bminer|xmrstak|cryptonight|kdevtmpfsi"
    r"|kinsing|c3pool|moneroocean|nicehash|unmineable|randomx)\b"
    r"|stratum\+(tcp|ssl|tls)://|--donate-level|--coin[= ]|-a\s+rx/0", re.I)
ATTACK_PROC = re.compile(
    r"\b(nmap|masscan|zmap|hping3?|hydra|medusa|ncrack|sqlmap|nikto|slowloris|mhddos|ufonet"
    r"|goldeneye|torshammer|xerxes|msfconsole|msfvenom|sliver-server|t50|bonesi|pkt-gen"
    r"|udpflood|synflood|httpflood|ddos)\b", re.I)
TUNNEL_PROC = re.compile(
    r"\b(tor|ngrok|cloudflared|frpc|frps|chisel|gost|v2ray|xray|sing-box|ss-server|ss-local"
    r"|trojan-go|3proxy|microsocks|sockd|danted|gs-netcat|gsocket|bore|playit|tailscaled"
    r"|zerotier-one|wireguard-go|openvpn)\b", re.I)
TORRENT_PROC = re.compile(r"\b(transmission-(daemon|cli)|qbittorrent(-nox)?|aria2c|rtorrent|deluged?|webtorrent|ctorrent"
                          r"|btpd|opentracker|bittorrent-tracker|peerflix|torrentd?|rqbit|imdl)\b", re.I)
TORRENT_PORTS = set(range(6881, 6890)) | {6969, 51413}
REVSHELL = re.compile(
    rb"/dev/tcp/\d{1,3}\.\d{1,3}|bash -i\s*>&|pty\.spawn\(|\bnc(at)?\s+(-\w+\s+)*-e\s+/bin/"
    rb"|socat\s+[^\n]{0,80}exec:|mkfifo\s+/tmp/[^\n]{0,60}\|\s*/bin/(ba)?sh", re.I)
SUSPICIOUS_EXE_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")
# Nom de thread noyau dans un conteneur : aucun usage légitime, technique classique des mineurs
KTHREAD_NAME = re.compile(r"^\[?(kworker|kthreadd|ksoftirqd|kswapd|kdevtmpfs|migration/|rcu_(sched|preempt|gp)|watchdog/|jbd2/|kblockd|khugepaged)")
# Images « runtime » où le code du client est interprété : un binaire du volume qui
# monopolise un cœur y est anormal (sur les images de jeux, c'est le cas normal).
RUNTIME_IMAGE = re.compile(r"yolks:(nodejs|python|java|bun|deno)|/(node|python|eclipse-temurin|openjdk|oven/bun)[:@]", re.I)

# Contenu des fichiers : (règle, niveau, déclencheurs, regex, description)
# Les regex tournent sur le contenu passé en minuscules, et seulement si un des
# déclencheurs (sous-chaînes simples, très rapides) est présent.
FILE_SIGS = [
    ("minage", "critique", (b"stratum+", b"xmrig", b"donate-level"),
     re.compile(rb"stratum\+(tcp|ssl|tls)://|\bxmrig\b|--donate-level|\"donate-level\""),
     "configuration ou binaire de minage"),
    ("grabber", "critique", (b"leveldb", b"discord_desktop_core", b"login data", b"cookies", b"wallet.dat", b"exodus"),
     re.compile(rb"local storage.{1,6}leveldb|discord_desktop_core|login data.{1,40}(sqlite|chrom|crypt)"
                rb"|cookies.{1,6}network|wallet\.dat|exodus[\\/]{1,2}exodus\.wallet"),
     "vol de jetons, cookies ou portefeuilles (grabber)"),
    ("reverse_shell", "critique", (b"/dev/tcp/", b"bash -i", b"mkfifo", b"pty.spawn", b"-e /bin/"),
     re.compile(rb"/dev/tcp/\d{1,3}\.\d{1,3}|bash -i\s*>&|\bnc(at)?\s+(-\w+\s+)*-e\s+/bin/"
                rb"|mkfifo\s+/tmp/[^\n]{0,60}\|\s*/bin/(ba)?sh"
                rb"|socket\.socket\([^\n]{0,200}\n[^\n]{0,200}connect\([^\n]{0,300}pty\.spawn"),
     "reverse shell"),
    ("webshell", "critique", (b"eval", b"assert", b"system", b"passthru", b"shell_exec", b"exec", b"c99shell", b"r57shell", b"filesman"),
     re.compile(rb"eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(|c99shell|r57shell|\bfilesman\b"
                rb"|\b(eval|assert|system|passthru|shell_exec|exec|popen)\s*\(\s*\$_(post|get|request|cookie)\["),
     "webshell PHP"),
    ("outil_ddos", "critique", (b"mhddos", b"slowloris", b"flood", b"bypass", b"l7_attack", b"booter", b"stresser", b"hping3"),
     re.compile(rb"\b(mhddos|slowloris|udp_?flood|syn_?flood|http_?flood|cfbypass|cf_bypass|l7_attack"
                rb"|booter|stresser|hping3)\b"),
     "outil d'attaque DDoS"),
    ("selfbot", "alerte", (b"selfbot", b"selfcord", b"discum", b"discord.py-self"),
     re.compile(rb"discord\.js-selfbot|discord-selfbot|selfcord|\bdiscum\b|discord\.py-self|selfbot-v13"),
     "selfbot Discord (interdit par les CGU Discord)"),
    ("payload_distant", "alerte", (b"|sh", b"| sh", b"|bash", b"| bash", b"| zsh", b"|zsh", b"| dash", b"|dash"),
     re.compile(rb"(curl|wget)\s[^\n|;]{0,200}\|\s*(ba|z|da)?sh\b"),
     "téléchargement et exécution d'un script distant"),
    ("torrent_lib", "alerte", (b"torrent", b"magnet:?"),
     re.compile(rb"require\(\s*['\"](webtorrent|torrent-stream|bittorrent-dht|bittorrent-tracker|peerflix)['\"]"
                rb"|from\s+['\"](webtorrent|torrent-stream)['\"]|\bimport\s+libtorrent\b|\"(webtorrent|torrent-stream|peerflix)\"\s*:"
                rb"|magnet:\?xt=urn:btih:[0-9a-z]{32}"),
     "partage BitTorrent (bibliothèque torrent ou lien magnet)"),
    ("pedocriminalite", "critique", (b"pthc", b"ptsc", b"hussyfan", b"ygold", b"babyshivid", b"porn", b"pedo", b"paedo", b"jailbait"),
     re.compile(rb"(?<![a-z0-9])(pthc|ptsc)(?![a-z])|hussyfan|r@ygold|raygold|babyshivid|child[ _.-]?porn|\bpa?edo[ _.-]?(porn|sex|video|pics?)"
                rb"|jailbait[ _.-]?(porn|sex|nude|video)|preteen[ _.-]?(porn|sex|nude)"),
     "termes associés à des contenus pédocriminels"),
    ("carding", "alerte", (b"fullz", b"cvv", b"dump", b"track", b"checker", b"combolist"),
     re.compile(rb"\bfullz\b|\bcvv2?\s?shop|\bdumps?\s?(\+|with|&|and)\s?pins?\b|\btrack\s?1\s?(&|and|\+)\s?2\b"
                rb"|\b(cc|bin|card)\s?checker\b|\bcombo\s?list"),
     "fraude à la carte bancaire ou revente de comptes volés"),
    ("phishing", "alerte", (b"nitro", b"steamcommunity.com.", b"gift", b"verify your"),
     re.compile(rb"(free|claim|get)\s+(discord\s+)?nitro|steamcommunity\.com\.[a-z]{2,}|discord(app)?-?gift[a-z]*\.(?!com)"
                rb"|verify your (paypal|apple id|microsoft) account"),
     "page d'hameçonnage ou arnaque Nitro"),
]
# Règles applicables selon le type de fichier
SIG_ONLY_EXT = {"webshell": {".php", ".phtml", ".inc", ".php5", ".php7"},
                "phishing": {".html", ".htm", ".php", ".js"},
                "pedocriminalite": {".html", ".htm", ".php", ".txt", ".json", ".md", ".csv"},
                "carding": {".html", ".htm", ".php", ".js", ".py", ".txt", ".md"},
                "outil_ddos": {".py", ".js", ".mjs", ".cjs", ".ts", ".go", ".sh", ".pl", ".rb", ".lua", ".php", ".bat", ".ps1"}}
ARCHIVE_EXT = {".jar", ".zip", ".tar", ".tgz", ".gz", ".rar", ".7z", ".xz", ".bz2"}          # contenu compressé : traité par _check_jar / ClamAV
BINARY_RULES = {"minage", "grabber", "reverse_shell"}   # règles utiles sur un exécutable
# Indicateurs de compromission connus dans les .jar (fractureiser, Skyrage, etc.)
JAR_IOCS = re.compile(
    rb"85\.217\.144\.130|107\.189\.3\.101|files-8ie\.pages\.dev|dev/neko/nekoclient|skyrage|"
    rb"connect\.skyrage\.de|stratum\+tcp://|/dev/tcp/", re.I)
PIRACY_NAMES = re.compile(r"nulled|leaked|blackspigot|\bcracked\b|\bcrack[-_ .]|(?<![a-z-])keygen|warez", re.I)
# Noms de fichiers : indicateurs pédocriminels quasi univoques (gel) et termes plus larges (alerte)
CSAM_NAMES_STRONG = re.compile(r"(?<![a-z0-9])(pthc|ptsc)(?![a-z])|hussyfan|r@ygold|raygold|babyshivid|kidzilla|child[ _.-]?porn", re.I)
CSAM_NAMES = re.compile(r"(?<![a-z])pa?edo(phil\w*)?[ _.-]?(porn|sex|video|pics?)|jailbait|preteen[ _.-]?(porn|sex|nude)"
                        r"|lolita[ _.-]?(porn|sex|nude)|(?<![0-9])(1[0-5]|[5-9])\s?(yo|y\.o\.?|ans)[ _.-]+(porn|sex|nude|naked)", re.I)
FRAUD_NAMES = re.compile(r"combo[ _.-]?list|\bfullz\b|\bcvv\b|\bdumps?[ _.-]?pins?\b", re.I)
COMBO_LINE = re.compile(rb"^[\w.+-]{1,64}@[\w-]{1,63}(\.[\w-]{1,63})+\s?[:;|]\s?\S{4,}\s*$", re.M)
COMBO_EXT = {".txt", ".csv", ".lst", ".log", ".dat", ""}
FILEHOST_RX = re.compile(rb"filebrowser|\bh5ai\b|pydio|nextcloud|owncloud|seafile|pairdrop|psitransfer|projectsend"
                         rb"|jirafeau|\blufi\b|chibisafe|zipline|pingvin|\bxbackbone\b|picoshare|transfer\.sh"
                         rb"|\bdufs\b|miniserve|copyparty|droppy|qbittorrent|transmission web")
MEDIA_EXT = {".mkv", ".mp4", ".avi", ".mov", ".iso", ".m4v", ".wmv"}
SCAN_EXT = {".jar", ".js", ".mjs", ".cjs", ".ts", ".py", ".sh", ".php", ".pl", ".rb", ".bat", ".ps1",
            ".html", ".htm", ".json", ".yml", ".yaml", ".toml", ".cfg", ".conf", ".txt", ".exe", ".dll",
            ".zip", ".so", ".bin", ".lua", ".go", ".tar", ".tgz", ".gz", ".rar", ".7z", ".apk", ".msi",
            ".scr", ".vbs", ".xz", ".bz2"}
CLAM_EXT = {".jar", ".exe", ".dll", ".zip", ".sh", ".py", ".js", ".php", ".bat", ".ps1", ".bin", ".html",
            ".tar", ".tgz", ".gz", ".rar", ".7z", ".apk", ".msi", ".scr", ".vbs", ".xz", ".bz2"}
CLAM_BIG_EXT = {".jar", ".exe", ".dll", ".zip", ".bin", ".tar", ".tgz", ".gz", ".rar", ".7z", ".apk", ".msi",
                ".scr", ".xz", ".bz2", ""}
SKIP_DIRS = {".git", ".cache", "world", "world_nether", "world_the_end", "region", "playerdata",
             "__pycache__", "libraries", "versions", ".npm", ".bun"}
SCAN_EXT |= CLAM_EXT
CLAM_SKIP_PARTS = ("/node_modules/", "/.venv/", "/site-packages/", "/dist-packages/")
# Arborescences système (eggs « VPS » qui embarquent un rootfs complet)
SYSTEM_PREFIXES = ("/usr/", "/lib/", "/lib32/", "/lib64/", "/bin/", "/sbin/", "/etc/", "/boot/", "/proc/",
                   "/sys/", "/dev/", "/var/lib/", "/var/cache/", "/var/log/", "/snap/")

MINING_PORTS = {3333, 3334, 4444, 5555, 5556, 6666, 7777, 9000, 10128, 10343, 13333, 14433, 14444,
                20535, 45560, 45700}
SENSITIVE_PORTS = {22, 23, 2222, 2323, 3389, 5900, 445, 139, 1433, 3306, 5432, 6379, 9200, 11211, 27017}
POOL_DOMAINS = [
    "pool.supportxmr.com", "xmr.pool.minergate.com", "gulf.moneroocean.stream", "xmr-eu1.nanopool.org",
    "xmr-eu2.nanopool.org", "pool.hashvault.pro", "auto.c3pool.org", "xmr.2miners.com", "rx.unmineable.com",
    "randomxmonero.auto.nicehash.com", "monero.herominers.com", "pool.minexmr.com", "xmrpool.eu",
    "rvn.2miners.com", "etc.2miners.com", "kas.2miners.com", "eth.f2pool.com", "stratum.antpool.com",
    "btc.viabtc.io", "xmr.f2pool.com", "pool.xmr.pt", "mine.c3pool.com", "us-west.minexmr.com",
]


# --------------------------------------------------------------------------
# Utilitaires
# --------------------------------------------------------------------------
def read(path, mode="r", limit=None):
    try:
        with open(path, mode) as f:
            return f.read(limit) if limit else f.read()
    except (OSError, ValueError):
        return None


def now():
    return time.time()


class State:
    """Petit état persistant (offsets de logs, empreintes vues, cooldowns)."""

    def __init__(self, path):
        self.path = path
        self.data = {}
        raw = read(path)
        if raw:
            try:
                self.data = json.loads(raw)
            except ValueError:
                log.warning("état illisible, réinitialisé")
        self.lock = threading.Lock()

    def get(self, k, default=None):
        return self.data.get(k, default)

    def set(self, k, v):
        with self.lock:
            self.data[k] = v

    def save(self):
        with self.lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.data, f)
            os.replace(tmp, self.path)


# --------------------------------------------------------------------------
# Inventaire des conteneurs Ptero (sans socket Docker)
# --------------------------------------------------------------------------
class Container:
    __slots__ = ("id", "uuid", "image", "pid", "ip", "cgroup", "cpu_limit", "location", "frozen")

    @property
    def short(self):
        return self.uuid[:8]


class Inventory:
    def __init__(self, cfg):
        self.cfg = cfg
        self.by_uuid = {}
        self.by_ip = {}
        self.lock = threading.Lock()
        self.ncpu = os.cpu_count() or 1
        self.started = None      # uuid -> StartedAt (y compris arrêtés)
        self.just_started = set()  # serveurs (re)démarrés depuis le dernier passage

    def refresh(self):
        found = {}
        starts = {}
        base = self.cfg["docker_dir"]
        try:
            ids = os.listdir(base)
        except OSError:
            ids = []
        for cid in ids:
            raw = read(f"{base}/{cid}/config.v2.json")
            if not raw:
                continue
            try:
                d = json.loads(raw)
            except ValueError:
                continue
            labels = (d.get("Config") or {}).get("Labels") or {}
            st = d.get("State") or {}
            if labels.get("Service") != "Pterodactyl":
                continue
            starts[d.get("Name", "").lstrip("/")] = st.get("StartedAt") or ""
            if not st.get("Running"):
                continue
            c = Container()
            c.id = cid
            c.uuid = d.get("Name", "").lstrip("/")
            c.image = (d.get("Config") or {}).get("Image", "?")
            c.pid = st.get("Pid") or 0
            nets = (d.get("NetworkSettings") or {}).get("Networks") or {}
            c.ip = next((n.get("IPAddress") for n in nets.values() if n.get("IPAddress")), None)
            c.cgroup = f"/sys/fs/cgroup/system.slice/docker-{cid}.scope"
            env = (d.get("Config") or {}).get("Env") or []
            c.location = next((e.split("=", 1)[1] for e in env if e.startswith("P_SERVER_LOCATION=")), "")
            cm = (read(c.cgroup + "/cpu.max") or "max").split()
            c.cpu_limit = (int(cm[0]) / int(cm[1])) if cm and cm[0] != "max" else float(self.ncpu)
            c.frozen = (read(c.cgroup + "/cgroup.freeze") or "0").strip() == "1"
            found[c.uuid] = c
        with self.lock:
            if self.started is not None:
                self.just_started |= {u for u, t in starts.items() if t and self.started.get(u) != t}
            self.started = starts
            self.by_uuid = found
            self.by_ip = {c.ip: c for c in found.values() if c.ip}

    def pop_started(self):
        with self.lock:
            s, self.just_started = self.just_started, set()
            return s

    def all(self):
        with self.lock:
            return list(self.by_uuid.values())

    def ip(self, ip):
        with self.lock:
            return self.by_ip.get(ip)


def cgroup_pids(cgroup):
    pids = []
    for root, _dirs, files in os.walk(cgroup):
        if "cgroup.procs" in files:
            raw = read(os.path.join(root, "cgroup.procs")) or ""
            pids.extend(int(p) for p in raw.split() if p.isdigit())
    return pids


def clamd_address(cfg):
    base = cfg["docker_dir"]
    for cid in os.listdir(base):
        r = read(f"{base}/{cid}/config.v2.json")
        if not r or f'"Name":"/{cfg["clamd_container"]}"' not in r:
            continue
        d = json.loads(r)
        for n in d["NetworkSettings"]["Networks"].values():
            if n.get("IPAddress"):
                return n["IPAddress"], cfg["clamd_port"]
    return None


# --------------------------------------------------------------------------
# Alertes
# --------------------------------------------------------------------------
COLORS = {"critique": 0xB3261E, "alerte": 0xC77700, "info": 0x4A6A4D}


class Alerter:
    def __init__(self, cfg, state, inventory):
        self.cfg = cfg
        self.state = state
        self.inv = inventory
        self.queue = collections.deque()
        self.cv = threading.Condition()
        os.makedirs(cfg["log_dir"], exist_ok=True)
        self.jsonl = os.path.join(cfg["log_dir"], "alertes.jsonl")
        self.allow = set(cfg["allow"]["rules"])
        self.outbox_lock = threading.Lock()
        threading.Thread(target=self._sender, daemon=True, name="discord").start()

    def webhook(self):
        url = (read(self.cfg["webhook_file"]) or "").strip()
        return url if url.startswith("https://discord.com/api/webhooks/") else None

    def emit(self, level, rule, title, details, container=None, key=None, freeze=False):
        uuid = container.uuid if container else "-"
        if uuid in self.allow or f"{uuid}:{rule}" in self.allow:
            return
        ck = f"{uuid}|{rule}|{key or title}"
        cool = self.state.get("cooldown", {})
        span = self.cfg["cooldown_critique_s"] if level == "critique" else self.cfg["cooldown_alert_s"]
        if level == "info":
            span = 7 * 86400
        if now() - cool.get(ck, 0) < span:
            return
        cool[ck] = now()
        self.state.set("cooldown", cool)
        ev = {"ts": dt.datetime.now().isoformat(timespec="seconds"), "level": level, "rule": rule,
              "title": title, "details": details, "server": uuid,
              "image": container.image if container else None}
        with open(self.jsonl, "a") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        getattr(log, "warning" if level != "info" else "info")("[%s] %s %s : %s", level, uuid[:8], title, details)
        want = self.cfg["freeze_on_critique"] or (freeze and self.cfg.get("auto_freeze"))
        if level == "critique" and container and container.cgroup and want and not container.frozen:
            try:
                with open(container.cgroup + "/cgroup.freeze", "w") as f:
                    f.write("1")
                container.frozen = True
                ev["details"] += "\n**Conteneur gelé** (cgroup.freeze). Dégel : `sudo ptero-guard unfreeze %s`" % uuid
            except OSError as e:
                log.error("gel impossible %s : %s", uuid, e)
        if level != "info":
            with self.cv:
                self.queue.append(ev)
                self.cv.notify()

    def _embed(self, ev):
        fields = []
        if ev["server"] != "-":
            short = ev['server'][:8]
            link = f"[{short}]({self.cfg['panel_url'].rstrip('/')}/server/{short})" if self.cfg.get("panel_url") else short
            fields.append({"name": "Serveur", "value": f"{link} `{ev['server']}`", "inline": False})
            if ev.get("image"):
                fields.append({"name": "Image", "value": f"`{ev['image'].split('/')[-1]}`", "inline": True})
        return {"title": f"{ev['level'].upper()} : {ev['title']}"[:256], "description": ev["details"][:3900],
                "color": COLORS[ev["level"]], "fields": fields,
                "footer": {"text": f"ptero-guard {VERSION} · règle {ev['rule']}"}, "timestamp":
                    dt.datetime.now(dt.timezone.utc).isoformat()}

    def outbox(self, payload):
        """File lue par un bot Discord externe : un message Discord prêt à envoyer par ligne."""
        path = os.path.join(self.cfg["log_dir"], "discord.jsonl")
        try:
            if os.path.getsize(path) > 2 * 1024 * 1024:
                os.replace(path, path + ".1")
        except OSError:
            pass
        msg = {"ts": dt.datetime.now().isoformat(timespec="seconds"), "content": payload.get("content"),
               "embeds": payload.get("embeds", []), "servers": payload.get("servers", [])}
        with self.outbox_lock, open(path, "a") as f:
            f.write(json.dumps(msg, ensure_ascii=False) + "\n")
        return True

    def post(self, payload):
        ok = self.outbox(payload)
        url = self.webhook()
        if not url:
            return ok
        payload = {k: v for k, v in payload.items() if k != "servers"}
        body = json.dumps(payload).encode()
        for attempt in range(4):
            req = urllib.request.Request(url, body, {"Content-Type": "application/json",
                                                      "User-Agent": "ptero-guard/" + VERSION})
            try:
                urllib.request.urlopen(req, timeout=15).read()
                return True
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    time.sleep(float(e.headers.get("Retry-After", "2")) + 0.5)
                    continue
                log.error("webhook HTTP %s", e.code)
                return False
            except OSError as e:
                log.error("webhook : %s", e)
                time.sleep(5 * (attempt + 1))
        return False

    def _sender(self):
        while True:
            with self.cv:
                while not self.queue:
                    self.cv.wait()
                batch = [self.queue.popleft() for _ in range(min(10, len(self.queue)))]
            content = "@here" if any(e["level"] == "critique" for e in batch) else None
            payload = {"username": "Ptero Guard", "embeds": [self._embed(e) for e in batch],
                       "allowed_mentions": {"parse": ["everyone"]}}
            if content:
                payload["content"] = content
            # Serveurs concernés par une alerte critique : le bot propose de les geler
            payload["servers"] = sorted({e["server"] for e in batch if e["level"] == "critique" and e["server"] != "-"})
            self.post(payload)
            time.sleep(2)

    def digest(self, hours=24):
        since = now() - hours * 3600
        evs = []
        for line in (read(self.jsonl) or "").splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if dt.datetime.fromisoformat(e["ts"]).timestamp() >= since:
                evs.append(e)
        counts = collections.Counter(e["level"] for e in evs)
        infos = [e for e in evs if e["level"] == "info"]
        lines = [f"Dernières {hours} h : **{counts['critique']}** critique, **{counts['alerte']}** alerte, "
                 f"**{counts['info']}** info. Serveurs surveillés : {len(self.inv.all())}."]
        for e in infos[:25]:
            lines.append(f"- `{e['server'][:8]}` {e['title']} : {e['details'].splitlines()[0][:160]}")
        if len(infos) > 25:
            lines.append(f"- … et {len(infos) - 25} autres (voir {self.jsonl})")
        return {"username": "Ptero Guard", "embeds": [{
            "title": "Résumé quotidien", "description": "\n".join(lines)[:3900], "color": COLORS["info"],
            "footer": {"text": f"ptero-guard {VERSION}"}}]}


# --------------------------------------------------------------------------
# Détecteurs
# --------------------------------------------------------------------------
class Detectors:
    def __init__(self, cfg, state, inv, alerter):
        self.cfg, self.state, self.inv, self.al = cfg, state, inv, alerter
        self.th = cfg["thresholds"]
        self.flows = collections.defaultdict(dict)       # uuid -> {(dst,dport,proto): ts}
        self.traffic = {}                                 # uuid -> (ts, txb, txp)
        self.traffic_hot = collections.defaultdict(float)  # uuid -> début du dépassement
        self.tx_hist = collections.defaultdict(collections.deque)  # uuid -> [(ts, txb)] sur 1 h
        self.web = {}                                     # uuid -> [description des services HTTP]
        self.cpu = {}                                     # uuid -> (ts, usage_usec)
        self.cpu_hot = {}
        self.pcpu = {}                                    # pid -> (ts, ticks, starttime)
        self.pcpu_hot = {}
        self.clk = os.sysconf("SC_CLK_TCK")
        self.pool_ips = set(self.state.get("pool_ips", []))
        self.tor_ips = set(self.state.get("tor_ips", []))
        self.allow_dst = set(cfg["allow"]["dst_ips"])
        self.seen_exe = {k: set(v) for k, v in self.state.get("seen_exe", {}).items()}
        self.private = [ipaddress.ip_network(n) for n in
                        ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]

    # -- renseignement : IP de pools et de relais Tor ---------------------------
    def refresh_intel(self):
        ips = set()
        for d in POOL_DOMAINS:
            try:
                for info in socket.getaddrinfo(d, None, socket.AF_INET):
                    ips.add(info[4][0])
            except OSError:
                pass
        if ips:
            self.pool_ips = ips
            self.state.set("pool_ips", sorted(ips))
        try:
            req = urllib.request.Request("https://onionoo.torproject.org/summary?running=true&type=relay",
                                         headers={"User-Agent": "ptero-guard/" + VERSION})
            data = json.loads(urllib.request.urlopen(req, timeout=60).read())
            tor = set()
            for r in data.get("relays", []):
                for a in r.get("a", []):
                    if "." in a:
                        tor.add(a)
            if tor:
                self.tor_ips = tor
                self.state.set("tor_ips", sorted(tor))
        except (OSError, ValueError) as e:
            log.warning("liste Tor indisponible : %s", e)
        log.info("renseignement : %d IP de pools, %d relais Tor", len(self.pool_ips), len(self.tor_ips))

    # -- processus ---------------------------------------------------------------
    def check_processes(self):
        seen_changed = False
        t = now()
        alive = set()
        for c in self.inv.all():
            known = self.seen_exe.setdefault(c.uuid, set())
            first_pass = not known
            for pid in cgroup_pids(c.cgroup):
                try:
                    exe = os.readlink(f"/proc/{pid}/exe")
                except OSError:
                    exe = ""
                raw = read(f"/proc/{pid}/cmdline", "rb") or b""
                cmd = raw.replace(b"\0", b" ").decode("utf-8", "replace").strip()
                comm = (read(f"/proc/{pid}/comm") or "").strip()
                blob = f"{comm} {os.path.basename(exe)} {cmd}"
                detail = f"PID {pid} `{comm}`\nexe : `{exe}`\ncommande : `{cmd[:600]}`"
                key = f"{comm}|{exe}"
                alive.add(pid)
                self._proc_cpu(c, pid, t, exe, comm, detail, key)
                if KTHREAD_NAME.search(comm) or (raw[:1] == b"[" and KTHREAD_NAME.search(cmd)):
                    self.al.emit("critique", "processus_camoufle", "Processus déguisé en thread du noyau",
                                 detail, c, key, freeze=True)
                if MINER_PROC.search(blob):
                    self.al.emit("critique", "minage", "Processus de minage de cryptomonnaie", detail, c, key, freeze=True)
                elif ATTACK_PROC.search(blob):
                    self.al.emit("critique", "outil_attaque", "Outil d'attaque ou de scan réseau", detail, c, key)
                elif REVSHELL.search(raw.replace(b"\0", b" ")):
                    self.al.emit("critique", "reverse_shell", "Reverse shell", detail, c, key)
                elif TORRENT_PROC.search(blob):
                    self.al.emit("critique", "torrent", "Client BitTorrent (partage de fichiers)", detail, c, key, freeze=True)
                elif TUNNEL_PROC.search(f"{comm} {os.path.basename(exe)}"):
                    self.al.emit("alerte", "tunnel_proxy", "Tunnel, proxy ou Tor", detail, c, key)
                if exe.endswith(" (deleted)") or exe.startswith("/memfd:") or exe.startswith(SUSPICIOUS_EXE_DIRS):
                    self.al.emit("alerte", "exe_suspect", "Exécutable supprimé, en mémoire ou dans /tmp", detail, c, key)
                if exe and exe not in known:
                    known.add(exe)
                    seen_changed = True
                    if not first_pass:
                        self.al.emit("info", "nouvel_exe", "Nouvel exécutable lancé", detail, c, exe)
        if seen_changed:
            self.state.set("seen_exe", {k: sorted(v) for k, v in self.seen_exe.items()})
        for pid in list(self.pcpu):
            if pid not in alive:
                del self.pcpu[pid]
                self.pcpu_hot.pop(pid, None)

    def _proc_cpu(self, c, pid, t, exe, comm, detail, key):
        """Processus qui monopolise un cœur longtemps alors que son binaire vient du volume
        du client sur une image runtime (Node, Python, Java...) : mineur renommé typique."""
        stat = read(f"/proc/{pid}/stat") or ""
        try:
            f = stat.rsplit(")", 1)[1].split()
            ticks, start = int(f[11]) + int(f[12]), f[19]
        except (IndexError, ValueError):
            return
        prev = self.pcpu.get(pid)
        self.pcpu[pid] = (t, ticks, start)
        if not prev or prev[2] != start or t - prev[0] <= 0:
            return
        pct = (ticks - prev[1]) / self.clk / (t - prev[0]) * 100
        if pct < self.th["proc_cpu_pct"]:
            self.pcpu_hot.pop(pid, None)
            return
        since = self.pcpu_hot.setdefault(pid, t)
        mins = (t - since) / 60
        if mins < self.th["proc_cpu_minutes"]:
            return
        from_volume = exe.startswith("/home/container/") or exe.startswith(SUSPICIOUS_EXE_DIRS) or exe.endswith(" (deleted)")
        if from_volume and RUNTIME_IMAGE.search(c.image):
            self.al.emit("alerte", "minage_deguise", "Binaire inconnu qui monopolise le CPU (mineur renommé ?)",
                         f"{pct:.0f} % d'un cœur depuis {mins:.0f} min\n{detail}", c, key)

    # -- réseau (conntrack) --------------------------------------------------------
    def is_public(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not any(a in n for n in self.private) and not a.is_multicast

    def check_network(self):
        raw = read("/proc/net/nf_conntrack") or ""
        t = now()
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) < 6 or parts[0] != "ipv4":
                continue
            proto = parts[2]
            kv = {}
            for p in parts:
                if "=" in p:
                    k, v = p.split("=", 1)
                    kv.setdefault(k, v)
            src, dst = kv.get("src"), kv.get("dst")
            c = self.inv.ip(src)
            if not c or not dst or not self.is_public(dst) or dst in self.allow_dst:
                continue
            try:
                dport = int(kv.get("dport", 0))
            except ValueError:
                dport = 0
            self.flows[c.uuid][(dst, dport, proto)] = t
            detail = f"{proto.upper()} {src} vers **{dst}:{dport}**"
            if dst in self.pool_ips:
                self.al.emit("critique", "minage", "Connexion à un pool de minage connu", detail, c, dst)
            elif dport in MINING_PORTS and proto == "tcp":
                self.al.emit("alerte", "port_minage", "Connexion vers un port typique de pool de minage", detail, c, f"{dst}:{dport}")
            if dst in self.tor_ips:
                self.al.emit("alerte", "tor", "Connexion au réseau Tor", detail, c, dst)
            if dport in TORRENT_PORTS:
                self.al.emit("alerte", "torrent_reseau", "Connexion vers un port BitTorrent (pair ou tracker)",
                             detail, c, f"torrent{dport}")
            if dport == 25 and proto == "tcp":
                self.al.emit("alerte", "smtp_sortant", "Envoi SMTP direct (port 25) : spam possible", detail, c, dst)
        # fenêtres glissantes 5 min
        for uuid in [u for u in self.tx_hist if u not in self.inv.by_uuid]:
            self.tx_hist.pop(uuid, None)
            self.web.pop(uuid, None)
        for uuid, flows in list(self.flows.items()):
            for k, ts in list(flows.items()):
                if t - ts > 300:
                    del flows[k]
            c = self.inv.by_uuid.get(uuid)
            if not c:
                self.flows.pop(uuid, None)
                continue
            dsts = {k[0] for k in flows}
            if len(dsts) > self.th["distinct_dst_5min"]:
                self.al.emit("alerte", "fanout", "Contacte un nombre anormal d'IP",
                             f"{len(dsts)} IP distinctes en 5 min (seuil {self.th['distinct_dst_5min']})", c, "fanout")
            sens = {k[0] for k in flows if k[1] in SENSITIVE_PORTS}
            if len(sens) > self.th["sensitive_dst_5min"]:
                ports = collections.Counter(k[1] for k in flows if k[1] in SENSITIVE_PORTS).most_common(5)
                self.al.emit("critique", "scan_bruteforce", "Scan ou brute force sortant (SSH, RDP, bases...)",
                             f"{len(sens)} IP distinctes en 5 min sur ports sensibles : {ports}", c, "sens")
            per_port = collections.defaultdict(set)
            for (d, p, _), _ts in flows.items():
                per_port[p].add(d)
            for p, ds in per_port.items():
                if len(ds) > self.th["same_port_dst_5min"] and p not in (443, 80):
                    self.al.emit("alerte", "scan_port", f"Balayage du port {p}",
                                 f"{len(ds)} IP distinctes contactées sur le port {p} en 5 min", c, f"port{p}")

    # -- débit sortant -------------------------------------------------------------
    def check_traffic(self):
        t = now()
        for c in self.inv.all():
            raw = read(f"/proc/{c.pid}/net/dev") if c.pid else None
            if not raw:
                continue
            txb = txp = 0
            for line in raw.splitlines()[2:]:
                name, _, rest = line.partition(":")
                if name.strip() == "lo":
                    continue
                f = rest.split()
                if len(f) >= 10:
                    txb += int(f[8])
                    txp += int(f[9])
            prev = self.traffic.get(c.uuid)
            self.traffic[c.uuid] = (t, txb, txp)
            hist = self.tx_hist[c.uuid]
            if hist and txb < hist[-1][1]:
                hist.clear()                              # compteurs remis à zéro (redémarrage)
            hist.append((t, txb))
            while hist and t - hist[0][0] > 3600:
                hist.popleft()
            if t - hist[0][0] >= 3000:
                gb = (txb - hist[0][1]) / 1e9
                if gb > self.th["tx_gb_hour"]:
                    web = self.web.get(c.uuid) or ["aucun service HTTP détecté"]
                    self.al.emit("alerte", "diffusion_volumineuse", "Gros volume de données envoyé (diffusion de fichiers ?)",
                                 f"{gb:.1f} Go envoyés en {int((t - hist[0][0]) / 60)} min "
                                 f"(seuil {self.th['tx_gb_hour']} Go/h)\nServices HTTP : " + " ; ".join(web)[:700],
                                 c, "volume")
            if not prev or t - prev[0] <= 0:
                continue
            dt_s = t - prev[0]
            mbps = (txb - prev[1]) * 8 / dt_s / 1e6
            pps = (txp - prev[2]) / dt_s
            if mbps > self.th["tx_mbps"] or pps > self.th["tx_pps"]:
                start = self.traffic_hot.setdefault(c.uuid, t)
                if t - start >= self.th["traffic_seconds"]:
                    flows = self.flows.get(c.uuid, {})
                    top = collections.Counter(k[0] for k in flows).most_common(5)
                    self.al.emit("critique", "flood_sortant", "Débit sortant anormal (DDoS possible)",
                                 f"{mbps:.0f} Mbit/s, {pps:.0f} paquets/s depuis {int(t - start)} s\n"
                                 f"Destinations principales : {top}", c, "flood")
            else:
                self.traffic_hot.pop(c.uuid, None)

    # -- services HTTP exposés (sites de partage de fichiers) --------------------------
    @staticmethod
    def _listening(pid):
        ports = set()
        for f in ("tcp", "tcp6"):
            for line in (read(f"/proc/{pid}/net/{f}") or "").splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4 or parts[3] != "0A":
                    continue
                addr, _, port = parts[1].rpartition(":")
                if addr in ("0100007F", "00000000000000000000000001000000"):
                    continue                              # 127.0.0.1 / ::1
                ports.add(int(port, 16))
        return sorted(ports)

    @staticmethod
    def _http_probe(ip, port):
        try:
            with socket.create_connection((ip, port), timeout=3) as s:
                s.settimeout(3)
                s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}:{port}\r\nUser-Agent: ptero-guard\r\n\r\n".encode())
                buf = b""
                while len(buf) < 65536:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    buf += chunk
        except (OSError, ValueError):
            return None
        return buf if buf.startswith(b"HTTP/") else None

    def check_web(self):
        for c in self.inv.all():
            if not c.pid or not c.ip or c.frozen:
                continue
            found = []
            for port in self._listening(c.pid)[:8]:
                resp = self._http_probe(c.ip, port)
                if resp is None:
                    continue
                low = resp.lower()
                title = re.search(rb"<title[^>]*>([^<]{0,80})", resp, re.I)
                desc = f"port {port}" + (f" « {title.group(1).decode('utf-8', 'replace').strip()} »" if title else "")
                found.append(desc)
                kind = None
                if re.search(rb"<title>\s*(index of /|directory listing for /)|<h1>\s*(index of /|directory listing for /)", low):
                    kind = "Listing de dossier public (serveur de fichiers ouvert)"
                elif FILEHOST_RX.search(low):
                    kind = "Application d'hébergement ou de partage de fichiers"
                if kind:
                    links = re.findall(rb'href="([^"?#][^"]{0,120})"', resp)[:15]
                    names = ", ".join(l.decode("utf-8", "replace") for l in links if not l.startswith(b"http"))
                    self.al.emit("alerte", "partage_fichiers", kind,
                                 f"http://{c.ip}:{port}/ {desc}\nEntrées : `{names[:600] or '?'}`", c, f"web{port}")
            self.web[c.uuid] = found

    # -- CPU -------------------------------------------------------------------------
    def check_cpu(self):
        t = now()
        for c in self.inv.all():
            raw = read(c.cgroup + "/cpu.stat") or ""
            m = re.search(r"usage_usec (\d+)", raw)
            if not m:
                continue
            usage = int(m.group(1))
            prev = self.cpu.get(c.uuid)
            self.cpu[c.uuid] = (t, usage)
            if not prev:
                continue
            pct = (usage - prev[1]) / 1e6 / (t - prev[0]) / c.cpu_limit * 100
            if pct >= self.th["cpu_pct"]:
                start = self.cpu_hot.setdefault(c.uuid, t)
                mins = (t - start) / 60
                if mins >= self.th["cpu_minutes"]:
                    self.al.emit("alerte", "cpu_soutenu", "CPU saturé en continu (minage possible)",
                                 f"{pct:.0f} % de la limite ({c.cpu_limit:g} cœurs) depuis {mins:.0f} min", c, "cpu")
            else:
                self.cpu_hot.pop(c.uuid, None)


# --------------------------------------------------------------------------
# Analyse des fichiers
# --------------------------------------------------------------------------
class FileScanner:
    def __init__(self, cfg, state, inv, alerter):
        self.cfg, self.state, self.inv, self.al = cfg, state, inv, alerter
        self.max = cfg["thresholds"]["file_max_mb"] * 1024 * 1024
        self.clam_max = cfg["thresholds"].get("clamav_max_mb", 100) * 1024 * 1024

    def clamd_scan(self, addr, path):
        try:
            with socket.create_connection(addr, timeout=120) as s, open(path, "rb") as f:
                s.sendall(b"zINSTREAM\0")
                while chunk := f.read(1 << 16):
                    s.sendall(struct.pack(">I", len(chunk)) + chunk)
                s.sendall(struct.pack(">I", 0))
                res = b""
                while not res.endswith(b"\0"):
                    part = s.recv(4096)
                    if not part:
                        break
                    res += part
            res = res.rstrip(b"\0").decode(errors="replace")
            return res.split(":", 1)[1].strip().removesuffix(" FOUND") if res.endswith("FOUND") else None
        except OSError as e:
            log.debug("clamd %s : %s", path, e)
            return None

    def scan(self, full=False):
        since = 0 if full else self.state.get("files_last_scan", 0)
        self.full = since == 0
        started = now()
        root = self.cfg["volumes_dir"]
        addr = None
        try:
            addr = clamd_address(self.cfg)
        except (OSError, ValueError, KeyError):
            pass
        containers = {c.uuid: c for c in self.inv.all()}
        stats = collections.Counter()
        for uuid in sorted(os.listdir(root)):
            self._scan_volume(root, uuid, containers, since, addr, stats)
        self.state.set("files_last_scan", started)
        log.info("analyse fichiers (%s) : %s en %.0f s", "complète" if full else "incrémentale",
                 dict(stats), now() - started)
        return stats

    def scan_started(self, uuids):
        """Analyse complète des volumes des serveurs qui viennent de démarrer."""
        root = self.cfg["volumes_dir"]
        try:
            addr = clamd_address(self.cfg)
        except (OSError, ValueError, KeyError):
            addr = None
        containers = {c.uuid: c for c in self.inv.all()}
        self.full = False
        for uuid in sorted(uuids):
            t0, stats = now(), collections.Counter()
            self._scan_volume(root, uuid, containers, 0, addr, stats)
            log.info("analyse au démarrage de %s : %s en %.0f s", uuid, dict(stats), now() - t0)

    def _scan_volume(self, root, uuid, containers, since, addr, stats):
            vol = os.path.join(root, uuid)
            if uuid.startswith(".") or "/" in uuid or not os.path.isdir(vol):
                return
            c = containers.get(uuid) or self._ghost(uuid)
            for dirpath, dirs, files in os.walk(vol):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for name in files:
                    path = os.path.join(dirpath, name)
                    try:
                        st = os.lstat(path)
                    except OSError:
                        continue
                    if not os.path.isfile(path) or os.path.islink(path) or max(st.st_mtime, st.st_ctime) < since:
                        continue
                    stats["fichiers"] += 1
                    self._check_file(c, vol, path, name, st, addr, stats)

    @staticmethod
    def _ghost(uuid):
        c = Container()
        c.uuid, c.image, c.cgroup, c.frozen, c.id = uuid, "(arrêté)", "", True, ""
        return c

    def _check_file(self, c, vol, path, name, st, addr, stats):
        rel = path[len(vol):]
        ext = os.path.splitext(name)[1].lower()
        size = st.st_size
        in_deps = any(p in path for p in CLAM_SKIP_PARTS)
        in_sys = rel.startswith(SYSTEM_PREFIXES)
        if PIRACY_NAMES.search(name) and not in_deps and not in_sys:
            self.al.emit("info", "piratage", "Fichier au nom évoquant du piratage", f"`{rel}` ({size // 1024} Ko)", c, rel)
        self._check_name(c, rel, name, f"`{rel}` ({size // 1024} Ko)", rel)
        if name.endswith(".torrent"):
            self.al.emit("alerte", "torrent", "Fichier .torrent sur un serveur", f"`{rel}`", c, rel)
        if ext in MEDIA_EXT and size > self.cfg["thresholds"]["media_warez_mb"] * 1024 * 1024:
            self.al.emit("alerte", "warez", "Gros fichier vidéo ou image disque (stockage de warez ?)",
                         f"`{rel}` ({size // 1048576} Mo)", c, rel)
        if size == 0 or size > self.clam_max:
            return
        try:
            with open(path, "rb") as f:
                head = f.read(min(size, 4 * 1024 * 1024))
        except OSError:
            return
        is_elf = head[:4] == b"\x7fELF"
        clam_ok = addr and not in_deps and not (in_sys and self.full)
        if size > self.max:
            # Trop gros pour les signatures : ClamAV seul, sur les types exécutables et archives
            if clam_ok and (is_elf or (ext and ext in CLAM_BIG_EXT)):
                self._clam(c, rel, path, addr, stats)
            return
        if ext not in SCAN_EXT and not is_elf and ext and ext not in COMBO_EXT:
            return
        stats["analysés"] += 1
        binary = is_elf or ext in {".exe", ".dll", ".so", ".bin"}
        if ext not in ARCHIVE_EXT and not binary and size > len(head):
            try:
                with open(path, "rb") as f:
                    head = f.read(self.max)       # fichier texte entier (une charge cachée en fin de fichier)
            except OSError:
                return
        if ext not in ARCHIVE_EXT:
            self._match_sigs(c, rel, rel, head, ext, binary, in_deps or in_sys)
            if ext in COMBO_EXT and not binary and not in_deps and not in_sys and b"@" in head:
                self._check_combo(c, rel, head)
        if ext == ".jar":
            self._check_jar(c, rel, path)
        elif ext in ARCHIVE_EXT:
            self._check_archive(c, rel, path, in_sys)
        if is_elf and not name.endswith(".so") and ".so." not in name and not in_deps and not in_sys:
            self.al.emit("info", "binaire_elf", "Binaire ELF dans le volume", f"`{rel}` ({size // 1024} Ko)", c, rel)
        # Fichiers système : ClamAV seulement sur les fichiers nouveaux (pas au premier passage complet)
        if clam_ok and (is_elf or ext in CLAM_EXT):
            self._clam(c, rel, path, addr, stats)

    def _check_name(self, c, rel, name, detail, key):
        """Noms de fichiers évoquant des contenus illégaux (le chemin complet compte : dossiers inclus)."""
        if CSAM_NAMES_STRONG.search(rel):
            self.al.emit("critique", "pedocriminalite", "Nom de fichier associé à des contenus pédocriminels",
                         detail, c, key + "|pedo", freeze=True)
        elif CSAM_NAMES.search(rel):
            self.al.emit("critique", "pedocriminalite", "Nom de fichier évoquant des contenus pédocriminels",
                         detail, c, key + "|pedo")
        if FRAUD_NAMES.search(name) and not any(p in rel for p in CLAM_SKIP_PARTS):
            self.al.emit("alerte", "carding", "Nom de fichier évoquant une fuite d'identifiants ou de cartes",
                         detail, c, key + "|fraud")

    def _check_combo(self, c, rel, data):
        n = 0
        for _ in COMBO_LINE.finditer(data):
            n += 1
            if n >= self.cfg["thresholds"]["combo_lines"]:
                self.al.emit("alerte", "fuite_identifiants", "Liste d'identifiants volés (email:mot de passe)",
                             f"`{rel}` : au moins {n} lignes email:mot de passe", c, rel + "|combo")
                return

    def _clam(self, c, rel, path, addr, stats):
        stats["clamav"] += 1
        sig = self.clamd_scan(addr, path)
        if sig:
            # Les PUA (outils potentiellement indésirables) ne justifient pas un gel automatique
            self.al.emit("critique", "clamav", f"Logiciel malveillant détecté ({sig})", f"`{rel}`", c, rel,
                         freeze="PUA" not in sig.upper())

    def _match_sigs(self, c, rel, label, data, ext, binary, lenient):
        low = data.lower()
        for rule, level, triggers, rx, desc in FILE_SIGS:
            if binary and rule not in BINARY_RULES:
                continue
            if rule in SIG_ONLY_EXT and ext not in SIG_ONLY_EXT[rule]:
                continue
            if lenient and rule in ("payload_distant", "outil_ddos", "phishing", "reverse_shell", "selfbot",
                                    "torrent_lib", "pedocriminalite", "carding"):
                continue  # trop de faux positifs dans les dépendances (docs, tests)
            if not any(t in low for t in triggers):
                continue
            m = rx.search(low)
            if not m:
                continue
            ctx = data[max(0, m.start() - 60):m.end() + 60].decode("utf-8", "replace").replace("`", "'")
            self.al.emit(level, rule, desc[0].upper() + desc[1:], f"`{label}`\n```\n{ctx[:400]}\n```", c, rel + "|" + rule)

    def _archive_entries(self, path):
        """(nom, taille, lecteur) des entrées d'une archive zip ou tar ; rien pour rar/7z (ClamAV seul)."""
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    if not info.is_dir():
                        yield info.filename, info.file_size, lambda i=info: z.read(i)
            return
        try:
            t = tarfile.open(path, "r:*")
        except (tarfile.TarError, OSError, EOFError, ValueError):
            return
        with t:
            for m in t:
                if m.isfile():
                    yield m.name, m.size, lambda m=m: t.extractfile(m).read()

    def _check_archive(self, c, rel, path, in_sys):
        """Archive envoyée sur le serveur : on regarde dedans sans l'extraire sur disque."""
        budget = 64 * 1024 * 1024
        try:
            for n, size, reader in self._archive_entries(path):
                label = f"{rel} > {n}"
                if JAR_IOCS.search(n.encode(errors="replace")):
                    self.al.emit("critique", "jar_malware", "Classe malveillante connue dans une archive",
                                 f"`{label}`", c, rel, freeze=True)
                    return
                base = n.rsplit("/", 1)[-1]
                self._check_name(c, rel, n, f"`{label}`", rel + ">" + n)
                if base.endswith(".torrent"):
                    self.al.emit("alerte", "torrent", "Fichier .torrent dans une archive", f"`{label}`", c, rel)
                e = os.path.splitext(base)[1].lower()
                if e not in SCAN_EXT or e in ARCHIVE_EXT or e in {".exe", ".dll", ".so", ".bin"}:
                    continue
                if size > 2 * 1024 * 1024 or budget <= 0:
                    continue
                budget -= size
                data = reader()
                lenient = in_sys or any(p.strip("/") in n.split("/") for p in CLAM_SKIP_PARTS)
                self._match_sigs(c, rel, label, data, e, False, lenient)
        except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, RuntimeError, ValueError,
                NotImplementedError, zlib.error, AttributeError):
            pass

    def _check_jar(self, c, rel, path):
        try:
            with zipfile.ZipFile(path) as z:
                budget = 64 * 1024 * 1024
                for info in z.infolist():
                    n = info.filename
                    if JAR_IOCS.search(n.encode()):
                        self.al.emit("critique", "jar_malware", "Classe malveillante connue dans un .jar",
                                     f"`{rel}` contient `{n}`", c, rel, freeze=True)
                        return
                    if not n.endswith(".class") or info.file_size > 2 * 1024 * 1024 or budget <= 0:
                        continue
                    budget -= info.file_size
                    data = z.read(info)
                    m = JAR_IOCS.search(data)
                    if m:
                        self.al.emit("critique", "jar_malware", "Indicateur de malware dans un .jar (fractureiser...)",
                                     f"`{rel}` : `{n}` contient `{m.group(0).decode(errors='replace')}`", c, rel, freeze=True)
                        return
        except (zipfile.BadZipFile, OSError, RuntimeError, ValueError, NotImplementedError):
            pass


# --------------------------------------------------------------------------
# Logs Wings et panel
# --------------------------------------------------------------------------
class LogWatcher:
    WINGS_SFTP = re.compile(r"sftp: failed to accept inbound connection.*?ip=([0-9a-fA-F.:]+):\d+")
    NGINX = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+) [^"]*" (\d{3}) ')
    SCANNER_PATHS = re.compile(r"/\.env|/\.git|/wp-(login|admin)|/phpmyadmin|/vendor/phpunit|/cgi-bin|\.php$", re.I)

    def __init__(self, cfg, state, alerter):
        self.cfg, self.state, self.al = cfg, state, alerter
        self.sftp = collections.defaultdict(collections.deque)
        self.panel = collections.defaultdict(collections.deque)

    def _tail(self, path):
        offs = self.state.get("log_offsets", {})
        try:
            st = os.stat(path)
        except OSError:
            return []
        ino, pos = offs.get(path, [st.st_ino, st.st_size])  # premier passage : on part de la fin
        if ino != st.st_ino or pos > st.st_size:
            pos = 0
        lines = []
        with open(path, "rb") as f:
            f.seek(pos)
            data = f.read(32 * 1024 * 1024)
            cut = data.rfind(b"\n") + 1
            lines = data[:cut].decode("utf-8", "replace").splitlines()
            pos += cut
        offs[path] = [st.st_ino, pos]
        self.state.set("log_offsets", offs)
        return lines

    def check(self):
        t = now()
        for line in self._tail(self.cfg["wings_log"]):
            m = self.WINGS_SFTP.search(line)
            if m:
                self.sftp[m.group(1)].append(t)
        for ip, dq in list(self.sftp.items()):
            while dq and t - dq[0] > 3600:
                dq.popleft()
            if not dq:
                del self.sftp[ip]
            elif len(dq) > self.cfg["thresholds"]["sftp_scan_per_hour"]:
                self.al.emit("alerte", "sftp_scan", "Scan ou brute force SFTP (Wings, port 2022)",
                             f"IP **{ip}** : {len(dq)} connexions refusées en 1 h", None, ip)
        for line in self._tail(self.cfg["panel_access_log"]):
            m = self.NGINX.match(line)
            if not m:
                continue
            ip, method, uri, status = m.group(1), m.group(2), m.group(3), int(m.group(4))
            if status in (401, 403, 419, 422, 429) or (status == 404 and self.SCANNER_PATHS.search(uri)):
                self.panel[ip].append((t, f"{method} {uri} {status}"))
        for ip, dq in list(self.panel.items()):
            while dq and t - dq[0][0] > 600:
                dq.popleft()
            if not dq:
                del self.panel[ip]
            elif len(dq) > self.cfg["thresholds"]["panel_4xx_10min"]:
                sample = "\n".join(x[1] for x in list(dq)[-6:])
                self.al.emit("alerte", "panel_abus", "Brute force ou scan du panel",
                             f"IP **{ip}** : {len(dq)} requêtes refusées en 10 min\n```\n{sample}\n```", None, ip)


# --------------------------------------------------------------------------
# Boucle principale
# --------------------------------------------------------------------------
class Guard:
    def __init__(self, cfg):
        self.cfg = cfg
        os.makedirs(cfg["state_dir"], exist_ok=True)
        self.state = State(os.path.join(cfg["state_dir"], "state.json"))
        self.inv = Inventory(cfg)
        self.inv.refresh()
        self.al = Alerter(cfg, self.state, self.inv)
        self.det = Detectors(cfg, self.state, self.inv, self.al)
        self.files = FileScanner(cfg, self.state, self.inv, self.al)
        self.logs = LogWatcher(cfg, self.state, self.al)
        self.stop = threading.Event()
        self.busy = {}       # job -> début de l'exécution en cours
        self.last_ok = {}    # job -> fin de la dernière exécution
        self.intervals = {}
        self.started_at = now()

    def _loop(self, name, interval, fn):
        self.intervals[name] = interval
        while not self.stop.is_set():
            t0 = now()
            self.busy[name] = t0
            try:
                fn()
            except Exception:
                log.exception("détecteur %s", name)
            self.busy.pop(name, None)
            self.last_ok[name] = now()
            self.stop.wait(max(1, interval - (now() - t0)))

    def _watchdog(self):
        """Détecteur bloqué (alerte interne) + fichier heartbeat lu par le bot Discord externe,
        qui prévient si ptero-guard ne donne plus signe de vie."""
        t = now()
        stuck = []
        for name, t0 in list(self.busy.items()):
            iv = self.intervals.get(name, 60)
            limit = 3 * 3600 if name in ("fichiers", "demarrage") else max(600, 5 * iv)
            if t - t0 > limit:
                stuck.append(f"{name} (depuis {(t - t0) / 60:.0f} min)")
        if stuck:
            self.al.emit("alerte", "detecteur_bloque", "Un détecteur de ptero-guard est bloqué",
                         "Détecteurs : " + ", ".join(stuck) + "\nVoir `journalctl -u ptero-guard`.", None, ",".join(stuck))
        hb = {"ts": t, "version": VERSION, "started": self.started_at, "servers": len(self.inv.all()),
              "jobs": {k: round(v) for k, v in self.last_ok.items()}, "stuck": stuck}
        path = os.path.join(self.cfg.get("log_dir", "/var/log/ptero-guard"), "heartbeat.json")
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(hb, f)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)

    def run(self):
        iv = self.cfg["intervals"]
        jobs = [("inventaire", 5, self.inv.refresh),
                ("demarrage", 5, lambda: self.files.scan_started(self.inv.pop_started())),
                ("processus", iv["process"], self.det.check_processes),
                ("reseau", iv["network"], self.det.check_network),
                ("debit", iv["traffic"], self.det.check_traffic),
                ("cpu", iv["cpu"], self.det.check_cpu),
                ("web", iv.get("web", 900), self.det.check_web),
                ("logs", iv["logs"], self.logs.check),
                ("renseignement", iv["intel"], self.det.refresh_intel),
                ("fichiers", iv["files"], lambda: self.files.scan(full=not self.state.get("files_last_scan"))),
                ("etat", 60, self.state.save),
                ("vie", 60, self._watchdog),
                ("resume", 60, self._digest_tick)]
        for name, interval, fn in jobs:
            threading.Thread(target=self._loop, args=(name, interval, fn), daemon=True, name=name).start()
        log.info("ptero-guard %s démarré : %d serveurs surveillés", VERSION, len(self.inv.all()))
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop.set())
        self.stop.wait()
        self.state.save()

    def _digest_tick(self):
        today = dt.date.today().isoformat()
        if dt.datetime.now().hour == self.cfg["digest_hour"] and self.state.get("digest_day") != today:
            self.state.set("digest_day", today)
            self.al.post(self.al.digest())


def main():
    ap = argparse.ArgumentParser(prog="ptero-guard")
    ap.add_argument("--config", default="/etc/ptero-guard/config.toml")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="démon")
    sub.add_parser("status", help="état des serveurs surveillés")
    sp = sub.add_parser("scan", help="analyse des fichiers maintenant")
    sp.add_argument("--full", action="store_true")
    sub.add_parser("test-alert", help="envoie une alerte de test sur Discord")
    sub.add_parser("digest", help="envoie le résumé maintenant")
    sp = sub.add_parser("alerts", help="dernières alertes")
    sp.add_argument("-n", type=int, default=20)
    sp = sub.add_parser("unfreeze", help="dégèle un conteneur gelé")
    sp.add_argument("uuid")
    sp = sub.add_parser("freeze", help="gèle un conteneur (cgroup.freeze, réversible)")
    sp.add_argument("uuid")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(levelname)s %(threadName)s %(message)s")
    cfg = load_config(a.config)

    if a.cmd == "run":
        Guard(cfg).run()
        return
    inv = Inventory(cfg)
    inv.refresh()
    if a.cmd == "status":
        for c in sorted(inv.all(), key=lambda c: c.uuid):
            print(f"{c.uuid}  {c.ip or '-':<12} cpu≤{c.cpu_limit:g}  {'GELÉ ' if c.frozen else ''}{c.image}")
        print(f"{len(inv.all())} serveurs en marche ; alertes en file dans discord.jsonl"
              f"{' + webhook' if (read(cfg['webhook_file']) or '').strip() else ''}")
        return
    if a.cmd == "alerts":
        lines = (read(os.path.join(cfg["log_dir"], "alertes.jsonl")) or "").splitlines()[-a.n:]
        for line in lines:
            e = json.loads(line)
            print(f"{e['ts']} {e['level']:<8} {e['server'][:8]} {e['title']} | {e['details'].splitlines()[0][:120]}")
        return
    if a.cmd in ("freeze", "unfreeze"):
        c = inv.by_uuid.get(a.uuid)
        if not c:
            sys.exit("conteneur introuvable ou arrêté")
        with open(c.cgroup + "/cgroup.freeze", "w") as f:
            f.write("1" if a.cmd == "freeze" else "0")
        print("gelé" if a.cmd == "freeze" else "dégelé")
        return
    os.makedirs(cfg["state_dir"], exist_ok=True)
    state = State(os.path.join(cfg["state_dir"], "state.json"))
    al = Alerter(cfg, state, inv)
    if a.cmd == "test-alert":
        ok = al.post({"username": "Ptero Guard", "embeds": [{"title": "Test", "color": COLORS["info"],
                      "description": f"ptero-guard {VERSION} est relié à ce salon. {len(inv.all())} serveurs surveillés."}]})
        print("envoyé" if ok else "échec")
    elif a.cmd == "digest":
        print("envoyé" if al.post(al.digest()) else "échec")
    elif a.cmd == "scan":
        FileScanner(cfg, state, inv, al).scan(full=a.full)
        state.save()
        time.sleep(3)  # laisse partir la file Discord


if __name__ == "__main__":
    main()
