#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Spotify Anti-Pub - bloqueur de publicites Spotify 100% local, open source.

Principe (sans modifier aucun fichier de Spotify) :
  1. Genere une autorite de certification locale + un certificat *.spotify.com
  2. Lance un proxy HTTPS local qui inspecte les requetes CEF du client Spotify
  3. Bloque les chemins publicitaires (/ads/, /ad-logic/, /audio-ads/,
     /gabo-receiver-service/) et les domaines purement publicitaires,
     relaye tout le reste sans y toucher
  4. Configure Spotify (--proxy-server) pour router SES requetes API vers ce
     proxy uniquement. La musique passe en direct (couche native) : la
     couverture est exactement celle du projet linux 'spotify-adblock'.

Reversible en 1 commande :  python antipub.py uninstall

Usage :
  python antipub.py            # LE suffit : installe si besoin + demarre
  python antipub.py install    # installe (certs + CA + reglages Spotify)
  python antipub.py start      # demarre le proxy (demarrer.bat)
  python antipub.py stop       # arrete le proxy ET rend Spotify « direct »
  python antipub.py status     # etat de l'installation
  python antipub.py uninstall  # tout retirer, restauration incluse
"""

from __future__ import annotations

import argparse
import json
import os
import re
import select
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE = Path(__file__).resolve().parent
CERT_DIR = BASE / "certs"
CA_KEY = CERT_DIR / "ca.key.pem"
CA_CRT = CERT_DIR / "ca.cert.pem"
CA_DER = CERT_DIR / "ca.cert.cer"
LEAF_KEY = CERT_DIR / "leaf.key.pem"
LEAF_CRT = CERT_DIR / "leaf.cert.pem"
STATE_FILE = BASE / "state.json"
LOG_FILE = BASE / "antipub.log"

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 9797
PROXY_URL = f"http://{PROXY_HOST}:{PROXY_PORT}"
CA_CN = "SpotiAntiPub Local CA"
FLAG = f"--proxy-server={PROXY_URL}"

APPDATA = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
SPOTIFY_LNK = APPDATA / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Spotify.lnk"
STARTUP_LNK = APPDATA / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "Spotify Anti-Pub.lnk"
PROTOCOL_KEY = r"Software\Classes\spotify\shell\open\command"

# Domaines purement publicitaires / tracking -> CONNECT rejete (403).
# Jamais de domaine partage avec la musique ou le coeur de Spotify.
BLOCK_HOSTS = {
    "adeventtracker.spotify.com",
    "ads.spotify.com",
    "googleads.g.doubleclick.net",
    "ad.doubleclick.net",
    "static.doubleclick.net",
    "securepubads.g.doubleclick.net",
    "pagead2.googlesyndication.com",
    "adservice.google.com",
    "ads.pubmatic.com",
    "ad.crwdcntrl.net",
    "ads.rubiconproject.com",
    "spclient.wg.spotify.com.g2.pcfd.doubleclick.net",
}

BLOCKED_RESP = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW

# Capture brute des requetes (ANTIPUB_DEBUG=1) pour diagnostic differe.
DBG_REQ = Path(__file__).with_name("debug_req.bin")
DBG_RESP = Path(__file__).with_name("debug_resp.bin")

# ---------------------------------------------------------------------------
# Journalisation
# ---------------------------------------------------------------------------

_log_lock = threading.Lock()


def log(msg: str) -> None:
    line = f"{datetime.now().strftime('%H:%M:%S')} {msg}"
    with _log_lock:
        try:
            print(line, flush=True)
        except Exception:
            pass
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as fh:
                fh.write(datetime.now().isoformat(timespec="seconds") + " " + msg + "\n")
        except Exception:
            pass


def run_cmd(args, timeout=60):
    """Lance un programme en capturant la sortie, sans fenetre console."""
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=NO_WINDOW,
        timeout=timeout,
    )


def ps(script: str, timeout=60):
    return run_cmd(["powershell", "-NoProfile", "-Command", script], timeout=timeout)


# ---------------------------------------------------------------------------
# Certificats (CA locale + certificat *.spotify.com)
# ---------------------------------------------------------------------------

def ensure_certs() -> None:
    if all(p.exists() for p in (CA_KEY, CA_CRT, CA_DER, LEAF_KEY, LEAF_CRT)):
        return
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)

    def new_key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def dump_key(key, path: Path) -> None:
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    # --- Autorite de certification (10 ans) ---
    ca_key = new_key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_CN)])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # --- Certificat serveur pour Spotify (27 mois) ---
    leaf_key = new_key()
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.spotify.com")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("*.spotify.com"),
                    x509.DNSName("spotify.com"),
                    x509.DNSName("*.wg.spotify.com"),
                    x509.DNSName("spclient.wg.spotify.com"),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, key_cert_sign=False, crl_sign=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    dump_key(ca_key, CA_KEY)
    CA_CRT.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    CA_DER.write_bytes(ca_cert.public_bytes(serialization.Encoding.DER))
    dump_key(leaf_key, LEAF_KEY)
    LEAF_CRT.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    log("Certificats locaux generees dans certs\\")


def ca_installed() -> bool:
    r = ps(
        "(Get-ChildItem Cert:\\CurrentUser\\Root -ErrorAction SilentlyContinue | "
        f"Where-Object {{$_.Subject -like '*{CA_CN}*'}}).Count"
    )
    return r.stdout.strip().splitlines()[:1] not in ([], ["0"])


def install_ca() -> None:
    if ca_installed():
        return
    r = run_cmd(["certutil.exe", "-user", "-addstore", "Root", str(CA_DER)])
    if not ca_installed():
        raise RuntimeError(
            "Impossible d'installer le certificat local (CA) : "
            f"{(r.stdout or '') + (r.stderr or '')}".strip()
        )
    log("Certificat local installe dans Cert:\\CurrentUser\\Root")


def remove_ca() -> None:
    run_cmd(["certutil.exe", "-user", "-delstore", "Root", CA_CN])
    ps(
        "Get-ChildItem Cert:\\CurrentUser\\Root -ErrorAction SilentlyContinue | "
        f"Where-Object {{$_.Subject -like '*{CA_CN}*'}} | ForEach-Object {{ $_.Delete() }}"
    )
    log("Certificat local retire")

# ---------------------------------------------------------------------------
# Etat d'installation (pour restauration exacte)
# ---------------------------------------------------------------------------

def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state() -> None:
    """Sauvegarde les valeurs ORIGINALES (une seule fois)."""
    if STATE_FILE.exists():
        return
    state = {
        "lnks_orig": {str(p): get_lnk_args(p) for p in all_spotify_lnks()},
        "proto_orig": get_proto_cmd(),
    }
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Reglages Spotify : raccourci Demarrer + protocole spotify:
# ---------------------------------------------------------------------------

def get_lnk_args(path: Path = SPOTIFY_LNK) -> str:
    r = ps(f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{path}'); Write-Output $s.Arguments")
    return (r.stdout or "").strip()


def set_lnk_args(args: str, path: Path = SPOTIFY_LNK) -> None:
    ps(
        f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{path}'); "
        f"$s.Arguments='{args}'; $s.Save()"
    )


def all_spotify_lnks() -> list[Path]:
    """Tous les raccourcis Spotify connus (Demarrer, Bureau, Barre des taches).

    Un lancement quelconque SANS le flag ouvre Spotify sans proxy -> les pubs
    repassent. On couvre donc tous les points d'entree connus.
    """
    known = [
        SPOTIFY_LNK,
        Path.home() / "Desktop" / "Spotify.lnk",
        Path(os.environ.get("PUBLIC", "")) / "Desktop" / "Spotify.lnk",
        APPDATA
        / "Microsoft"
        / "Internet Explorer"
        / "Quick Launch"
        / "User Pinned"
        / "TaskBar"
        / "Spotify.lnk",
    ]
    out, seen = [], set()
    for p in known:
        try:
            rp = p.resolve() if p.exists() else p
        except OSError:
            rp = p
        if p.exists() and str(rp).lower() not in seen:
            seen.add(str(rp).lower())
            out.append(p)
    return out


def get_proto_cmd() -> str | None:
    r = ps(
        f"$k=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('{PROTOCOL_KEY}'); "
        "if ($k) { Write-Output ([string]$k.GetValue('')) }"
    )
    val = (r.stdout or "").strip("\r\n")
    return val or None


def set_proto_cmd(val: str) -> None:
    ps(
        f"$k=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('{PROTOCOL_KEY}',$true); "
        f"if ($k) {{ $k.SetValue('', '{val}', [Microsoft.Win32.RegistryValueKind]::String); $k.Close() }}"
    )


def strip_flag(s: str | None) -> str:
    return re.sub(r"\s*" + re.escape(FLAG), "", s or "").strip()


def ensure_flags() -> None:
    """Ajoute --proxy-server a TOUS les raccourcis + au protocole (idempotent)."""
    lnks = all_spotify_lnks()
    if not lnks:
        log("AVERTISSEMENT : aucun raccourci Spotify trouve")
    for lnk in lnks:
        args = get_lnk_args(lnk)
        if FLAG not in (args or ""):
            set_lnk_args((args + " " + FLAG).strip(), lnk)
            log(f"Raccourci configure : {lnk.name} ({lnk.parent})")
    cmd = get_proto_cmd()
    if cmd and FLAG not in cmd:
        set_proto_cmd((cmd + " " + FLAG).strip())
        log("Protocole spotify: : proxy configure")


def clear_flags() -> None:
    for lnk in all_spotify_lnks():
        set_lnk_args(strip_flag(get_lnk_args(lnk)), lnk)
    cmd = get_proto_cmd()
    if cmd:
        set_proto_cmd(strip_flag(cmd))
    log("Reglages Spotify restaures (connexion directe)")


def ensure_startup_lnk() -> None:
    """Lance automatiquement le proxy a chaque connexion Windows."""
    pyw = Path(sys.executable).with_name("pythonw.exe")
    if not pyw.exists():
        pyw = Path(sys.executable)
    script = BASE / "antipub.py"
    args = f'"{script}" start'
    ps(
        f"$sh=New-Object -ComObject WScript.Shell; "
        f"$s=$sh.CreateShortcut('{STARTUP_LNK}'); "
        f"$s.TargetPath='{pyw}'; "
        f"$s.Arguments='{args}'; "
        f"$s.WorkingDirectory='{BASE}'; "
        f"$s.Description='Proxy anti-pub Spotify'; $s.Save()"
    )
    log("Demarrage automatique configure (dossier Startup)")


def remove_startup_lnk() -> None:
    try:
        STARTUP_LNK.unlink(missing_ok=True)
    except Exception:
        pass


def kill_listener() -> bool:
    """Arrete le processus qui ecoute sur le port du proxy."""
    r = ps(
        f"$c=Get-NetTCPConnection -LocalPort {PROXY_PORT} -State Listen -ErrorAction SilentlyContinue | "
        "Select-Object -First 1; if ($c) { "
        "$p=Get-CimInstance Win32_Process -Filter \"ProcessId=$($c.OwningProcess)\"; "
        "if ($p.CommandLine -like '*antipub.py*') { Stop-Process -Id $c.OwningProcess -Force; 'killed' } }"
    )
    return "killed" in (r.stdout or "")


def proxy_listening() -> bool:
    try:
        with socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=1.5):
            return True
    except OSError:
        return False

# ---------------------------------------------------------------------------
# Lecteur de sockets avec tampon (parsing HTTP fiable)
# ---------------------------------------------------------------------------

class Reader:
    def __init__(self, sock: socket.socket, initial: bytes = b""):
        self.sock = sock
        self.buf = initial

    def _fill(self) -> None:
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError
        self.buf += chunk

    def read_until(self, delim: bytes, cap: int = 1 << 20) -> bytes:
        while delim not in self.buf:
            if len(self.buf) > cap:
                raise ValueError("entete trop volumineuse")
            self._fill()
        i = self.buf.index(delim) + len(delim)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            self._fill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def readline(self) -> bytes:
        while b"\r\n" not in self.buf:
            if len(self.buf) > 8192:
                raise ValueError("ligne trop longue")
            self._fill()
        i = self.buf.index(b"\r\n") + 2
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def recv_raw(self) -> bytes:
        if self.buf:
            out, self.buf = self.buf, b""
            return out
        return self.sock.recv(65536)


def parse_head(head: bytes):
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin1", "replace").split(" ")
    if len(parts) < 3:
        raise ValueError("ligne de requete invalide")
    method, target, version = parts[0], parts[1], " ".join(parts[2:])
    headers = {}
    for ln in lines[1:]:
        if b":" not in ln:
            continue
        k, v = ln.split(b":", 1)
        headers[k.decode("latin1", "replace").lower()] = v.decode("latin1", "replace").strip()
    return method, target, version, headers


def split_hostport(hostport: str, default: int = 443):
    if hostport.startswith("["):  # IPv6
        host, _, rest = hostport[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default
    if ":" in hostport:
        host, _, port = hostport.rpartition(":")
        return host, int(port)
    return hostport, default


def host_blocked(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == b or h.endswith("." + b) for b in BLOCK_HOSTS)


def is_mitm(host: str) -> bool:
    """Hotels dont on inspecte les chemins (spclient = transport des pubs)."""
    h = host.lower()
    if h in ("spclient.wg.spotify.com", "spclient.spotify.com"):
        return True
    return bool(re.fullmatch(r"[a-z0-9-]+-spclient\.spotify\.com", h))


def path_blocked(target: str) -> bool:
    p = target.split("?", 1)[0].split("#", 1)[0]
    for base in ("/ads", "/ad-logic", "/gabo-receiver-service", "/audio-ads"):
        if p == base or p.startswith(base + "/"):
            return True
    return False


# ---------------------------------------------------------------------------
# Transfert de corps / reponses
# ---------------------------------------------------------------------------

def forward_body(src: Reader, dst: socket.socket, headers: dict) -> None:
    te = headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        while True:
            line = src.readline()
            dst.sendall(line)
            try:
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
            except ValueError:
                raise ValueError("chunk invalide")
            if size == 0:
                while True:
                    t = src.readline()
                    if not t:
                        return
                    dst.sendall(t)
                    if t in (b"\r\n", b"\n", b""):
                        return
            dst.sendall(src.read_exact(size))
            dst.sendall(src.read_exact(2))
    elif "content-length" in headers:
        n = int(headers["content-length"])
        while n > 0:
            chunk = src.read_exact(min(n, 65536))
            dst.sendall(chunk)
            n -= len(chunk)


def forward_chunked(src: Reader, dst: socket.socket) -> None:
    while True:
        line = src.readline()
        dst.sendall(line)
        try:
            size = int(line.split(b";", 1)[0].strip() or b"0", 16)
        except ValueError:
            raise ValueError("chunk invalide")
        if size == 0:
            while True:
                t = src.readline()
                if not t:
                    return
                dst.sendall(t)
                if t in (b"\r\n", b"\n", b""):
                    return
        dst.sendall(src.read_exact(size))
        dst.sendall(src.read_exact(2))


def splice(a: socket.socket, b: socket.socket) -> None:
    """Relaie bidirectionnel brut jusqu'a fermeture."""
    socks = [a, b]
    try:
        while True:
            r, _, x = select.select(socks, [], socks, 120)
            if x or not r:
                return
            for s in r:
                try:
                    data = s.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                other = b if s is a else a
                try:
                    other.sendall(data)
                except OSError:
                    return
    finally:
        close_sock(a)
        close_sock(b)


def relay_response(ur: Reader, dst: socket.socket, method: str, ctx: str = "") -> bool:
    """Transfere une reponse complete. Retourne True si keep-alive."""
    while True:
        head = ur.read_until(b"\r\n\r\n")
        dst.sendall(head)
        lines = head.split(b"\r\n")
        try:
            code = int(lines[0].split(b" ")[1])
        except Exception:
            code = 0
        if code == 101:  # Switching Protocols -> relais brut
            splice(dst, ur.sock)
            return False
        if 100 <= code < 200:
            continue  # information (100 Continue...)
        break

    headers = {}
    for ln in lines[1:]:
        if b":" not in ln:
            continue
        k, v = ln.split(b":", 1)
        headers[k.decode("latin1", "replace").lower()] = v.decode("latin1", "replace").strip()

    te = headers.get("transfer-encoding", "").lower()
    if ctx:
        log(
            f"REP     {ctx} status={code} "
            f"cl={headers.get('content-length', '-')} te={te or '-'}"
        )
    if method == "HEAD" or code in (204, 304) or code < 200:
        body = None
    else:
        body = "chunked" if "chunked" in te else ("length" if "content-length" in headers else "eof")

    if body == "chunked":
        forward_chunked(ur, dst)
    elif body == "length":
        n = int(headers["content-length"])
        while n > 0:
            chunk = ur.read_exact(min(n, 65536))
            dst.sendall(chunk)
            n -= len(chunk)
    elif body == "eof":
        while True:
            try:
                chunk = ur.recv_raw()
            except OSError:
                break
            if not chunk:
                break
            dst.sendall(chunk)
        return False

    conn = headers.get("connection", "").lower()
    if "close" in conn:
        return False
    if lines[0].endswith(b"HTTP/1.0") and "keep-alive" not in conn:
        return False
    return True

# ---------------------------------------------------------------------------
# Session proxy (coeur du filtrage)
# ---------------------------------------------------------------------------

MITM_CTX: ssl.SSLContext | None = None


def build_mitm_ctx() -> None:
    global MITM_CTX
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(LEAF_CRT), str(LEAF_KEY))
    ctx.set_alpn_protocols(["http/1.1"])  # evite HTTP/2 a intercepter
    MITM_CTX = ctx


def connect_upstream(host: str):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    raw = socket.create_connection((host, 443), timeout=20)
    raw.settimeout(60)
    tls = ctx.wrap_socket(raw, server_hostname=host)
    return tls, Reader(tls)


def open_upstream(host: str, port: int, upstream_ssl: bool):
    """Ouvre une connexion fraiche vers l'amont (TLS ou brut)."""
    if upstream_ssl:
        return connect_upstream(host)
    s = socket.create_connection((host, port), timeout=20)
    s.settimeout(60)
    return s, Reader(s)


def proxy_session(cr: Reader, cw: socket.socket, host: str, port: int, upstream_ssl: bool) -> None:
    """Boucle requete/reponse avec filtrage des chemins publicitaires."""
    up: socket.socket | None = None
    ur: Reader | None = None
    try:
        while True:
            head = cr.read_until(b"\r\n\r\n")
            method, target, version, headers = parse_head(head)

            # HTTP absolu (hors MITM) -> chemin seul
            if target.startswith("http://"):
                m = re.match(r"^http://[^/]+(/.*)$", target)
                if m:
                    target = m.group(1)

            if path_blocked(target):
                log(f"BLOQUE  {host}{target}")
                cw.sendall(BLOCKED_RESP)
                return
            log(
                f"OK      {host}{target} "
                f"[{method} cl={headers.get('content-length', '-')} "
                f"expect={'100-continue' if headers.get('expect') else '-'} "
                f"te={headers.get('transfer-encoding', '-')}]"
            )

            if up is None:
                up, ur = open_upstream(host, port, upstream_ssl)

            # Reconstruit la premiere ligne (cible relative) sans Proxy-Connection
            # head se termine TOUJOURS par \r\n\r\n : on le retire avant de
            # scinder, sinon les elements vides de fin ajoutent 2 CRLF
            # supplementaires et le corps (Content-Length) devient decale ->
            # le serveur reçoit un corps corrompu et renvoie 400.
            lines = head[:-4].split(b"\r\n")
            first = f"{method} {target} {version}".encode("latin1", "replace")
            rest = [ln for ln in lines[1:] if not ln.lower().startswith(b"proxy-connection:")]
            req = b"\r\n".join([first] + rest) + b"\r\n\r\n"
            has_body = bool(
                headers.get("content-length") or "chunked" in headers.get("transfer-encoding", "")
            )
            dbg = bool(os.environ.get("ANTIPUB_DEBUG")) and any(
                k in target for k in ("playplay", "manifests", "storage-resolve")
            )

            try:
                up.sendall(req)
                body_saved = b""
                if has_body:
                    # Si le client attend un "100 Continue" avant d'envoyer le
                    # corps, on le lui donne tout de suite : sinon on attend son
                    # corps pendant qu'il attend notre accord -> blocage (deadlock).
                    if headers.get("expect", "").lower() == "100-continue":
                        cw.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                    if dbg and "content-length" in headers:
                        try:
                            n_body = int(headers["content-length"])
                        except ValueError:
                            n_body = -1
                        if 0 < n_body <= 4_000_000:
                            body_saved = cr.read_exact(n_body)
                            up.sendall(body_saved)
                        else:
                            forward_body(cr, up, headers)
                    else:
                        forward_body(cr, up, headers)
                if dbg:
                    try:
                        DBG_REQ.write_bytes(req + body_saved)
                        log(f"DEBUG   requete capturee ({len(req) + len(body_saved)} o)")
                    except Exception:
                        pass
            except (OSError, ValueError):
                # Amont ferme entre-temps (keep-alive expire) : on
                # reconnexionne. Rejoue la requete uniquement si elle n'a
                # aucun corps (sinon le corps est partiel -> on abandonne
                # proprement, le client reessaiera de son cote).
                close_sock(up)
                up, ur = None, None
                if has_body:
                    return
                up, ur = open_upstream(host, port, upstream_ssl)
                try:
                    up.sendall(req)
                except OSError:
                    return

            keep = relay_response(ur, cw, method, f"{host}{target}")
            if not keep:
                return
            if headers.get("connection", "").lower() == "close":
                return
            # L'amont reste ouvert pour la requete suivante (keep-alive).
            # NB : pas de recv(MSG_PEEK) ici — interdit sur socket SSL, cela
            # levait un ValueError et tuait la connexion apres chaque reponse
            # (Spotify ne pouvait plus reutiliser ses connexions -> lecture
            # bloque). Si l'amont est ferme, le prochain envoi levera une
            # OSError geree plus haut.
    except EOFError:
        # Amont ferme avant la fin d'une reponse : Spotify n'a rien recu ->
        # il abandonne la lecture. On le dit plutot que de silencieuser.
        log(f"ERREUR  reponse amont interrompue (EOF) {host}")
        raise
    finally:
        close_sock(up)


def mitm_session(c: socket.socket, pre: Reader, host: str) -> None:
    tls = MITM_CTX.wrap_socket(c, server_side=True)
    log(f"MITM    {host} (inspection active)")
    cr = Reader(tls, initial=pre.buf)
    pre.buf = b""
    try:
        proxy_session(cr, tls, host, 443, upstream_ssl=True)
    finally:
        close_sock(tls)


def tunnel(c: socket.socket, host: str, port: int) -> None:
    u = socket.create_connection((host, port), timeout=20)
    splice(c, u)


# ---------------------------------------------------------------------------
# Gestion d'une connexion entrante
# ---------------------------------------------------------------------------

def client_thread(c: socket.socket) -> None:
    try:
        c.settimeout(60)
        r = Reader(c)
        head = r.read_until(b"\r\n\r\n", cap=65536)
        method, target, _version, _h = parse_head(head)

        if method == "CONNECT":
            host, port = split_hostport(target)
            if host_blocked(host):
                log(f"BLOQUE  {host} (domaine)")
                c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            if is_mitm(host):
                c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                mitm_session(c, r, host)
                return
            # Tunnel brut : on ne touche a rien d'autre (visibilite seule)
            log(f"TUNNEL  {host}:{port}")
            try:
                u = socket.create_connection((host, port), timeout=20)
            except OSError as exc:
                log(f"ERREUR  tunnel {host}:{port} -> {exc}")
                c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            splice(c, u)
            return

        # HTTP simple (rare)
        m = re.match(r"^http://([^/:]+)(?::(\d+))?(/.*)$", target)
        if not m:
            c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        host, port, path = m.group(1), int(m.group(2) or 80), m.group(3)
        if host_blocked(host) or path_blocked(path):
            log(f"BLOQUE  {host}{path}")
            c.sendall(BLOCKED_RESP)
            return
        proxy_session(r, c, host, port, upstream_ssl=False)
    except (EOFError, socket.timeout, ConnectionResetError, BrokenPipeError, ValueError):
        pass
    except ssl.SSLError as exc:
        log(f"ERREUR  TLS client: {exc}")
    except Exception:
        log("ERREUR  " + traceback.format_exc(limit=4))
    finally:
        close_sock(c)


def close_sock(s) -> None:
    if s is None:
        return
    try:
        s.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Serveur
# ---------------------------------------------------------------------------

def serve() -> int:
    ensure_certs()
    install_ca()
    save_state()
    ensure_flags()
    ensure_startup_lnk()
    build_mitm_ctx()

    # Sonde AVANT bind : sur Windows, SO_REUSEADDR autorise un 2e bind sur le
    # meme port -> deux instances "actives" mais une seule receptif. La sonde
    # connect detecte un reel ecouteur deja en place.
    if proxy_listening():
        log(f"Proxy deja actif sur {PROXY_URL} (rien a faire)")
        return 0

    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        ls.bind((PROXY_HOST, PROXY_PORT))
    except OSError:
        log(f"Proxy deja actif sur {PROXY_URL} (rien a faire)")
        return 0
    ls.listen(128)
    log(f"=== Proxy anti-pub actif sur {PROXY_URL} ===")
    log("Spotify est configure pour passer par ce proxy.")
    log("Arret : Ctrl+C ici, ou 'python antipub.py stop'")

    try:
        while True:
            try:
                c, _addr = ls.accept()
            except OSError:
                break
            threading.Thread(target=client_thread, args=(c,), daemon=True).start()
    except KeyboardInterrupt:
        log("Proxy arrete. Pour reactiver : demarrer.bat")
        log("(Spotify garde le reglage : sans proxy il ne pourra pas se connecter)")
    finally:
        close_sock(ls)
    return 0

# ---------------------------------------------------------------------------
# Commandes
# ---------------------------------------------------------------------------

def cmd_install_and_start() -> int:
    """Point d'entree par defaut : installe tout (si besoin) puis demarre."""
    print("== Spotify Anti-Pub ==")
    ensure_certs()
    install_ca()
    save_state()
    ensure_flags()
    ensure_startup_lnk()
    if proxy_listening():
        print(f"Proxy deja actif sur {PROXY_URL} — rien a faire.")
        print("Ouvrez Spotify (n'importe quel raccourci) : c'est protege.")
        return 0
    print(f"Demarrage du proxy sur {PROXY_URL} ...")
    print("(fermez cette fenetre pour arreter, ou tapez Ctrl+C)")
    print()
    return serve()


def cmd_install() -> int:
    print("== Installation du Spotify Anti-Pub ==")
    ensure_certs()
    install_ca()
    save_state()
    ensure_flags()
    ensure_startup_lnk()
    print()
    print("Termine ! Prochaine etape :")
    print("   python antipub.py start   (ou double-cliquez sur demarrer.bat)")
    print()
    print("Pensez a fermer Spotify puis a le relancer via son raccourci")
    print("(Demarrer menu ou protocole spotify:) pour activer le proxy.")
    return 0


def cmd_start() -> int:
    return serve()


def cmd_stop() -> int:
    clear_flags()
    if kill_listener():
        print("Proxy arrete.")
    else:
        print("Proxy deja a l'arret.")
    print("Spotify reprend la connexion directe (relancez-le pour en profiter).")
    print("Reactiver : demarrer.bat")
    return 0


def cmd_status() -> int:
    ok_proxy = proxy_listening()
    ok_ca = ca_installed()
    lnks = all_spotify_lnks()
    bad_lnks = [p for p in lnks if FLAG not in (get_lnk_args(p) or "")]
    ok_lnk = bool(lnks) and not bad_lnks
    cmd = get_proto_cmd()
    ok_proto = bool(cmd) and FLAG in cmd
    ok_start = STARTUP_LNK.exists()

    def mark(b):
        return "OK  " if b else "NON"

    print("== Etat du Spotify Anti-Pub ==")
    print(f"  [{mark(ok_proxy)}] Proxy en ecoute sur {PROXY_URL}")
    print(f"  [{mark(ok_ca)}] Certificat local (CA) installe")
    if lnks:
        for p in lnks:
            good = FLAG in (get_lnk_args(p) or "")
            print(f"  [{mark(good)}] Raccourci : {p}")
    else:
        print("  [NON] Aucun raccourci Spotify trouve")
    print(f"  [{mark(ok_proto)}] Protocole spotify: configure")
    print(f"  [{mark(ok_start)}] Demarrage automatique")
    r = ps("(Get-Process spotify -ErrorAction SilentlyContinue).Count")
    running = (r.stdout or "").strip() not in ("", "0")
    print(f"  [{'EN COURS' if running else 'arrete'}] Client Spotify")
    print()
    if bad_lnks:
        print("ATTENTION : ces raccourcis lancent Spotify SANS le proxy")
        print("(les pubs passeraient) -> relancez 'python antipub.py install'")
    if (ok_lnk or ok_proto) and not ok_proxy:
        print("ATTENTION : Spotify est configure pour le proxy mais le proxy est")
        print("arrete -> Spotify ne pourra pas se connecter. Lancez demarrer.bat !")
    elif ok_proxy and not (ok_lnk or ok_proto):
        print("NOTE : le proxy tourne mais Spotify n'est pas encore configure.")
    elif ok_proxy and ok_lnk and not bad_lnks:
        print("Tout est en place. Redemarrez Spotify si besoin.")
    return 0


def cmd_uninstall() -> int:
    print("== Desinstallation du Spotify Anti-Pub ==")
    kill_listener()
    state = load_state()
    lnks_orig = state.get("lnks_orig")
    if isinstance(lnks_orig, dict):
        for path_str, orig in lnks_orig.items():
            p = Path(path_str)
            if p.exists():
                set_lnk_args(orig, p)
        # raccourcis apparus depuis l'installation
        for p in all_spotify_lnks():
            if str(p) not in lnks_orig:
                set_lnk_args(strip_flag(get_lnk_args(p)), p)
    elif state.get("lnk_orig") is not None and SPOTIFY_LNK.exists():
        set_lnk_args(state["lnk_orig"])
        for p in all_spotify_lnks():
            if p != SPOTIFY_LNK:
                set_lnk_args(strip_flag(get_lnk_args(p)), p)
    else:
        clear_flags()
    if state.get("proto_orig") is not None:
        set_proto_cmd(state["proto_orig"])
    remove_startup_lnk()
    remove_ca()
    shutil.rmtree(CERT_DIR, ignore_errors=True)
    try:
        STATE_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    print("Termine : Spotify est revu en etat d'origine.")
    print("(Le journal antipub.log est conserve)")
    return 0


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="antipub.py",
        description="Bloqueur de publicites Spotify local (proxy + certificat locale)",
        epilog="Sans sous-commande : installe si besoin et demarre le proxy.",
    )
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("install", help="installe certs + CA + reglages Spotify")
    sub.add_parser("start", help="demarre le proxy")
    sub.add_parser("stop", help="arrete le proxy et rend Spotify direct")
    sub.add_parser("status", help="affiche l'etat")
    sub.add_parser("uninstall", help="retire tout et restaure l'original")
    args = ap.parse_args()

    try:
        # Aucune sous-commande -> "tout d'un coup" : verifie l'installation
        # puis demarre le proxy. Une seule commande a retenir.
        if not args.cmd:
            return cmd_install_and_start()
        if args.cmd == "install":
            return cmd_install()
        if args.cmd == "start":
            return cmd_start()
        if args.cmd == "stop":
            return cmd_stop()
        if args.cmd == "status":
            return cmd_status()
        if args.cmd == "uninstall":
            return cmd_uninstall()
    except RuntimeError as exc:
        print(f"ERREUR : {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
