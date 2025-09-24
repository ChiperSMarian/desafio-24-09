# utils.py
"""
Funciones de consulta a APIs, scoring y ensamblaje de alertas.

Incluye:
- Consultas: VirusTotal (IP y dominios), AbuseIPDB, OTX, IPQualityScore (URL e IP), ip-api (geo/red)
- Scoring: score_from_virustotal, score_from_abuse, score_from_otx,
  score_phishing_url, score_login_ip, score_from_bruteforce, score_from_dos, score_from_ddos
- Enriquecimiento: get_country_for_ip, get_ip_api_info, get_network_enrichment
- Crear alerta: crear_alerta_final
"""

import os
import json
import math
import requests
from datetime import datetime
from typing import Dict, Any, Optional

# intentar cloudscraper (opcional, para Cloudflare)
try:
    import cloudscraper
    _HAS_CLOUDSCRAPER = True
except Exception:
    cloudscraper = None
    _HAS_CLOUDSCRAPER = False

try:
    import tldextract
except Exception:
    tldextract = None

API_KEYS = {
    "virustotal": os.getenv("virustotal_api_key") or os.getenv("VIRUSTOTAL_API_KEY", ""),
    "abuseipdb": os.getenv("abuseipdb_api_key") or os.getenv("ABUSEIPDB_API_KEY", ""),
    "otx": os.getenv("otx_api_key") or os.getenv("OTX_API_KEY", ""),
    "urlscan": os.getenv("urlscan_api_key") or os.getenv("URLSCAN_API_KEY", ""),
    "ipqs": os.getenv("ipqualityscore") or os.getenv("IPQS_API_KEY", "")
}

# -------------------
# HTTP helper
# -------------------
def _http_get(url: str, headers: Optional[dict] = None, params: Optional[dict] = None, timeout: int = 10):
    if _HAS_CLOUDSCRAPER and cloudscraper:
        try:
            s = cloudscraper.create_scraper()
            return s.get(url, headers=headers, params=params, timeout=timeout)
        except Exception:
            pass
    return requests.get(url, headers=headers, params=params, timeout=timeout)

def consultar_api(url: str, headers: Optional[dict] = None, params: Optional[dict] = None, timeout: int = 10):
    try:
        r = _http_get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                return {"__status_code__": r.status_code, "__text__": r.text}
        else:
            return {"__status_code__": r.status_code, "__text__": r.text}
    except requests.exceptions.RequestException as e:
        return {"__exception__": str(e)}
    except Exception as e:
        return {"__exception__": str(e)}

# -------------------
# Consultas a APIs concretas
# -------------------
def consultar_virustotal_ip(ip_address: str):
    api_key = API_KEYS.get("virustotal") or ""
    if not api_key:
        return {"__error__": "No API key de VirusTotal configurada."}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    return consultar_api(url, headers=headers)

def consultar_abuseipdb_ip(ip_address: str):
    api_key = API_KEYS.get("abuseipdb") or ""
    if not api_key:
        return {"__error__": "No API key de AbuseIPDB configurada."}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 365}
    return consultar_api(url, headers=headers, params=params)

def consultar_otx_ip(ip_address: str):
    api_key = API_KEYS.get("otx") or ""
    if not api_key:
        return {"__error__": "No API key de OTX configurada."}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
    headers = {"X-OTX-API-KEY": api_key}
    return consultar_api(url, headers=headers)

def consultar_virustotal_domain(hostname: str):
    api_key = API_KEYS.get("virustotal") or ""
    if not api_key:
        return None
    dominio_raiz = None
    try:
        if tldextract:
            dominio_raiz = tldextract.extract(hostname).registered_domain
    except Exception:
        dominio_raiz = None
    dominio = dominio_raiz or hostname
    if not dominio:
        return None
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {"x-apikey": api_key}
    return consultar_api(url, headers=headers)

def consultar_ipqs_url(url: str):
    api_key = API_KEYS.get("ipqs") or ""
    if not api_key:
        return None
    import urllib.parse
    url_codificada = urllib.parse.quote_plus(url)
    endpoint = f"https://www.ipqualityscore.com/api/json/url/{api_key}/{url_codificada}"
    return consultar_api(endpoint)

def consultar_ipqs_ip(ip: str, strictness: int = 1):
    """
    IPQualityScore (IP) para flags vpn/proxy/tor.
    """
    api_key = API_KEYS.get("ipqs") or ""
    if not api_key:
        return None
    params = {
        "strictness": strictness,
        "allow_public_access_points": "true",
        "lighter_penalties": "true"
    }
    url = f"https://www.ipqualityscore.com/api/json/ip/{api_key}/{ip}"
    return consultar_api(url, params=params)

# -------------------
# Geo IP / Red: país, ISP, AS, VPN
# -------------------
def _geoip_ip_api(ip: str, fields: str = "status,countryCode,message", timeout: int = 5) -> Optional[dict]:
    try:
        url = f"http://ip-api.com/json/{ip}?fields={fields}"
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        data = r.json()
        return data
    except Exception:
        return None

def get_country_for_ip(ip: str, abuse_json: Optional[dict] = None) -> Optional[str]:
    try:
        if abuse_json and isinstance(abuse_json, dict):
            data = abuse_json.get("data") or abuse_json
            if isinstance(data, dict):
                cc = data.get("countryCode") or data.get("country") or data.get("country_code")
                if cc and isinstance(cc, str) and len(cc.strip()) > 0:
                    return cc.strip()
        data = _geoip_ip_api(ip, fields="status,countryCode,message")
        if data and data.get("status") == "success":
            return data.get("countryCode")
        return None
    except Exception:
        return None

def get_ip_api_info(ip: str) -> dict:
    fields = "status,countryCode,isp,org,as,message"
    data = _geoip_ip_api(ip, fields=fields)
    if not data or data.get("status") != "success":
        return {}
    return {
        "countryCode": data.get("countryCode"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "as": data.get("as")
    }

def get_network_enrichment(ip: str, vt_json: Optional[dict] = None, ipqs_json: Optional[dict] = None) -> dict:
    as_owner = None
    isp = None
    vpn = None

    try:
        if vt_json and isinstance(vt_json, dict):
            as_owner = vt_json.get("data", {}).get("attributes", {}).get("as_owner")
    except Exception:
        as_owner = None

    ipapi = get_ip_api_info(ip)
    if not as_owner:
        as_owner = ipapi.get("org") or ipapi.get("as") or as_owner
    isp = ipapi.get("isp") or as_owner

    try:
        if ipqs_json and isinstance(ipqs_json, dict):
            vpn_flag = bool(ipqs_json.get("vpn")) if "vpn" in ipqs_json else False
            proxy_flag = bool(ipqs_json.get("proxy")) if "proxy" in ipqs_json else False
            tor_flag = bool(ipqs_json.get("tor")) if "tor" in ipqs_json else False
            vpn = bool(vpn_flag or proxy_flag or tor_flag)
    except Exception:
        vpn = None

    return {
        "as_owner": as_owner,
        "isp": isp,
        "vpn": vpn
    }

# -------------------
# Scoring genérico
# -------------------
def score_from_virustotal(vt_json):
    try:
        if not vt_json or not isinstance(vt_json, dict) or 'data' not in vt_json:
            return 0.0
        stats = vt_json.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = int(stats.get('malicious', 0) or 0)
        suspicious = int(stats.get('suspicious', 0) or 0)
        score = min((malicious * 5) + suspicious, 10)
        return float(score)
    except Exception:
        return 0.0

def score_from_abuse(abuse_json):
    try:
        if not abuse_json or not isinstance(abuse_json, dict):
            return 0.0
        data = abuse_json.get("data") or abuse_json
        score100 = data.get("abuseConfidenceScore", 0)
        return float(score100) / 10.0
    except Exception:
        return 0.0

def score_from_otx(otx_json):
    try:
        if not otx_json or not isinstance(otx_json, dict):
            return 0.0
        if "pulse_info" in otx_json:
            pulses = (otx_json.get("pulse_info") or {}).get('count', 0) or 0
            if pulses <= 0:
                return 0.0
            return min(10.0, math.log10(pulses + 1) * 3.3)
        rep = otx_json.get("reputation")
        if rep is not None:
            return min(10.0, float(rep) / 10.0)
        return 0.0
    except Exception:
        return 0.0

def score_phishing_url(vt_json, ipqs_json):
    score_vt = score_from_virustotal(vt_json)
    score_ipqs = 0.0
    try:
        if ipqs_json and isinstance(ipqs_json, dict) and ipqs_json.get("success"):
            score_ipqs = float(ipqs_json.get("risk_score", 0)) / 10.0
    except Exception:
        score_ipqs = 0.0
    score_final = (score_vt * 0.5) + (score_ipqs * 0.5)
    return min(10.0, round(score_final, 2))

# -------------------
# Fuerza Bruta
# -------------------
BF_WEIGHT_ABUSE = 0.55
BF_WEIGHT_RATE = 0.25
BF_WEIGHT_ATT = 0.20

BF_ATT_MIN, BF_ATT_MAX = 100, 1000
BF_RATE_MIN, BF_RATE_MAX = 30, 80

def normalize_attempts_bf(intentos: int) -> float:
    try:
        if intentos <= BF_ATT_MIN:
            return 0.0
        if intentos >= BF_ATT_MAX:
            return 10.0
        return ((intentos - BF_ATT_MIN) / (BF_ATT_MAX - BF_ATT_MIN)) * 10.0
    except Exception:
        return 0.0

def normalize_rate_bf(rate: int) -> float:
    try:
        if rate <= BF_RATE_MIN:
            return 0.0
        if rate >= BF_RATE_MAX:
            return 10.0
        return ((rate - BF_RATE_MIN) / (BF_RATE_MAX - BF_RATE_MIN)) * 10.0
    except Exception:
        return 0.0

def weighted_sum_with_missing_bf(abuse_norm: float, rate_norm: float, att_norm: float) -> float:
    parts = [
        ("abuse", BF_WEIGHT_ABUSE, abuse_norm),
        ("rate", BF_WEIGHT_RATE, rate_norm),
        ("att", BF_WEIGHT_ATT, att_norm)
    ]
    present = [(k, w, v) for (k, w, v) in parts if v and v > 0.0]
    if not present:
        return 0.0
    sum_weights_present = sum(w for (_, w, _) in present)
    total = 0.0
    for (_, w, v) in present:
        adjusted_w = w / sum_weights_present
        total += adjusted_w * v
    return total

def score_from_bruteforce(abuse_json, intentos: int, ratio: int, target: str = "ssh", w_target: float = 0.5) -> float:
    abuse_norm = score_from_abuse(abuse_json)
    att_norm = normalize_attempts_bf(intentos)
    rate_norm = normalize_rate_bf(ratio)
    inner = weighted_sum_with_missing_bf(abuse_norm, rate_norm, att_norm)
    coef = float(w_target) * inner
    coef = max(0.0, min(10.0, coef))
    return round(coef, 4)

# -------------------
# DoS
# -------------------
DOS_WEIGHT_REQUESTS = 0.20
DOS_WEIGHT_RATE     = 0.30
DOS_WEIGHT_ABUSE    = 0.50

DOS_REQ_MIN,  DOS_REQ_MAX  = 1000, 5000
DOS_RATE_MIN, DOS_RATE_MAX =  100, 1000

def normalize_requests_dos(requests_count: int) -> float:
    try:
        if requests_count <= DOS_REQ_MIN:
            return 0.0
        if requests_count >= DOS_REQ_MAX:
            return 10.0
        return ((requests_count - DOS_REQ_MIN) / (DOS_REQ_MAX - DOS_REQ_MIN)) * 10.0
    except Exception:
        return 0.0

def normalize_rate_dos(rate: int) -> float:
    try:
        if rate <= DOS_RATE_MIN:
            return 0.0
        if rate >= DOS_RATE_MAX:
            return 10.0
        return ((rate - DOS_RATE_MIN) / (DOS_RATE_MAX - DOS_RATE_MIN)) * 10.0
    except Exception:
        return 0.0

def weighted_sum_with_missing_dos(req_norm: float, rate_norm: float, abuse_norm: float) -> float:
    parts = [
        ("requests", DOS_WEIGHT_REQUESTS, req_norm),
        ("rate",     DOS_WEIGHT_RATE,     rate_norm),
        ("abuse",    DOS_WEIGHT_ABUSE,    abuse_norm),
    ]
    present = [(k, w, v) for (k, w, v) in parts if v and v > 0.0]
    if not present:
        return 0.0
    sum_weights_present = sum(w for (_, w, _) in present)
    total = 0.0
    for (_, w, v) in present:
        adjusted_w = w / sum_weights_present
        total += adjusted_w * v
    return total

def score_from_dos(abuse_json, requests_count: int, rate: int) -> float:
    abuse_norm = score_from_abuse(abuse_json)
    req_norm   = normalize_requests_dos(requests_count)
    rate_norm  = normalize_rate_dos(rate)
    inner = weighted_sum_with_missing_dos(req_norm, rate_norm, abuse_norm)
    score = max(0.0, min(10.0, inner))
    return round(score, 4)

# -------------------
# DDoS (nuevo)
#   Coef_ddos = 0.15*sources_norm + 0.15*requests_norm + 0.20*rate_norm + 0.50*abuse_norm
#   sources:  300..1500 (paso 100)
#   requests: 10000..100000 (paso 5000)
#   rate/s:   500..5000 (paso 100)
#   Normalización 0..10 y redistribución de pesos si faltan parámetros.
# -------------------
DDOS_WEIGHT_SOURCES  = 0.15
DDOS_WEIGHT_REQUESTS = 0.15
DDOS_WEIGHT_RATE     = 0.20
DDOS_WEIGHT_ABUSE    = 0.50

DDOS_SRC_MIN,  DDOS_SRC_MAX  =   300,  1500
DDOS_REQ_MIN,  DDOS_REQ_MAX  = 10000, 100000
DDOS_RATE_MIN, DDOS_RATE_MAX =   500,   5000

def normalize_sources_ddos(sources: int) -> float:
    try:
        if sources <= DDOS_SRC_MIN:
            return 0.0
        if sources >= DDOS_SRC_MAX:
            return 10.0
        return ((sources - DDOS_SRC_MIN) / (DDOS_SRC_MAX - DDOS_SRC_MIN)) * 10.0
    except Exception:
        return 0.0

def normalize_requests_ddos(requests_count: int) -> float:
    try:
        if requests_count <= DDOS_REQ_MIN:
            return 0.0
        if requests_count >= DDOS_REQ_MAX:
            return 10.0
        return ((requests_count - DDOS_REQ_MIN) / (DDOS_REQ_MAX - DDOS_REQ_MIN)) * 10.0
    except Exception:
        return 0.0

def normalize_rate_ddos(rate: int) -> float:
    try:
        if rate <= DDOS_RATE_MIN:
            return 0.0
        if rate >= DDOS_RATE_MAX:
            return 10.0
        return ((rate - DDOS_RATE_MIN) / (DDOS_RATE_MAX - DDOS_RATE_MIN)) * 10.0
    except Exception:
        return 0.0

def weighted_sum_with_missing_ddos(src_norm: float, req_norm: float, rate_norm: float, abuse_norm: float) -> float:
    parts = [
        ("sources",  DDOS_WEIGHT_SOURCES,  src_norm),
        ("requests", DDOS_WEIGHT_REQUESTS, req_norm),
        ("rate",     DDOS_WEIGHT_RATE,     rate_norm),
        ("abuse",    DDOS_WEIGHT_ABUSE,    abuse_norm),
    ]
    present = [(k, w, v) for (k, w, v) in parts if v and v > 0.0]
    if not present:
        return 0.0
    sum_weights_present = sum(w for (_, w, _) in present)
    total = 0.0
    for (_, w, v) in present:
        adjusted_w = w / sum_weights_present
        total += adjusted_w * v
    return total  # 0..10

def score_from_ddos(abuse_json, sources: int, requests_count: int, rate: int) -> float:
    abuse_norm = score_from_abuse(abuse_json)             # 0..10
    src_norm   = normalize_sources_ddos(sources)          # 0..10
    req_norm   = normalize_requests_ddos(requests_count)  # 0..10
    rate_norm  = normalize_rate_ddos(rate)                # 0..10
    inner = weighted_sum_with_missing_ddos(src_norm, req_norm, rate_norm, abuse_norm)
    score = max(0.0, min(10.0, inner))
    return round(score, 4)

# -------------------
# Login y clasificación
# -------------------
def score_login_ip(vt_json, abuse_json, otx_json):
    score_vt = score_from_virustotal(vt_json)
    score_abuse = score_from_abuse(abuse_json)
    score_otx = score_from_otx(otx_json)
    base_weights = {"vt": 0.60, "abuse": 0.30, "otx": 0.10}
    scores = {"vt": score_vt, "abuse": score_abuse, "otx": score_otx}
    active = {k: v for k, v in scores.items() if v and v > 0}
    if not active:
        return 0.0
    total_w = sum(base_weights[k] for k in active.keys())
    weighted = sum((base_weights[k] * active[k]) for k in active.keys())
    score_final = weighted / total_w
    return min(10.0, round(score_final, 2))

def clasificar_por_score_final(score_final: float) -> str:
    if score_final <= 0:
        return "Inofensivo"
    elif score_final <= 3.9:
        return "Bajo"
    elif score_final <= 6.9:
        return "Medio"
    elif score_final <= 8.9:
        return "Alto"
    else:
        return "Crítico"

# -------------------
# Crear alerta final (para otras rutas)
# -------------------
def crear_alerta_final(alerta_base: Dict[str, Any], vt_json=None, abuse_json=None, otx_json=None) -> Dict[str, Any]:
    try:
        fecha, hora = alerta_base.get("timestamp", "").split(" ")
    except Exception:
        now = datetime.now()
        fecha = now.strftime("%Y-%m-%d")
        hora = now.strftime("%H:%M:%S")

    score_vt = score_from_virustotal(vt_json)
    score_abuse = score_from_abuse(abuse_json)
    score_otx = score_from_otx(otx_json)

    score_final, riesgo = (0.0, "Inofensivo")
    try:
        if score_vt == 0 and score_abuse == 0 and score_otx == 0:
            score_final = 0.0
            riesgo = "Desconocido"
        else:
            score_final = score_login_ip(vt_json, abuse_json, otx_json)
            riesgo = clasificar_por_score_final(score_final)
    except Exception:
        score_final = 0.0
        riesgo = "Desconocido"

    pais = (vt_json or {}).get("data", {}).get("attributes", {}).get("country") if isinstance(vt_json, dict) else None
    isp = (vt_json or {}).get("data", {}).get("attributes", {}).get("as_owner") if isinstance(vt_json, dict) else None

    try:
        intentos = int(alerta_base.get("intentos") or 0)
        dur = int(alerta_base.get("duracion") or 0) or 1
        ratio_intentos = round(intentos / dur, 6) if dur > 0 else None
    except Exception:
        ratio_intentos = None

    alerta_final = {
        "fecha": fecha,
        "hora": hora,
        "usuario": alerta_base.get("usuario"),
        "intentos": int(alerta_base.get("intentos") or 0) if alerta_base.get("intentos") is not None else None,
        "duracion": int(alerta_base.get("duracion") or 0) if alerta_base.get("duracion") is not None else None,
        "ratio_intentos": ratio_intentos,
        "ip": alerta_base.get("ip"),
        "login": alerta_base.get("login"),
        "pais": pais,
        "isp": isp,
        "uso": alerta_base.get("uso"),
        "resultado_vt_raw": json.dumps((vt_json or {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}), ensure_ascii=False) if isinstance(vt_json, dict) else None,
        "score_vt": round(float(score_vt or 0.0), 2),
        "score_abuse": round(float(score_abuse or 0.0), 2),
        "score_otx": round(float(score_otx or 0.0), 2),
        "score_final": round(float(score_final or 0.0), 2),
        "risk_level": riesgo
    }
    return alerta_final

# -------------------
# Export
# -------------------
__all__ = [
    "consultar_api", "consultar_virustotal_ip", "consultar_abuseipdb_ip", "consultar_otx_ip",
    "consultar_virustotal_domain", "consultar_ipqs_url", "consultar_ipqs_ip",
    "score_from_virustotal", "score_from_abuse", "score_from_otx",
    "score_phishing_url", "score_login_ip",
    "score_from_bruteforce", "normalize_attempts_bf", "normalize_rate_bf",
    "score_from_dos", "normalize_requests_dos", "normalize_rate_dos",
    "score_from_ddos", "normalize_sources_ddos", "normalize_requests_ddos", "normalize_rate_ddos",
    "crear_alerta_final", "clasificar_por_score_final",
    "get_country_for_ip", "get_ip_api_info", "get_network_enrichment"
]
