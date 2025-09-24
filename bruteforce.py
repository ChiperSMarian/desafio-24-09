# bruteforce.py
import random
from datetime import datetime
from typing import Optional

from bd import fetch_ip_malas, insert_alert_to_db
from save_csv import append_row_to_csv

from utils import (
    consultar_abuseipdb_ip,
    consultar_ipqs_ip,
    get_country_for_ip,
    get_network_enrichment,
    score_from_bruteforce,
)

# Rango esperado / pasos definidos por la usuaria
ATT_MIN, ATT_MAX, ATT_STEP = 100, 1000, 100    # intentos (100..1000 paso 100)
RATE_MIN, RATE_MAX, RATE_STEP = 30, 80, 10     # rate /s (30..80 paso 10)


def pick_ip(ip_source: str = "any", bad_prob: float = 0.5, conn_params=None):
    """
    Selecciona una IP desde la BD (tabla ip_malas).
    """
    ips = fetch_ip_malas(conn_params=conn_params)
    if not ips:
        raise RuntimeError("No hay IPs en la tabla ip_malas.")
    return random.choice(ips)


def generate_alert(
    ip_source: str = "any",
    bad_prob: float = 0.5,
    with_enrichment: bool = False,
    save_csv: bool = True,
    save_db: bool = True,
    conn_params=None,
    w_target: float = 0.5,
):
    """
    Genera una alerta de fuerza bruta:
      - target: 'ssh' o 'smb' al 50%
      - intentos: 100-1000 paso 100
      - ratio: 30-80 paso 10
    Enriquecimiento:
      - AbuseIPDB (score 0..10 vía utils.score_from_abuse)
      - ip-api (código país, isp, as/org)
      - IPQS IP (vpn/proxy/tor -> flag 'vpn')
    Guarda en CSV y en BD (tabla alertas_fuerza_bruta).
    Devuelve diccionario con 'alerta' y 'score_final'.
    """
    ip = pick_ip(ip_source=ip_source, bad_prob=bad_prob, conn_params=conn_params)
    now = datetime.now()
    fecha = now.strftime("%Y-%m-%d")
    hora = now.strftime("%H:%M:%S")

    target = random.choice(["ssh", "smb"])
    intentos = random.choice(list(range(ATT_MIN, ATT_MAX + 1, ATT_STEP)))
    ratio = random.choice(list(range(RATE_MIN, RATE_MAX + 1, RATE_STEP)))

    abuse_json = None
    ipqs_ip_json = None

    if with_enrichment:
        abuse_json = consultar_abuseipdb_ip(ip)
        ipqs_ip_json = consultar_ipqs_ip(ip)  # puede ser None si no hay API key

    # País (ISO2 si disponible)
    codigo_pais = get_country_for_ip(ip, abuse_json=abuse_json)

    # as_owner / isp / vpn
    net_enrich = get_network_enrichment(ip, vt_json=None, ipqs_json=ipqs_ip_json)
    as_owner = net_enrich.get("as_owner")
    isp = net_enrich.get("isp")
    vpn = net_enrich.get("vpn")

    # Score fuerza bruta 0..10
    score_final = score_from_bruteforce(
        abuse_json=abuse_json,
        intentos=intentos,
        ratio=ratio,
        target=target,
        w_target=w_target,
    )

    # Clasificación textual
    if score_final == 0:
        riesgo_text = "Inofensivo"
    elif score_final <= 3.9:
        riesgo_text = "Bajo"
    elif score_final <= 6.9:
        riesgo_text = "Medio"
    elif score_final <= 8.5:
        riesgo_text = "Alto"
    else:
        riesgo_text = "Crítico"

    row_db = {
        "fecha": fecha,
        "hora": hora,
        "ip": ip,
        "codigo_pais": codigo_pais,
        "target": target,
        "intentos": intentos,
        "ratio": ratio,
        "as_owner": as_owner,
        "isp": isp,
        "vpn": vpn,  # boolean (True si VPN/Proxy/Tor segun IPQS)
        "abuse_confidence_raw": (abuse_json or {}).get("data", {}).get("abuseConfidenceScore")
            if isinstance(abuse_json, dict) else None,
        "score_final": score_final,
        "riesgo": riesgo_text,
    }

    if save_csv:
        append_row_to_csv(row_db, attack_type="bruteforce")

    result_db = None
    if save_db:
        result_db = insert_alert_to_db(row_db, table_name="alertas_fuerza_bruta", conn_params=conn_params)

    return {
        "ok": True,
        "alerta": row_db,
        "saved": {"csv": save_csv, "db": result_db},
        "enrichment": {
            "abuseipdb_used": bool(with_enrichment and abuse_json is not None),
            "ipqs_used": bool(with_enrichment and ipqs_ip_json is not None),
            "codigo_pais": codigo_pais,
            "as_owner": as_owner,
            "isp": isp,
            "vpn": vpn,
        },
    }
