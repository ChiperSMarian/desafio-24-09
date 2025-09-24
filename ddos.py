# ddos.py
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import random
from datetime import datetime
from typing import Dict, Any, Optional

from bd import insert_alert_to_db
from save_csv import append_row_to_csv

# Reutilizamos pick_ip_from_db de dos.py
from dos import pick_ip_from_db

from utils import (
    consultar_abuseipdb_ip,
    consultar_ipqs_ip,
    get_country_for_ip,
    get_network_enrichment,
    score_from_ddos,
    clasificar_por_score_final,
)

# RANGOS (según especificación)
SRC_MIN, SRC_MAX, SRC_STEP     =   300,   1500, 100     # sources
REQ_MIN, REQ_MAX, REQ_STEP     = 10000, 100000, 5000   # requests
RATE_MIN, RATE_MAX, RATE_STEP  =   500,   5000, 100    # rate/s

def generate_ddos_alert(
    ip_source: str = "any",
    bad_prob: float = 0.5,
    with_enrichment: bool = True,
    save_csv: bool = True,
    save_db: bool = True,
    conn_params: Optional[dict] = None
) -> Dict[str, Any]:
    """
    Genera una alerta DDoS y la guarda opcionalmente en CSV/DB (tabla 'alertas_ddos').

    Enriquecimiento (si with_enrichment):
      - AbuseIPDB -> abuseConfidenceScore (normalizado a 0..10)
      - ip-api.com -> countryCode, isp, as/org (para as_owner)
      - IPQualityScore (IP) -> flags vpn/proxy/tor -> boolean 'vpn'

    Ponderación 0..10:
      Coef_ddos = 0.15*sources_norm + 0.15*requests_norm + 0.20*rate_norm + 0.50*abuse_norm
      con redistribución de pesos si falta alguno (valor 0).
    """
    ip = pick_ip_from_db(conn_params=conn_params)

    now = datetime.now()
    fecha = now.strftime("%Y-%m-%d")
    hora = now.strftime("%H:%M:%S")

    sources = random.choice(list(range(SRC_MIN, SRC_MAX + 1, SRC_STEP)))
    requests_count = random.choice(list(range(REQ_MIN, REQ_MAX + 1, REQ_STEP)))
    ratio = random.choice(list(range(RATE_MIN, RATE_MAX + 1, RATE_STEP)))

    abuse_json = None
    ipqs_ip_json = None

    if with_enrichment:
        abuse_json = consultar_abuseipdb_ip(ip)
        ipqs_ip_json = consultar_ipqs_ip(ip)

    # País
    codigo_pais = get_country_for_ip(ip, abuse_json=abuse_json)

    # as_owner / isp / vpn
    net_enrich = get_network_enrichment(ip, vt_json=None, ipqs_json=ipqs_ip_json)
    as_owner = net_enrich.get("as_owner")
    isp = net_enrich.get("isp")
    vpn = net_enrich.get("vpn")

    # Score DDoS (0..10)
    score_final = score_from_ddos(
        abuse_json=abuse_json,
        sources=sources,
        requests_count=requests_count,
        rate=ratio
    )

    riesgo_text = clasificar_por_score_final(score_final)

    row_db = {
        "fecha": fecha,
        "hora": hora,
        "ip": ip,
        "codigo_pais": codigo_pais,
        "sources": sources,
        "requests": requests_count,
        "ratio": ratio,
        "as_owner": as_owner,
        "isp": isp,
        "vpn": vpn,  # True si VPN/Proxy/Tor (según IPQS)
        "abuse_confidence_raw": (abuse_json or {}).get("data", {}).get("abuseConfidenceScore")
            if isinstance(abuse_json, dict) else None,
        "score_final": score_final,
        "riesgo": riesgo_text
    }

    # CSV correcto para DDoS
    if save_csv:
        append_row_to_csv(row_db, attack_type="ddos")

    result_db = None
    if save_db:
        result_db = insert_alert_to_db(row_db, table_name="alertas_ddos", conn_params=conn_params)

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
            "vpn": vpn
        }
    }

# Compatibilidad con llamadas antiguas
def generate_dos_alert(ip_source: str = "any", bad_prob: float = 0.5,
                       save_csv: bool = True, save_db: bool = True, conn_params: Optional[dict] = None) -> Dict[str, Any]:
    from dos import generate_dos_alert as _dos_alert
    return _dos_alert(ip_source=ip_source, bad_prob=bad_prob, save_csv=save_csv, save_db=save_db, conn_params=conn_params)

def generate_alert(ip_source: str = "any", bad_prob: float = 0.5,
                   with_enrichment: bool = True, save_csv: bool = True, save_db: bool = True,
                   conn_params: Optional[dict] = None, attack: str = "ddos") -> Dict[str, Any]:
    a = (attack or "ddos").lower()
    if a == "dos":
        from dos import generate_dos_alert as _dos_alert
        return _dos_alert(ip_source=ip_source, bad_prob=bad_prob, save_csv=save_csv, save_db=save_db, conn_params=conn_params)
    else:
        return generate_ddos_alert(ip_source=ip_source, bad_prob=bad_prob, with_enrichment=with_enrichment,
                                   save_csv=save_csv, save_db=save_db, conn_params=conn_params)
