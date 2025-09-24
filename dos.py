# dos.py
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import random
from datetime import datetime
from typing import Dict, Any, Optional

from bd import insert_alert_to_db
from save_csv import append_row_to_csv

from utils import (
    consultar_abuseipdb_ip,
    consultar_ipqs_ip,
    get_country_for_ip,
    get_network_enrichment,
    score_from_dos,
    clasificar_por_score_final,
)

# RANGOS (según tu especificación)
REQ_MIN, REQ_MAX, REQ_STEP   = 1000, 5000, 1000   # requests 1000..5000 paso 1000
RATE_MIN, RATE_MAX, RATE_STEP =  100, 1000, 100   # rate/s  100..1000 paso 100

def pick_ip_from_db(conn_params: Optional[dict] = None) -> str:
    """
    Lee la tabla ip_malas desde bd.fetch_ip_malas y devuelve 1 IP aleatoria.
    """
    try:
        from bd import fetch_ip_malas as _fetch
        ips = _fetch(conn_params=conn_params)
        if not ips:
            raise RuntimeError("No hay IPs en la tabla 'ip_malas'.")
        return random.choice(ips)
    except Exception as e:
        raise

def generate_dos_alert(
    ip_source: str = "any",
    bad_prob: float = 0.5,
    with_enrichment: bool = True,
    save_csv: bool = True,
    save_db: bool = True,
    conn_params: Optional[dict] = None
) -> Dict[str, Any]:
    """
    Genera una alerta DoS y la guarda opcionalmente en CSV y DB (tabla 'alertas_dos').

    Enriquecimiento (si with_enrichment):
      - AbuseIPDB -> abuseConfidenceScore (normalizado a 0..10 en utils.score_from_abuse)
      - ip-api.com -> countryCode (código país), isp, as/org (para as_owner)
      - IPQualityScore (IP) -> flags vpn/proxy/tor -> 'vpn' booleano

    Ponderación (0..10): Coef_DoS = 0.2*requests_norm + 0.3*rate_norm + 0.5*abuse_norm
    con redistribución si alguno de los tres es 0 para evitar infravalorar.
    """
    ip = pick_ip_from_db(conn_params=conn_params)
    now = datetime.now()
    fecha = now.strftime("%Y-%m-%d")
    hora = now.strftime("%H:%M:%S")

    # Rango y pasos especificados
    requests_count = random.choice(list(range(REQ_MIN, REQ_MAX + 1, REQ_STEP)))
    ratio = random.choice(list(range(RATE_MIN, RATE_MAX + 1, RATE_STEP)))

    abuse_json = None
    ipqs_ip_json = None

    if with_enrichment:
        abuse_json = consultar_abuseipdb_ip(ip)
        ipqs_ip_json = consultar_ipqs_ip(ip)  # puede ser None si no hay API key

    # País
    codigo_pais = get_country_for_ip(ip, abuse_json=abuse_json)

    # as_owner / isp / vpn
    net_enrich = get_network_enrichment(ip, vt_json=None, ipqs_json=ipqs_ip_json)
    as_owner = net_enrich.get("as_owner")
    isp = net_enrich.get("isp")
    vpn = net_enrich.get("vpn")

    # Score DoS 0..10
    score_final = score_from_dos(
        abuse_json=abuse_json,
        requests_count=requests_count,
        rate=ratio
    )

    riesgo_text = clasificar_por_score_final(score_final)

    row_db = {
        "fecha": fecha,
        "hora": hora,
        "ip": ip,
        "codigo_pais": codigo_pais,
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

    # ✅ Guardar en el CSV correcto para DoS
    if save_csv:
        append_row_to_csv(row_db, attack_type="dos")

    result_db = None
    if save_db:
        result_db = insert_alert_to_db(row_db, table_name="alertas_dos", conn_params=conn_params)

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
