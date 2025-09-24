# phishing.py
"""
Genera alertas de phishing tomando la URL desde la tabla 'url_malas'.
Calcula score con VT/IPQS y guarda en CSV y BD (alertas_phishing).
"""

import os
import sys
import random
import traceback
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from bd import insert_alert_to_db, fetch_url_malas  # usa url_malas de la BBDD
from save_csv import append_row_to_csv

try:
    from utils import consultar_virustotal_domain, consultar_ipqs_url, score_phishing_url
except Exception:
    consultar_virustotal_domain = None
    consultar_ipqs_url = None
    score_phishing_url = None


def _pick_url_from_db(conn_params: Optional[dict] = None) -> str:
    urls = fetch_url_malas(conn_params=conn_params)
    if not urls:
        raise RuntimeError("No hay URLs en la tabla 'url_malas'.")
    return random.choice(urls)


def generate_alert(
    with_enrichment: bool = True,
    save_csv: bool = True,
    save_db: bool = True,
    conn_params: Optional[dict] = None
) -> Dict[str, Any]:
    # ----------------- Selección URL desde BBDD -----------------
    url_a_analizar = _pick_url_from_db(conn_params=conn_params)
    hostname = urlparse(url_a_analizar).hostname or url_a_analizar

    # ----------------- Enriquecimiento -----------------
    vt_json = ipqs_json = None
    if with_enrichment:
        try:
            if consultar_virustotal_domain:
                vt_json = consultar_virustotal_domain(hostname)
        except Exception:
            traceback.print_exc()
        try:
            if consultar_ipqs_url:
                ipqs_json = consultar_ipqs_url(url_a_analizar)
        except Exception:
            traceback.print_exc()

    # ----------------- Scoring -----------------
    # score_phishing_url debe devolver float 0..10; si no existe, hacemos un fallback básico
    if score_phishing_url:
        score_final = score_phishing_url(vt_json, ipqs_json)
    else:
        score_final = 0.0
        try:
            # Heurística mínima si no hay util:
            vt_mal = 0
            if isinstance(vt_json, dict):
                vt_mal = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            ipqs_score = (ipqs_json or {}).get("risk_score", 0) if isinstance(ipqs_json, dict) else 0
            score_final = min(10.0, (vt_mal * 0.7) + (ipqs_score * 0.3))
        except Exception:
            pass

    if score_final >= 9.0:
        risk_level = "Crítico"
    elif score_final >= 7.0:
        risk_level = "Alto"
    elif score_final >= 4.0:
        risk_level = "Medio"
    elif score_final > 0:
        risk_level = "Bajo"
    else:
        risk_level = "Inofensivo"

    # Resumen corto VT/IPQS
    try:
        vt_malicious = "N/A"
        if isinstance(vt_json, dict) and "data" in vt_json:
            vt_malicious = vt_json["data"]["attributes"].get("last_analysis_stats", {}).get("malicious", "N/A")
    except Exception:
        vt_malicious = "N/A"
    try:
        ipqs_score = ipqs_json.get("risk_score", "N/A") if isinstance(ipqs_json, dict) else "N/A"
    except Exception:
        ipqs_score = "N/A"
    resumen_vt_ipqs = f"VT: M{vt_malicious}, IPQS: S{ipqs_score}"

    now = datetime.now()
    fecha = now.strftime('%Y-%m-%d')
    hora = now.strftime('%H:%M:%S')

    # ----------------- CSV -----------------
    alerta_para_csv = {
        "fecha": fecha,
        "hora": hora,
        "ip": hostname,               # mantenemos 'ip' como host/dominio para consistencia visual
        "url": url_a_analizar,
        "score_final": score_final,
        "risk_level": risk_level,
        "riesgo": resumen_vt_ipqs,    # renombrado de "resultado" -> "riesgo"
    }
    if save_csv:
        try:
            append_row_to_csv(alerta_para_csv, attack_type="phishing")
        except Exception:
            print("[phishing] Error guardando CSV:")
            traceback.print_exc()

    # ----------------- BD -----------------
    if save_db:
        try:
            # Tu tabla alertas_phishing tiene DEFAULT para fecha/hora, pero añadimos igualmente por claridad.
            row_db = {
                "fecha": fecha,
                "hora": hora,
                "ip": hostname,
                "url": url_a_analizar,
                "score_final": score_final,
                "risk_level": risk_level,
                "riesgo": resumen_vt_ipqs,   # <- bd.insert_alert_to_db espera 'riesgo'
            }
            res = insert_alert_to_db(row_db, table_name="alertas_phishing", conn_params=conn_params)
            if not res.get("ok"):
                print("[phishing] Error guardando en BD:", res.get("error"))
            else:
                print(f"[phishing] Insertado en BD con id={res.get('id')}")
        except Exception:
            print("[phishing] Excepción guardando en BD:")
            traceback.print_exc()

    return alerta_para_csv


if __name__ == "__main__":
    r = generate_alert(with_enrichment=False, save_csv=False, save_db=False)
    print(r)
