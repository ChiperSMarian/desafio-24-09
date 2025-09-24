# login.py
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import random
import traceback
from datetime import datetime
from typing import Dict, Any, Optional

from bd import insert_alert_to_db, fetch_ip_malas  # usa ip_malas de la BBDD
from save_csv import append_row_to_csv

# Helpers de enriquecimiento y scoring definidos en tu utils.py
try:
    from utils import (
        consultar_virustotal_ip,
        consultar_abuseipdb_ip,
        consultar_otx_ip,
        crear_alerta_final,   # construye score_vt/abuse/otx, score_final, risk_level, etc.
    )
except Exception:
    consultar_virustotal_ip = None
    consultar_abuseipdb_ip = None
    consultar_otx_ip = None
    crear_alerta_final = None

# Datos de demo
USUARIOS_DEMO = ["admin", "root", "test", "guest", "operador", "soporte"]
SERVICIOS_DEMO = ["ssh", "web", "vpn", "smb"]

# Fallbacks locales si la BBDD no responde
FALLBACK_BAD_IPS = ["45.155.205.233", "185.220.101.1", "89.248.165.72", "5.188.206.130", "141.98.10.60"]
FALLBACK_GOOD_IPS = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "9.9.9.9", "208.67.222.222"]


def _fallback_ip(ip_source: str = "any") -> str:
    s = (ip_source or "any").lower()
    if s == "bad":
        pool = FALLBACK_BAD_IPS
    elif s == "good":
        pool = FALLBACK_GOOD_IPS
    else:
        pool = FALLBACK_BAD_IPS + FALLBACK_GOOD_IPS
    return random.choice(pool) if pool else "8.8.8.8"


def _pick_ip_from_db(conn_params: Optional[dict] = None, ip_source: str = "any") -> str:
    """
    Intenta leer una IP de la tabla ip_malas. Si no hay/da error, usa fallback.
    """
    try:
        ips = fetch_ip_malas(conn_params=conn_params)
        if not ips:
            raise RuntimeError("No hay IPs en la tabla 'ip_malas'.")
        return random.choice(ips)
    except Exception as e:
        print(f"[login] Aviso: fallo leyendo 'ip_malas' de la BBDD, usando fallback local. Detalle: {e}")
        return _fallback_ip(ip_source)


def generate_alert(
    ip_source: str = "any",          # compatibilidad con app.py
    bad_prob: float = 0.5,           # compatibilidad (no se usa aquí)
    with_enrichment: bool = True,
    save_csv: bool = True,
    save_db: bool = True,
    conn_params: Optional[dict] = None
) -> Dict[str, Any]:
    """
    Genera una alerta de login sospechoso:
    - IP tomada de la tabla ip_malas (si falla, fallback).
    - Enriquecimiento opcional VT/Abuse/OTX via utils.
    - Guarda CSV y BD (tabla alertas_login_sospechoso).
    """
    # ----------------- Generación base -----------------
    ip = _pick_ip_from_db(conn_params=conn_params, ip_source=ip_source)
    usuario = random.choice(USUARIOS_DEMO)
    servicio = random.choice(SERVICIOS_DEMO)  # lo guardamos en el campo 'login'
    intentos = random.randint(3, 20)
    duracion = random.randint(1, 600)  # seg
    ratio_intentos = round(intentos / max(1, duracion), 4)

    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    fecha = now.strftime("%Y-%m-%d")
    hora = now.strftime("%H:%M:%S")

    alerta_base = {
        "timestamp": timestamp,
        "usuario": usuario,
        "intentos": intentos,
        "duracion": duracion,
        "ip": ip,
        "login": servicio,
        "uso": "aut"  # etiqueta opcional
    }

    # ----------------- Enriquecimiento -----------------
    vt_json = abuse_json = otx_json = None
    if with_enrichment:
        try:
            if consultar_virustotal_ip:
                vt_json = consultar_virustotal_ip(ip)
        except Exception:
            traceback.print_exc()
        try:
            if consultar_abuseipdb_ip:
                abuse_json = consultar_abuseipdb_ip(ip)
        except Exception:
            traceback.print_exc()
        try:
            if consultar_otx_ip:
                otx_json = consultar_otx_ip(ip)
        except Exception:
            traceback.print_exc()

    # Construye métricas finales (score_vt/abuse/otx, score_final, risk_level, etc.)
    if crear_alerta_final:
        alerta_final = crear_alerta_final(alerta_base, vt_json=vt_json, abuse_json=abuse_json, otx_json=otx_json)
    else:
        alerta_final = dict(alerta_base)
        alerta_final.update({
            "score_vt": None, "score_abuse": None, "score_otx": None,
            "score_final": None, "risk_level": None
        })

    # ----------------- CSV -----------------
    if save_csv:
        try:
            csv_row = dict(alerta_final)
            csv_row.update({
                "fecha": fecha,
                "hora": hora,
                "usuario": usuario,
                "login": servicio,
                "intentos": intentos,
                "duracion": duracion,
                "ratio_intentos": ratio_intentos,
                "ip": ip,
                "riesgo": csv_row.pop("risk_level", None),  # renombre para CSV
            })
            # Si tu append_row_to_csv espera (row, attack_type="login"):
            append_row_to_csv(csv_row, attack_type="login")
        except Exception:
            print("[login] Error guardando CSV:")
            traceback.print_exc()

    # ----------------- BD -----------------
    if save_db:
        try:
            row_db = {
                "fecha": fecha,
                "hora": hora,
                "usuario": usuario,
                "intentos": intentos,
                "duracion": duracion,
                "ratio_intentos": ratio_intentos,
                "ip": ip,
                "login": servicio,
                # campos opcionales si tu crear_alerta_final los aporta
                "pais": alerta_final.get("pais"),
                "isp": alerta_final.get("isp"),
                "uso": alerta_final.get("uso") or "aut",
                "resultado_vt_raw": alerta_final.get("resultado_vt_raw"),
                "score_vt": alerta_final.get("score_vt"),
                "score_abuse": alerta_final.get("score_abuse"),
                "score_otx": alerta_final.get("score_otx"),
                "score_final": alerta_final.get("score_final"),
                "riesgo": alerta_final.get("risk_level"),
            }
            res = insert_alert_to_db(row_db, table_name="alertas_login_sospechoso", conn_params=conn_params)
            if not res.get("ok"):
                print("[login] Error guardando en BD:", res.get("error"))
            else:
                print(f"[login] Insertado en BD con id={res.get('id')}")
        except Exception:
            print("[login] Excepción guardando en BD:")
            traceback.print_exc()

    # Lo que devuelve app.py al front
    # Devolvemos la alerta con fecha/hora añadidas para facilitar la UI
    alerta_ui = dict(alerta_final)
    alerta_ui.update({"fecha": fecha, "hora": hora})
    return alerta_ui


if __name__ == "__main__":
    r = generate_alert(with_enrichment=False, save_csv=False, save_db=False)
    print(r)
