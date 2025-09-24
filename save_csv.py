# save_csv.py
"""
append_row_to_csv con soporte por tipo de ataque.

Funciones:
- append_row_to_csv(row, csv_file=None, attack_type=None, encoding='utf-8')
    Si se pasa attack_type se elige un CSV por tipo:
      'login'      -> reporte_alertas_login_sospechoso.csv
      'dos'        -> reporte_alertas_dos.csv
      'ddos'       -> reporte_alertas_ddos.csv
      'phishing'   -> reporte_alertas_phishing.csv
      'bruteforce' -> reporte_alertas_fuerza_bruta.csv
    Si se pasa csv_file explícito, tiene prioridad.
    Si no se pasa nada, usa DEFAULT_CSV o 'reporte_alertas.csv' en la carpeta del módulo.
- normalizea rutas para que funcione independientemente del cwd.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Dict, List, Union
import pandas as pd

DEFAULT_NAME = os.getenv("DEFAULT_CSV", "reporte_alertas.csv")
BASE_DIR = Path(__file__).resolve().parent

# Mapa por tipo -> nombre fichero
DEFAULT_FILENAMES = {
    "login": "reporte_alertas_login_sospechoso.csv",
    "dos": "reporte_alertas_dos.csv",            # <- añadido
    "ddos": "reporte_alertas_ddos.csv",
    "phishing": "reporte_alertas_phishing.csv",
    "bruteforce": "reporte_alertas_fuerza_bruta.csv",
}

def _normalize_csv_path(csv_file: Union[str, Path, None]) -> Path:
    if csv_file is None:
        return (BASE_DIR / DEFAULT_NAME).resolve()
    p = Path(csv_file)
    if not p.is_absolute():
        p = (BASE_DIR / p).resolve()
    return p

def append_row_to_csv(row: Union[Dict[str, Any], List[Dict[str, Any]]],
                      csv_file: Union[str, Path, None] = None,
                      attack_type: Union[str, None] = None,
                      encoding: str = "utf-8") -> Dict[str, Any]:
    """
    Añade una fila (o varias) a un CSV. Retorna dict con resultado.

    Parámetros:
      - row: dict o list[dict]
      - csv_file: ruta concreta (si se indica, tiene prioridad)
      - attack_type: 'login'|'dos'|'ddos'|'phishing'|'bruteforce' (elige CSV automático)
      - encoding: 'utf-8' por defecto

    Retorna:
      {"ok": True/False, "csv_file": ruta, "created": True/False, "error": mensaje}
    """
    try:
        # Determinar fichero objetivo
        if csv_file is None and attack_type:
            atk = (attack_type or "").lower()
            if atk in DEFAULT_FILENAMES:
                csv_file = DEFAULT_FILENAMES[atk]
            else:
                # si tipo desconocido, usar DEFAULT_NAME con sufijo tipo
                csv_file = f"reporte_alertas_{atk or 'otros'}.csv"

        target = _normalize_csv_path(csv_file)
        target_dir = target.parent
        if not target_dir.exists():
            target_dir.mkdir(parents=True, exist_ok=True)

        # Normalizar entrada
        if isinstance(row, dict):
            rows = [row]
        elif isinstance(row, list):
            if not all(isinstance(r, dict) for r in row):
                return {"ok": False, "csv_file": str(target), "created": False,
                        "error": "Si 'row' es lista, todos sus elementos deben ser dicts."}
            rows = row
        else:
            return {"ok": False, "csv_file": str(target), "created": False,
                    "error": "Argumento 'row' debe ser dict o list[dict]."}

        df = pd.DataFrame(rows)
        write_header = not target.exists()
        df.to_csv(target, mode="a", header=write_header, index=False, encoding=encoding)
        return {"ok": True, "csv_file": str(target), "created": write_header}
    except Exception as e:
        return {"ok": False, "csv_file": str(csv_file or (BASE_DIR / DEFAULT_NAME)), "created": False, "error": str(e)}

# Prueba rápida si se ejecuta standalone
if __name__ == "__main__":
    example = {
        "fecha": "2025-09-21",
        "hora": "09:47:06",
        "usuario": "root",
        "intentos": 15,
        "duracion": 336,
        "ratio_intentos": 15/336,
        "ip": "80.94.95.112",
        "login": "Fallido",
        "pais": "RO",
        "isp": "No disponible",
        "uso": "desconocido",
        "resultado_vt_raw": '{"malicious":16,"suspicious":1,"undetected":28,"harmless":50,"timeout":0}',
        "score_vt": 6.76,
        "score_abuse": 0.0,
        "score_otx": 0.0,
        "score_final": 6.16,
        "risk_level": "Medio"
    }
    print(append_row_to_csv(example, attack_type="login"))
