# app.py
import os
import sys
import traceback
import io
import csv
import random
import re
import unicodedata
from urllib.parse import quote
from datetime import datetime, date, time as time_type, timedelta, timezone
from decimal import Decimal
from flask import send_file, make_response
import informes

from flask import Flask, jsonify, send_from_directory, request, Response
import bd
from psycopg2 import sql

from flask_cors import CORS

app = Flask(__name__)
CORS(app)  

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.append(ROOT)

app = Flask(__name__, static_folder='.', static_url_path='/static')

@app.route("/")
def root_index():
    return send_from_directory('.', 'index.html')

_ATTACK_TO_TABLE = {
    "ddos": "alertas_ddos",
    "dos": "alertas_dos",
    "fuerza_bruta": "alertas_fuerza_bruta",
    "login_sospechoso": "alertas_login_sospechoso",
    "phishing": "alertas_phishing",
}

# ---------------- JSON-safe helpers ----------------
def _make_json_safe(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        # timezone-aware or naive -> ISO
        try:
            return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, time_type):
        return value.strftime("%H:%M:%S")
    if isinstance(value, Decimal):
        try:
            return float(value)
        except Exception:
            return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return bytes(value).decode("utf-8", errors="ignore")
        except Exception:
            return str(value)
    if isinstance(value, (list, tuple)):
        return [_make_json_safe(v) for v in value]
    if isinstance(value, dict):
        return {k: _make_json_safe(v) for k, v in value.items()}
    if not isinstance(value, (str, int, float, bool)):
        try:
            return str(value)
        except Exception:
            return None
    return value

def _sanitize_value(v):
    if v is None:
        return None
    if isinstance(v, dict):
        return {k: _sanitize_value(val) for k, val in v.items()}
    if isinstance(v, (list, tuple)):
        return [_sanitize_value(x) for x in v]
    return _make_json_safe(v)

# ---------------- Helper: mapa de estados (id -> codigo) ----------------
def _get_status_map():
    conn = bd._connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id_status, codigo FROM estado_alerta;")
            return {row[0]: row[1] for row in cur.fetchall()}
    finally:
        conn.close()

# ---------------- DB fetch helper (añadido filtro estado) ----------------
def _fetch_alerts_from_table_with_columns(table_name: str, client_id: int = None, limit: int = 20, start_date: date = None, status_code: str = None):
    try:
        conn = bd._connect()
        with conn.cursor() as cur:
            conditions = []
            params = []
            if client_id:
                conditions.append(sql.SQL("id_cliente = %s"))
                params.append(client_id)
            if start_date:
                conditions.append(sql.SQL("fecha >= %s"))
                params.append(start_date)
            if status_code:
                conditions.append(sql.SQL("id_status = (SELECT id_status FROM estado_alerta WHERE codigo=%s)"))
                params.append(status_code)

            where_clause = sql.SQL("")
            if conditions:
                where_clause = sql.SQL("WHERE ") + sql.SQL(" AND ").join(conditions)

            q = sql.SQL("SELECT * FROM {tbl} {where} ORDER BY fecha DESC NULLS LAST, hora DESC NULLS LAST LIMIT %s").format(
                tbl=sql.Identifier(table_name),
                where=where_clause
            )
            params.append(limit)
            cur.execute(q, tuple(params))
            rows = cur.fetchall()
            cols = [c[0] for c in cur.description]
        conn.close()

        result = []
        for r in rows:
            d = {}
            for i, col in enumerate(cols):
                val = r[i]
                if isinstance(val, (bytearray, bytes)):
                    try:
                        val = val.decode('utf-8', errors='ignore')
                    except Exception:
                        val = str(val)
                d[col] = val
            result.append(d)
        return result, cols
    except Exception:
        raise

# ---------------- Endpoints ----------------
@app.route("/api/clients", methods=["GET"])
def api_clients():
    try:
        conn = bd._connect()
        with conn.cursor() as cur:
            cur.execute("SELECT id_cliente, nombre FROM clientes ORDER BY nombre;")
            rows = cur.fetchall()
        conn.close()
        clients = [{"id": r[0], "nombre": r[1]} for r in rows]
        return jsonify({"ok": True, "clients": clients})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/attack-types", methods=["GET"])
def api_attack_types():
    candidates = ["tipos_ataques", "tipo_alerta", "tipo_ataque", "tipo_alerta"]
    conn = None
    try:
        conn = bd._connect()
        with conn.cursor() as cur:
            for tbl in candidates:
                try:
                    cur.execute(sql.SQL("SELECT id_tipo, codigo, descripcion FROM {tbl} ORDER BY id_tipo;").format(
                        tbl=sql.Identifier(tbl)
                    ))
                    rows = cur.fetchall()
                    types = [{"id": r[0], "codigo": r[1], "descripcion": r[2]} for r in rows]
                    return jsonify({"ok": True, "types": types})
                except Exception:
                    continue
        fallback = [
            {"id": 1, "codigo": "dos", "descripcion": "Denial of Service (DoS)"},
            {"id": 2, "codigo": "ddos", "descripcion": "Distributed DoS (DDoS)"},
            {"id": 3, "codigo": "fuerza_bruta", "descripcion": "Fuerza bruta"},
            {"id": 4, "codigo": "login_sospechoso", "descripcion": "Login sospechoso"},
            {"id": 5, "codigo": "phishing", "descripcion": "Phishing"}
        ]
        return jsonify({"ok": True, "types": fallback})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if conn:
            try: conn.close()
            except Exception: pass


@app.route("/api/report_by_id", methods=["GET"])
def api_report_by_id():
    """
    Devuelve PDF para una alerta concreta.
    Parámetros:
      - attack: 'dos'|'ddos'|'fuerza_bruta'|'login_sospechoso'|'phishing'
      - alert_id: id entero en su tabla
    """
    try:
        attack = (request.args.get("attack") or "").strip().lower()
        alert_id = request.args.get("alert_id", type=int)
        if not attack or alert_id is None:
            return jsonify({"ok": False, "error": "Parámetros 'attack' y 'alert_id' requeridos."}), 400

        path, fname = informes.generate_pdf_for_id(attack, alert_id)

        # envolvemos para poder añadir un header propio
        resp = make_response(send_file(
            path,
            as_attachment=True,
            download_name=fname,
            mimetype="application/pdf"
        ))
        resp.headers["X-Report-Filename"] = fname   # nombre explícito para el front
        return resp
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()}), 500
    

# ------ catálogo de estados
@app.route("/api/alert-status", methods=["GET"])
def api_alert_status():
    try:
        bd.ensure_catalogs()
        return jsonify({"ok": True, "status": bd.get_status_catalog()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/alerts", methods=["GET"])
def api_alerts_json():
    """
    Parámetros:
      - client_id (int)
      - attack (str) obligatorio
      - limit (int)
      - period (str): '24h','7d','1m','3m','6m','1y' o '10','20','50'
      - status (str): 'new' | 'processing' | 'finished'
    """
    try:
        client_id = request.args.get("client_id", type=int)
        attack = (request.args.get("attack") or "").strip().lower()
        limit = request.args.get("limit", default=20, type=int)
        period = (request.args.get("period") or "").strip().lower()
        status_code = (request.args.get("status") or "").strip().lower()

        if not attack:
            return jsonify({"ok": False, "error": "Parámetro 'attack' requerido"}), 400
        if attack not in _ATTACK_TO_TABLE:
            return jsonify({"ok": False, "error": f"Tipo de ataque desconocido: {attack}"}), 400

        # periodo -> start_date o limit
        start_date = None
        if period:
            if period in ("10", "20", "50"):
                limit = int(period)
            else:
                days_map = {"24h":1, "7d":7, "1m":30, "3m":90, "6m":180, "1y":365}
                if period in days_map:
                    start_dt = datetime.now(timezone.utc) - timedelta(days=days_map[period])
                    start_date = start_dt.date()

        table = _ATTACK_TO_TABLE[attack]
        alerts, columns = _fetch_alerts_from_table_with_columns(
            table, client_id=client_id, limit=limit, start_date=start_date, status_code=(status_code or None)
        )

        # ---- sustituir id_status por texto para la visualización ----
        status_map = _get_status_map()  # {1:'new', 2:'processing', 3:'finished', ...}
        for r in alerts:
            sid = r.get("id_status")
            r["id_status_txt"] = status_map.get(sid, str(sid) if sid is not None else None)
        display_columns = [("id_status_txt" if c == "id_status" else c) for c in columns]
        # --------------------------------------------------------------------

        safe_alerts = [_sanitize_value(row) for row in alerts]
        return jsonify({"ok": True, "count": len(safe_alerts), "columns": display_columns, "alerts": safe_alerts})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/api/alerts.csv", methods=["GET"])
def api_alerts_csv():
    try:
        client_id = request.args.get("client_id", type=int)
        attack = (request.args.get("attack") or "").strip().lower()
        limit = request.args.get("limit", default=10000, type=int)
        period = (request.args.get("period") or "").strip().lower()
        status_code = (request.args.get("status") or "").strip().lower()

        if not attack:
            return jsonify({"ok": False, "error": "Parámetro 'attack' requerido"}), 400
        if attack not in _ATTACK_TO_TABLE:
            return jsonify({"ok": False, "error": f"Tipo de ataque desconocido: {attack}"}), 400

        start_date = None
        if period:
            if period in ("10", "20", "50"):
                limit = int(period)
            else:
                days_map = {"24h":1, "7d":7, "1m":30, "3m":90, "6m":180, "1y":365}
                if period in days_map:
                    start_dt = datetime.now(timezone.utc) - timedelta(days=days_map[period])
                    start_date = start_dt.date()

        table = _ATTACK_TO_TABLE[attack]
        alerts, columns = _fetch_alerts_from_table_with_columns(
            table, client_id=client_id, limit=limit, start_date=start_date, status_code=(status_code or None)
        )

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        client_label = None
        if client_id:
            try:
                conn = bd._connect()
                with conn.cursor() as cur:
                    cur.execute("SELECT nombre FROM clientes WHERE id_cliente = %s", (client_id,))
                    row = cur.fetchone()
                conn.close()
                if row and row[0]:
                    client_name = str(row[0]).strip()
                    name_norm = unicodedata.normalize("NFKD", client_name)
                    name_ascii = name_norm.encode("ascii", "ignore").decode("ascii").lower()
                    client_label = re.sub(r'[^a-z0-9]+', '_', name_ascii).strip('_')
            except Exception:
                client_label = None
        if not client_label:
            client_label = f"cliente{client_id}" if client_id else "todos"

        attack_label = re.sub(r'[^a-z0-9]+', '_', attack).strip('_')
        filename = f"alertas_{client_label}_{attack_label}_{ts}.csv"

        if not alerts:
            csv_text = ""
            disposition = f'attachment; filename="{filename}"; filename*=UTF-8\'\'{quote(filename)}'
            return Response(csv_text, mimetype="text/csv", headers={"Content-Disposition": disposition})

        safe_rows = []
        for r in alerts:
            safe_rows.append({k: ("" if v is None else _make_json_safe(v)) for k, v in r.items()})

        fieldnames = columns if columns else list(safe_rows[0].keys())
        sio = io.StringIO()
        writer = csv.DictWriter(sio, fieldnames=fieldnames)
        writer.writeheader()
        for r in safe_rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})
        csv_text = sio.getvalue()
        sio.close()

        disposition = f'attachment; filename="{filename}"; filename*=UTF-8\'\'{quote(filename)}'
        return Response(csv_text, mimetype="text/csv", headers={"Content-Disposition": disposition})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/api/report", methods=["GET"])
def api_report_latest():
    """
    Descarga el informe PDF del último ataque para un tipo dado (y, opcionalmente, cliente).
    Parámetros:
      - attack: 'dos'|'ddos'|'fuerza_bruta'|'login_sospechoso'|'phishing' (obligatorio)
      - client_id: opcional (int) para filtrar por cliente
    """
    try:
        attack = (request.args.get("attack") or "").strip().lower()
        client_id = request.args.get("client_id", type=int)
        if not attack:
            return jsonify({"ok": False, "error": "Parámetro 'attack' requerido."}), 400

        path, fname = informes.generate_pdf_latest(attack, client_id)

        # Envolvemos para poder añadir header auxiliar con el nombre final
        resp = make_response(send_file(
            path,
            as_attachment=True,
            download_name=fname,
            mimetype="application/pdf"
        ))
        resp.headers["X-Report-Filename"] = fname
        return resp
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()}), 500


# -------- Simulate (modificado para devolver fila insertada y columnas)
@app.route("/api/simulate_attack", methods=["POST"])
def api_simulate_attack():
    try:
        data = request.get_json(force=True)
        client_id = data.get("client_id")
        attack = (data.get("attack") or "").strip().lower()
        if client_id is None or attack not in _ATTACK_TO_TABLE:
            return jsonify({"ok": False, "error": "client_id y attack (ddos|dos|fuerza_bruta|login_sospechoso|phishing) son obligatorios"}), 400

        table = _ATTACK_TO_TABLE[attack]

        ip = None
        try:
            ips = bd.fetch_ip_malas()
            if ips:
                ip = random.choice(ips) if isinstance(ips, list) else ips
        except Exception:
            ip = None
        if not ip:
            ip = random.choice(["1.1.1.1", "8.8.8.8", "9.9.9.9"])

        now = datetime.now(timezone.utc)
        fecha = now.date().isoformat()
        hora = now.time().strftime("%H:%M:%S")

        if attack == "dos":
            requests_cnt = random.choice([1000,2000,3000,4000,5000])
            ratio = random.choice(list(range(100,1001,100)))
            row = {"fecha": fecha, "hora": hora, "ip": ip, "codigo_pais": None,
                   "requests": requests_cnt, "ratio": ratio,
                   "as_owner": None, "isp": None, "vpn": False,
                   "abuse_confidence_raw": None, "score_final": None, "riesgo": None}
        elif attack == "ddos":
            sources = random.choice(list(range(300,1501,100)))
            requests_cnt = random.choice(list(range(10000,100001,5000)))
            ratio = random.choice(list(range(500,5001,100)))
            row = {"fecha": fecha, "hora": hora, "ip": ip, "codigo_pais": None,
                   "sources": sources, "requests": requests_cnt, "ratio": ratio,
                   "as_owner": None, "isp": None, "vpn": False,
                   "abuse_confidence_raw": None, "score_final": None, "riesgo": None}
        elif attack == "fuerza_bruta":
            intentos = random.choice([1000,2000,3000,4000,5000])
            ratio = random.choice(list(range(100,1001,100)))
            target = random.choice(["ssh","smd"])
            row = {"fecha": fecha, "hora": hora, "ip": ip, "codigo_pais": None,
                   "target": target, "intentos": intentos, "ratio": ratio,
                   "as_owner": None, "isp": None, "vpn": False,
                   "abuse_confidence_raw": None, "score_final": None, "riesgo": None}
        elif attack == "login_sospechoso":
            usuario = random.choice(["admin","root","test","guest"])
            intentos = random.randint(3, 12)
            duracion = random.randint(1, 600)
            ratio_intentos = round(intentos / max(1, duracion), 6)
            row = {"fecha": fecha, "hora": hora, "usuario": usuario,
                   "intentos": intentos, "duracion": duracion, "ratio_intentos": ratio_intentos,
                   "ip": ip, "login": "ssh", "pais": None, "isp": None, "uso": "aut",
                   "resultado_vt_raw": None, "score_vt": None, "score_abuse": None, "score_otx": None,
                   "score_final": None, "riesgo": None}
        elif attack == "phishing":
            url_val = None
            try:
                urls = bd.fetch_url_malas()
                if urls:
                    url_val = random.choice(urls) if isinstance(urls, list) else urls
            except Exception:
                url_val = None
            if not url_val:
                url_val = "http://example-phish.test/login"
            hostname = url_val
            row = {"fecha": fecha, "hora": hora, "ip": hostname, "url": url_val,
                   "score_final": None, "risk_level": None, "riesgo": None}
        else:
            return jsonify({"ok": False, "error": f"Tipo de ataque no soportado: {attack}"}), 400

        cliente_nombre = None
        try:
            conn = bd._connect()
            with conn.cursor() as cur:
                cur.execute("SELECT nombre FROM clientes WHERE id_cliente = %s", (client_id,))
                r = cur.fetchone()
            conn.close()
            if r:
                cliente_nombre = r[0]
        except Exception:
            cliente_nombre = None

        # --- Inserta y devuelve la fila insertada + columnas ---
        res = bd.insert_alert_to_db(row, table_name=table, cliente_nombre=cliente_nombre or client_id)

        if res.get("ok"):
            # res may contain raw 'row' with non-serializable types -> avoid returning it directly
            res_summary = {k: v for k, v in res.items() if k != "row"}
            inserted = res.get("row") or {}
            columns = res.get("columns") or []

            # normaliza valores para JSON (fechas, horas, Decimal, bytes...)
            if isinstance(inserted, dict):
                inserted_safe = {k: _make_json_safe(v) for k, v in inserted.items()}
            else:
                inserted_safe = inserted

            return jsonify({"ok": True, "res": res_summary, "inserted": inserted_safe, "columns": columns})
        else:
            # res may contain error string - safe to return
            return jsonify({"ok": False, "res": {"error": res.get("error", "unknown")}}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()}), 500

# ------ Guardar cambios de estado
@app.route("/api/alerts/update-status", methods=["POST"])
def api_update_status():
    """
    body: { "attack": "fuerza_bruta", "changes": [ { "id": 123, "action": "check"|"dismiss" }, ... ] }
    """
    try:
        data = request.get_json(force=True)
        attack = (data.get("attack") or "").strip().lower()
        changes = data.get("changes") or []
        if attack not in _ATTACK_TO_TABLE:
            return jsonify({"ok": False, "error": "attack inválido"}), 400
        table = _ATTACK_TO_TABLE[attack]
        res = bd.update_alert_status_bulk(table, changes)
        if "error" in res:
            return jsonify({"ok": False, "error": res["error"]}), 500
        return jsonify({"ok": True, **res})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
