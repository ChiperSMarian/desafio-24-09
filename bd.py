# bd.py
import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor

# -------------------------------------------------------------------------
# Conexión
# -------------------------------------------------------------------------
def get_conn_params():
    """
    Usa .env con minúsculas (db_host, db_name, db_user, db_password, db_port, environment)
    """
    return {
        "host": os.getenv("db_host") or os.getenv("DB_HOST"),
        "dbname": os.getenv("db_name") or os.getenv("DB_NAME"),
        "user": os.getenv("db_user") or os.getenv("DB_USER"),
        "password": os.getenv("db_password") or os.getenv("DB_PASSWORD"),
        "port": int(os.getenv("db_port") or os.getenv("DB_PORT") or 5432),
        "sslmode": "require" if (os.getenv("environment") or "").lower() in {"prod", "production"} else os.getenv("sslmode", "prefer"),
    }

def _connect(conn_params=None):
    return psycopg2.connect(**(conn_params or get_conn_params()))

# -------------------------------------------------------------------------
# Esquema base y catálogos
# -------------------------------------------------------------------------
TIPOS = [
    ("dos", "Denial of Service (DoS)"),
    ("ddos", "Distributed Denial of Service (DDoS)"),
    ("fuerza_bruta", "Fuerza bruta"),
    ("login_sospechoso", "Login sospechoso"),
    ("phishing", "Phishing"),
]

ESTADOS = [
    ("new", "Alerta nueva"),
    ("processing", "Alerta en proceso"),
    ("finished", "Alerta resuelta"),
]

def ensure_catalogs(conn=None):
    close_at_end = False
    if conn is None:
        conn = _connect()
        close_at_end = True

    with conn.cursor() as cur:
        # clientes (si no lo tienes ya)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS clientes (
                id_cliente SERIAL PRIMARY KEY,
                nombre     TEXT NOT NULL UNIQUE,
                email      TEXT,
                password   TEXT,
                cif        VARCHAR(20),
                address    TEXT,
                url_photo  TEXT
            );
        """)

        # tipos_ataques
        cur.execute("""
            CREATE TABLE IF NOT EXISTS tipos_ataques (
                id_tipo SERIAL PRIMARY KEY,
                codigo  TEXT NOT NULL UNIQUE,
                descripcion TEXT
            );
        """)
        for cod, desc in TIPOS:
            cur.execute("""
                INSERT INTO tipos_ataques (codigo, descripcion)
                VALUES (%s, %s) ON CONFLICT (codigo) DO NOTHING;
            """, (cod, desc))

        # estado_alerta
        cur.execute("""
            CREATE TABLE IF NOT EXISTS estado_alerta (
                id_status   SERIAL PRIMARY KEY,
                codigo      TEXT NOT NULL UNIQUE,
                descripcion TEXT
            );
        """)
        for cod, desc in ESTADOS:
            cur.execute("""
                INSERT INTO estado_alerta (codigo, descripcion)
                VALUES (%s, %s) ON CONFLICT (codigo) DO NOTHING;
            """, (cod, desc))

    conn.commit()
    if close_at_end:
        conn.close()

def _id_tipo(conn, codigo: str) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT id_tipo FROM tipos_ataques WHERE codigo=%s;", (codigo,))
        r = cur.fetchone()
        if r: return r[0]
        cur.execute("INSERT INTO tipos_ataques (codigo) VALUES (%s) RETURNING id_tipo;", (codigo,))
        return cur.fetchone()[0]

def _id_status(conn, codigo: str) -> int:
    codigo = (codigo or "new").strip().lower()
    with conn.cursor() as cur:
        cur.execute("SELECT id_status FROM estado_alerta WHERE codigo=%s;", (codigo,))
        r = cur.fetchone()
        if r: return r[0]
        cur.execute("INSERT INTO estado_alerta (codigo) VALUES (%s) RETURNING id_status;", (codigo,))
        return cur.fetchone()[0]

def _id_cliente(conn, cliente_nombre_or_id):
    if isinstance(cliente_nombre_or_id, int):
        return cliente_nombre_or_id
    nombre = str(cliente_nombre_or_id).strip()
    with conn.cursor() as cur:
        cur.execute("SELECT id_cliente FROM clientes WHERE nombre=%s;", (nombre,))
        r = cur.fetchone()
        if r: return r[0]
        cur.execute("INSERT INTO clientes (nombre) VALUES (%s) RETURNING id_cliente;", (nombre,))
        return cur.fetchone()[0]

# -------------------------------------------------------------------------
# Tablas de alertas
# -------------------------------------------------------------------------
def ensure_alert_tables(conn=None):
    """
    Crea/actualiza las 5 tablas asegurando la columna id_status como FK a estado_alerta.
    """
    close_at_end = False
    if conn is None:
        conn = _connect()
        close_at_end = True

    with conn.cursor() as cur:
        # DOS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alertas_dos (
                id SERIAL PRIMARY KEY,
                id_cliente INTEGER NOT NULL REFERENCES clientes(id_cliente),
                id_tipo    INTEGER NOT NULL REFERENCES tipos_ataques(id_tipo),
                fecha DATE,
                hora  TIME,
                ip TEXT,
                codigo_pais TEXT,
                requests INTEGER,
                ratio INTEGER,
                as_owner TEXT,
                isp TEXT,
                vpn BOOLEAN,
                abuse_confidence_raw NUMERIC,
                score_final NUMERIC,
                riesgo TEXT,
                id_status INTEGER REFERENCES estado_alerta(id_status)
            );
        """)
        # DDoS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alertas_ddos (
                id SERIAL PRIMARY KEY,
                id_cliente INTEGER NOT NULL REFERENCES clientes(id_cliente),
                id_tipo    INTEGER NOT NULL REFERENCES tipos_ataques(id_tipo),
                fecha DATE,
                hora  TIME,
                ip TEXT,
                codigo_pais TEXT,
                sources INTEGER,
                requests INTEGER,
                ratio INTEGER,
                as_owner TEXT,
                isp TEXT,
                vpn BOOLEAN,
                abuse_confidence_raw NUMERIC,
                score_final NUMERIC,
                riesgo TEXT,
                id_status INTEGER REFERENCES estado_alerta(id_status)
            );
        """)
        # Fuerza Bruta
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alertas_fuerza_bruta (
                id SERIAL PRIMARY KEY,
                id_cliente INTEGER NOT NULL REFERENCES clientes(id_cliente),
                id_tipo    INTEGER NOT NULL REFERENCES tipos_ataques(id_tipo),
                fecha DATE,
                hora  TIME,
                ip TEXT,
                codigo_pais TEXT,
                target TEXT,
                intentos INTEGER,
                ratio INTEGER,
                as_owner TEXT,
                isp TEXT,
                vpn BOOLEAN,
                abuse_confidence_raw NUMERIC,
                score_final NUMERIC,
                riesgo TEXT,
                id_status INTEGER REFERENCES estado_alerta(id_status)
            );
        """)
        # Login Sospechoso
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alertas_login_sospechoso (
                id SERIAL PRIMARY KEY,
                id_cliente INTEGER NOT NULL REFERENCES clientes(id_cliente),
                id_tipo    INTEGER NOT NULL REFERENCES tipos_ataques(id_tipo),
                fecha DATE,
                hora  TIME,
                usuario TEXT,
                intentos INTEGER,
                duracion INTEGER,
                ratio_intentos NUMERIC,
                ip TEXT,
                login TEXT,
                pais TEXT,
                isp TEXT,
                uso TEXT,
                resultado_vt_raw TEXT,
                score_vt NUMERIC,
                score_abuse NUMERIC,
                score_otx NUMERIC,
                score_final NUMERIC,
                riesgo TEXT,
                id_status INTEGER REFERENCES estado_alerta(id_status)
            );
        """)
        # Phishing
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alertas_phishing (
                id SERIAL PRIMARY KEY,
                id_cliente INTEGER NOT NULL REFERENCES clientes(id_cliente),
                id_tipo    INTEGER NOT NULL REFERENCES tipos_ataques(id_tipo),
                fecha DATE,
                hora  TIME,
                ip TEXT,
                url TEXT,
                score_final NUMERIC,
                risk_level TEXT,
                riesgo TEXT,
                id_status INTEGER REFERENCES estado_alerta(id_status)
            );
        """)

    conn.commit()
    if close_at_end:
        conn.close()

# -------------------------------------------------------------------------
# Funciones de inserción (MODIFICADA para devolver la fila insertada y columnas)
# -------------------------------------------------------------------------
def insert_alert_to_db(row: dict, table_name: str, cliente_nombre):
    """
    Inserta en la tabla indicada. Asegura:
      - id_cliente desde nombre o id
      - id_tipo según table_name
      - id_status por defecto 'new' salvo que row['status'] se pase

    Devuelve:
      {"ok": True, "table": table_name, "id": new_id, "status": status_code, "row": {...}, "columns": [...]}
    o {"ok": False, "error": "..."}
    """
    conn = _connect()
    ensure_catalogs(conn)
    ensure_alert_tables(conn)

    try:
        id_cliente = _id_cliente(conn, cliente_nombre)
        id_tipo = _id_tipo(conn, table_name.replace("alertas_", ""))
        status_code = (row.get("status") or "new").strip().lower()
        id_status = _id_status(conn, status_code)

        base_cols = ["id_cliente", "id_tipo", "fecha", "hora", "id_status"]
        base_vals = [id_cliente, id_tipo, row.get("fecha"), row.get("hora"), id_status]

        per_table_cols = []
        if table_name == "alertas_dos":
            per_table_cols = ["ip","codigo_pais","requests","ratio","as_owner","isp","vpn",
                              "abuse_confidence_raw","score_final","riesgo"]
        elif table_name == "alertas_ddos":
            per_table_cols = ["ip","codigo_pais","sources","requests","ratio","as_owner","isp","vpn",
                              "abuse_confidence_raw","score_final","riesgo"]
        elif table_name == "alertas_fuerza_bruta":
            per_table_cols = ["ip","codigo_pais","target","intentos","ratio","as_owner","isp","vpn",
                              "abuse_confidence_raw","score_final","riesgo"]
        elif table_name == "alertas_login_sospechoso":
            per_table_cols = ["usuario","intentos","duracion","ratio_intentos","ip","login","pais","isp","uso",
                              "resultado_vt_raw","score_vt","score_abuse","score_otx","score_final","riesgo"]
        elif table_name == "alertas_phishing":
            per_table_cols = ["ip","url","score_final","risk_level","riesgo"]
        else:
            raise ValueError(f"Tabla no soportada: {table_name}")

        cols = base_cols + per_table_cols
        vals = base_vals + [row.get(k) for k in per_table_cols]

        placeholders = ", ".join(["%s"] * len(cols))
        q = f"INSERT INTO {table_name} ({', '.join(cols)}) VALUES ({placeholders}) RETURNING id;"
        with conn.cursor() as cur:
            cur.execute(q, vals)
            new_id = cur.fetchone()[0]
        conn.commit()

        # Recuperar la fila insertada completa y las columnas (orden)
        with conn.cursor() as cur:
            cur.execute(f"SELECT * FROM {table_name} WHERE id = %s;", (new_id,))
            fetched = cur.fetchone()
            cols_desc = [c[0] for c in cur.description]

        # transformar a dict
        row_dict = {}
        if fetched:
            for i, col in enumerate(cols_desc):
                val = fetched[i]
                # decode bytes si aplicable
                if isinstance(val, (bytearray, bytes)):
                    try:
                        val = val.decode('utf-8', errors='ignore')
                    except Exception:
                        val = str(val)
                row_dict[col] = val

        return {"ok": True, "table": table_name, "id": new_id, "status": status_code, "row": row_dict, "columns": cols_desc}
    except Exception as e:
        conn.rollback()
        return {"ok": False, "error": str(e)}
    finally:
        conn.close()

# -------------------------------------------------------------------------
# Listas de apoyo
# -------------------------------------------------------------------------
def fetch_ip_malas(limit: int = 100):
    """
    Devuelve lista de IPs desde tabla 'ip_malas' si existe.
    """
    conn = _connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM information_schema.tables WHERE table_name='ip_malas';")
            if not cur.fetchone():
                return []
            cur.execute("SELECT ip FROM ip_malas LIMIT %s;", (limit,))
            return [r[0] for r in cur.fetchall()]
    finally:
        conn.close()

def fetch_url_malas(limit: int = 100):
    conn = _connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM information_schema.tables WHERE table_name='url_malas';")
            if not cur.fetchone():
                return []
            cur.execute("SELECT url FROM url_malas LIMIT %s;", (limit,))
            return [r[0] for r in cur.fetchall()]
    finally:
        conn.close()

# -------------------------------------------------------------------------
# Estados: lectura y actualización
# -------------------------------------------------------------------------
def get_status_catalog():
    conn = _connect()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id_status, codigo, descripcion FROM estado_alerta ORDER BY id_status;")
            return list(cur.fetchall())
    finally:
        conn.close()

_ALLOWED = {
    "new": {"check": "processing", "dismiss": "finished"},
    "processing": {"dismiss": "finished"},
    "finished": {}
}

def update_alert_status_bulk(table_name: str, changes: list):
    """
    changes: [{ "id": <int>, "action": "check"|"dismiss" }]
    Aplica reglas:
      - new -> check => processing
      - new -> dismiss => finished
      - processing -> dismiss => finished
      - finished -> (no cambia)
    """
    if not changes:
        return {"updated": 0, "skipped": 0}

    conn = _connect()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # obtener estado actual de los ids
            ids = [int(c["id"]) for c in changes if "id" in c]
            cur.execute(f"SELECT id, id_status FROM {table_name} WHERE id = ANY(%s);", (ids,))
            current = {row["id"]: row["id_status"] for row in cur.fetchall()}

            # mapa id_status -> codigo
            cur.execute("SELECT id_status, codigo FROM estado_alerta;")
            id2code = {r["id_status"]: r["codigo"] for r in cur.fetchall()}
            code2id = {v: k for k, v in id2code.items()}

            updated = 0
            skipped = 0
            for c in changes:
                _id = int(c.get("id"))
                action = (c.get("action") or "").strip().lower()
                curr_id = current.get(_id)
                if curr_id is None:
                    skipped += 1
                    continue
                curr_code = id2code.get(curr_id, "new")
                target_code = _ALLOWED.get(curr_code, {}).get(action)
                if not target_code:
                    skipped += 1
                    continue
                target_id = code2id.get(target_code)
                cur.execute(f"UPDATE {table_name} SET id_status=%s WHERE id=%s;", (target_id, _id))
                updated += 1

        conn.commit()
        return {"updated": updated, "skipped": skipped}
    except Exception as e:
        conn.rollback()
        return {"error": str(e)}
    finally:
        conn.close()
