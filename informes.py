# informes.py — PDF estilo ejemplo_1 (ReportLab) con márgenes simétricos,
# mitigaciones tras tabla, texto justificado con interlineado 1.5,
# y ESPACIADO ANTERIOR (12 pt) antes de los 5 títulos numerados solicitados.
# ---------------------------------------------------------------------------------

import os
import unicodedata
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas
from reportlab.lib import colors

import bd
import mitigaciones

ROOT = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(ROOT, "informes")
os.makedirs(OUTPUT_DIR, exist_ok=True)

_ATTACK_TO_TABLE = {
    "ddos": "alertas_ddos",
    "dos": "alertas_dos",
    "fuerza_bruta": "alertas_fuerza_bruta",
    "bruteforce": "alertas_fuerza_bruta",
    "login_sospechoso": "alertas_login_sospechoso",
    "phishing": "alertas_phishing",
}

def _slugify(s: str) -> str:
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return s.strip().lower().replace(" ", "_")

def _get_client_name_and_slug(client_id: Optional[int]) -> Tuple[str, str]:
    if not client_id:
        return "Desconocido", "desconocido"
    conn = bd._connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT nombre FROM clientes WHERE id_cliente = %s LIMIT 1;", (client_id,))
            row = cur.fetchone()
            if row and row[0]:
                name = str(row[0]).strip()
                return name, _slugify(name)
    finally:
        conn.close()
    return "Desconocido", "desconocido"

def _fetch_latest_alert(attack: str, client_id: Optional[int]):
    code = (attack or "").strip().lower()
    if code not in _ATTACK_TO_TABLE:
        raise ValueError(f"Tipo de ataque desconocido: {attack}")
    table = _ATTACK_TO_TABLE[code]
    conn = bd._connect()
    try:
        with conn.cursor() as cur:
            conds, params = [], []
            if client_id:
                conds.append("id_cliente = %s")
                params.append(client_id)
            where = ("WHERE " + " AND ".join(conds)) if conds else ""
            q = f"""
                SELECT * FROM {table}
                {where}
                ORDER BY fecha DESC NULLS LAST, hora DESC NULLS LAST, id DESC
                LIMIT 1;
            """
            cur.execute(q, tuple(params))
            row = cur.fetchone()
            if not row:
                return None, []
            cols = [c[0] for c in cur.description]
            return {cols[i]: row[i] for i in range(len(cols))}, cols
    finally:
        conn.close()

def _fetch_alert_by_id(attack: str, alert_id: int):
    code = (attack or "").strip().lower()
    if code not in _ATTACK_TO_TABLE:
        raise ValueError(f"Tipo de ataque desconocido: {attack}")
    table = _ATTACK_TO_TABLE[code]
    conn = bd._connect()
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT * FROM {table} WHERE id = %s LIMIT 1;", (alert_id,))
            row = cur.fetchone()
            if not row:
                return None, []
            cols = [c[0] for c in cur.description]
            return {cols[i]: row[i] for i in range(len(cols))}, cols
    finally:
        conn.close()

def _leer_mitigaciones_estructuradas(tipo_ataque: str) -> List[Tuple[str, str]]:
    try:
        if hasattr(mitigaciones, "leer_mitigaciones"):
            bloques = list(mitigaciones.leer_mitigaciones(tipo_ataque))
            if bloques and isinstance(bloques[0], (list, tuple)) and len(bloques[0]) == 2:
                return [(str(k), str(v)) for k, v in bloques]
    except Exception:
        pass
    out: List[Tuple[str, str]] = []
    try:
        raw = mitigaciones.get_mitigaciones(tipo_ataque)
        for line in (raw or "").splitlines():
            t = (line or "").strip()
            if not t:
                continue
            if len(t) < 60 and t == t.strip() and t[:1].isupper():
                out.append(("titulo", t))
            else:
                out.append(("parrafo", t))
    except Exception as e:
        out.append(("parrafo", f"Error leyendo mitigaciones: {e}"))
    return out

SECTION_COLOR = colors.HexColor("#1A237E")   # (26,35,126)
TITLE_COLOR   = colors.HexColor("#B71C1C")   # (183,28,28)

def _draw_title(c: canvas.Canvas, x: float, y: float, text: str):
    c.setFont("Helvetica-Bold", 22)
    c.setFillColor(TITLE_COLOR)
    c.drawString(x, y, text)
    text_w = c.stringWidth(text, "Helvetica-Bold", 22)
    c.setStrokeColor(TITLE_COLOR); c.setLineWidth(2)
    c.line(x, y - 4, x + text_w, y - 4)
    c.setFillColor(colors.black)

def _draw_subtitle(c: canvas.Canvas, x: float, y: float, text: str):
    c.setFont("Helvetica-Oblique", 11)
    c.setFillColor(colors.HexColor("#555555"))
    c.drawString(x, y, text)
    c.setFillColor(colors.black)

def _wrap_words_for_width(c: canvas.Canvas, words: List[str], max_w: float,
                          font="Helvetica", size=10) -> List[List[str]]:
    c.setFont(font, size)
    lines: List[List[str]] = []
    cur: List[str] = []
    def width_of(ws: List[str]) -> float:
        if not ws: return 0.0
        wsum = sum(c.stringWidth(w, font, size) for w in ws)
        spaces = max(0, len(ws) - 1)
        return wsum + spaces * c.stringWidth(" ", font, size)
    for w in words:
        if width_of(cur + [w]) <= max_w:
            cur.append(w)
        else:
            if cur: lines.append(cur)
            cur = [w]
    if cur: lines.append(cur)
    if not lines: lines = [[]]
    return lines

def _draw_justified_paragraph(c: canvas.Canvas, x: float, y: float, text: str, max_w: float,
                              font="Helvetica", size=10, leading=15) -> float:
    words = text.split()
    lines = _wrap_words_for_width(c, words, max_w, font=font, size=size)
    base_space = c.stringWidth(" ", font, size)
    for i, line_words in enumerate(lines):
        if not line_words:
            y -= leading; continue
        is_last = (i == len(lines) - 1)
        c.setFont(font, size)
        if is_last or len(line_words) == 1:
            c.drawString(x, y, " ".join(line_words))
        else:
            text_w = sum(c.stringWidth(w, font, size) for w in line_words)
            gaps = len(line_words) - 1
            extra_per_gap = (max_w - text_w - gaps * base_space) / gaps if gaps else 0.0
            cursor_x = x
            for j, w in enumerate(line_words):
                c.drawString(cursor_x, y, w)
                if j < gaps:
                    cursor_x += c.stringWidth(w, font, size) + base_space + max(0.0, extra_per_gap)
        y -= leading
    return y

def _draw_key_value_table(c: canvas.Canvas, x: float, y: float, col_w: float,
                          key: str, value: str, row_h: float = 16) -> float:
    c.setStrokeColor(colors.HexColor("#eeeeee"))
    c.setFillColor(colors.HexColor("#f7f7f7")); c.rect(x, y - row_h, col_w * 0.35, row_h, fill=1, stroke=1)
    c.setFillColor(colors.white); c.rect(x + col_w * 0.35, y - row_h, col_w * 0.65, row_h, fill=1, stroke=1)
    c.setFillColor(colors.black); c.setFont("Helvetica-Bold", 10)
    c.drawString(x + 6, y - row_h + 4, key); c.setFont("Helvetica", 10)

    max_w = col_w * 0.65 - 10
    words = str(value).split()
    lines = _wrap_words_for_width(c, words, max_w, font="Helvetica", size=10)
    needed_h = max(row_h, 4 + len(lines) * 12)
    if needed_h > row_h:
        c.setStrokeColor(colors.HexColor("#eeeeee"))
        c.setFillColor(colors.HexColor("#f7f7f7")); c.rect(x, y - needed_h, col_w * 0.35, needed_h, fill=1, stroke=1)
        c.setFillColor(colors.white); c.rect(x + col_w * 0.35, y - needed_h, col_w * 0.65, needed_h, fill=1, stroke=1)

    vy = y - 12
    for line_words in lines:
        c.drawString(x + col_w * 0.35 + 6, vy, " ".join(line_words))
        vy -= 12
    return y - needed_h - 10

def _draw_section_title(c: canvas.Canvas, x: float, y: float, text: str, size=14) -> float:
    c.setFont("Helvetica-Bold", size)
    c.setFillColor(SECTION_COLOR); c.drawString(x, y, text)
    text_w = c.stringWidth(text, "Helvetica-Bold", size)
    c.setStrokeColor(SECTION_COLOR); c.setLineWidth(1.2); c.line(x, y - 3, x + text_w, y - 3)
    c.setFillColor(colors.black)
    return y - 24

def _draw_footer(c: canvas.Canvas, page_num: int, width: float, client_name: str, ts_str: str, margin_lr: float):
    c.setFont("Helvetica", 9); c.setFillColor(colors.HexColor("#666666"))
    footer_text = f"Página {page_num} — {client_name} — {ts_str}"
    tw = c.stringWidth(footer_text, "Helvetica", 9)
    left_x = margin_lr; right_x = width - margin_lr
    center_x = left_x + (right_x - left_x - tw) / 2.0
    c.drawString(center_x, 1.5 * cm, footer_text)
    c.setFillColor(colors.black)

def _compose_pdf_from_row(attack: str, row: Dict[str, Any]) -> Tuple[str, str]:
    alert_id = row.get("id") or row.get("id_alerta") or "SIN_ID"
    client_id = row.get("id_cliente")
    client_name, client_slug = _get_client_name_and_slug(client_id)

    now = datetime.now()
    ts_file = now.strftime("%Y%m%d_%H%M%S")
    ts_footer = now.strftime("%d/%m/%Y %H:%M:%S")
    filename = f"informe_{client_slug}_{attack}_{alert_id}_{ts_file}.pdf"
    outpath = os.path.join(OUTPUT_DIR, filename)

    fecha = row.get("fecha") or ""
    hora = row.get("hora") or ""
    indicador = row.get("ip") or row.get("url") or ""
    usuario = row.get("usuario") or "N/A"
    pais = row.get("codigo_pais") or row.get("pais") or "N/A"
    riesgo = row.get("riesgo") or row.get("risk_level") or "N/A"
    score = row.get("score_final")
    try:
        score = f"{float(score):.2f}" if score is not None else "N/A"
    except Exception:
        score = str(score) if score is not None else "N/A"

    structured_lines: List[Tuple[str, str]] = []
    for kind, text in _leer_mitigaciones_estructuradas(attack):
        t = str(text).strip()
        if t: structured_lines.append((kind, t))

    def norm(s: str) -> str: return " ".join(s.lower().split())
    TITLE_NO_NUMBER = {norm("Mitigaciones clave contra DDoS")}
    TITLES_NUMBERED = {
        norm("Prevención en la capa de red / entrega"),
        norm("Prevención en la capa de correo / entrega"),
        norm("Prevención en la capa de autenticación"),
        norm("Educación y conciencia del equipo"),
        norm("Educación y concienciación del usuario"),
        norm("Educación y resistencia del usuario"),
        norm("Detección y enriquecimiento (Data / AI)"),
        norm("Respuesta y mitigación automatizada"),
        norm("Herramientas, procesos y gobernanza"),
        norm("Herramientas y procesos de soporte"),
        norm("Autenticación y seguridad de credenciales"),
        norm("Gestión y ciclo de vida de cuentas"),
        norm("Monitoreo y detección"),
    }

    c = canvas.Canvas(outpath, pagesize=A4)
    width, height = A4
    margin_lr = 2 * cm
    margin_tb = 2 * cm
    content_w = width - 2 * margin_lr
    cursor_y = height - margin_tb
    page_num = 1

    def new_page():
        nonlocal page_num, cursor_y
        _draw_footer(c, page_num, width, client_name, ts_footer, margin_lr)
        c.showPage(); page_num += 1
        cursor_y = height - margin_tb

    # Cabecera
    _draw_title(c, margin_lr, cursor_y, "Reporte de Incidente de Seguridad"); cursor_y -= 28
    _draw_subtitle(c, margin_lr, cursor_y, f"Generado el: {now.strftime('%d/%m/%Y a las %H:%M:%S')} para {client_name}")
    cursor_y -= 26

    # Detalles
    cursor_y = _draw_section_title(c, margin_lr, cursor_y, f"Detalles del Evento Detectado (Tipo: {attack.upper()})", size=14)
    rows = [
        ("ID del Incidente en BBDD:", str(alert_id)),
        ("Fecha/Hora:", f"{fecha} {hora}".strip()),
        ("Indicador (IP/URL):", str(indicador)),
        ("Usuario:", str(usuario)),
        ("País:", str(pais)),
        ("Nivel de Riesgo:", str(riesgo)),
        ("Score (0-10):", str(score)),
    ]
    for k, v in rows:
        if cursor_y < 4 * cm: new_page()
        cursor_y = _draw_key_value_table(c, margin_lr, cursor_y, content_w, k, v, row_h=18)

    # Separación tras tabla
    MIN_SPACE = 28
    if cursor_y - MIN_SPACE < 5 * cm: new_page()
    else: cursor_y -= MIN_SPACE

    # Mitigaciones
    cursor_y = _draw_section_title(c, margin_lr, cursor_y, "Estrategias de Mitigación Recomendadas", size=14)

    base_font_size = 10
    leading = int(base_font_size * 1.5)  # interlineado 1.5
    title_counter = 0

    for kind, text in structured_lines:
        if cursor_y < 3 * cm: new_page()

        if kind.lower() == "titulo":
            tnorm = norm(text)

            if tnorm in TITLE_NO_NUMBER:
                # "Mitigaciones clave contra DDoS" -> SIN numeración, negrita
                c.setFont("Helvetica-Bold", 12)
                c.drawString(margin_lr, cursor_y, text)
                cursor_y -= 16

            else:
                # Estos cinco títulos: numerados y con ESPACIADO ANTERIOR de 12pt
                if tnorm in TITLES_NUMBERED:
                    # Espaciado anterior solicitado (12 pt) antes del título
                    if cursor_y - 12 < 3 * cm:
                        new_page()
                    else:
                        cursor_y -= 12

                    title_counter += 1
                    label = f"{title_counter} - {text}"
                else:
                    label = text  # cualquier otro título no contemplado

                c.setFont("Helvetica-Bold", 12)
                c.drawString(margin_lr, cursor_y, label)
                cursor_y -= 16

        else:
            # párrafos justificados (12 pt de espaciado anterior ya añadido en versión previa)
            cursor_y -= 12
            cursor_y = _draw_justified_paragraph(
                c, margin_lr, cursor_y, text, content_w,
                font="Helvetica", size=base_font_size, leading=leading
            )
            cursor_y -= 2

    _draw_footer(c, page_num, width, client_name, ts_footer, margin_lr)
    c.save()
    return outpath, filename

def generate_pdf_latest(attack: str, client_id: Optional[int] = None) -> Tuple[str, str]:
    row, _ = _fetch_latest_alert(attack, client_id)
    if not row: raise RuntimeError("No hay alertas para los criterios indicados.")
    return _compose_pdf_from_row(attack, row)

def generate_pdf_for_id(attack: str, alert_id: int) -> Tuple[str, str]:
    row, _ = _fetch_alert_by_id(attack, alert_id)
    if not row: raise RuntimeError(f"No se encontró la alerta id={alert_id} para tipo {attack}")
    return _compose_pdf_from_row(attack, row)
