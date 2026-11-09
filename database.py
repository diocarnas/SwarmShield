import sqlite3
from contextlib import closing

DB_NAME = "network_monitor.db"
MAX_ROWS = 200_000  # limite de pacotes mantidos no banco


def connect():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    # WAL + synchronous NORMAL: gravações muito mais rápidas sem travar leituras
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    with closing(connect()) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                length INTEGER
            );
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                timestamp TEXT
            );
            CREATE TABLE IF NOT EXISTS alert_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                label INTEGER,        -- 1 = ameaça (bloqueado), 0 = legítimo
                features TEXT,        -- vetor de características (JSON) no momento do rótulo
                timestamp TEXT
            );
            CREATE TABLE IF NOT EXISTS pso_weights (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                weights TEXT,
                info TEXT,
                timestamp TEXT
            );
        """)
        conn.commit()


def save_packets(conn, rows):
    """Grava vários pacotes de uma vez (uma transação só)."""
    conn.executemany(
        "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()


def prune(conn):
    """Mantém só os MAX_ROWS pacotes mais recentes."""
    conn.execute(
        "DELETE FROM packets WHERE id <= (SELECT MAX(id) FROM packets) - ?", (MAX_ROWS,)
    )
    conn.commit()


def load_summary():
    """Lido uma única vez na inicialização para popular os contadores em memória."""
    with closing(connect()) as conn:
        protocols = dict(conn.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol"))
        sources = dict(conn.execute(
            "SELECT src_ip, COUNT(*) c FROM packets GROUP BY src_ip ORDER BY c DESC LIMIT 500"
        ))
        packets, size = conn.execute("SELECT COUNT(*), COALESCE(SUM(length), 0) FROM packets").fetchone()
    return protocols, sources, packets, size


def list_blocked():
    with closing(connect()) as conn:
        rows = conn.execute("SELECT ip, timestamp FROM blocked_ips ORDER BY id DESC").fetchall()
    return [{"ip": r[0], "timestamp": r[1]} for r in rows]


def add_blocked(ip, timestamp):
    with closing(connect()) as conn:
        conn.execute("INSERT OR IGNORE INTO blocked_ips (ip, timestamp) VALUES (?, ?)", (ip, timestamp))
        conn.commit()


def remove_blocked(ip):
    with closing(connect()) as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        conn.commit()


def load_recent(limit):
    """Últimos pacotes gravados, mais novos primeiro (para a tabela não iniciar vazia)."""
    with closing(connect()) as conn:
        rows = conn.execute(
            "SELECT timestamp, src_ip, dst_ip, protocol, length FROM packets ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [{"horario": r[0], "origem": r[1], "destino": r[2], "protocolo": r[3], "tamanho": r[4]} for r in rows]


# --- Retorno do usuário e pesos do PSO ---
MAX_FEEDBACK = 2000


def add_feedback(ip, label, features_json, timestamp):
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO alert_feedback (ip, label, features, timestamp) VALUES (?, ?, ?, ?)",
            (ip, label, features_json, timestamp),
        )
        conn.execute(
            "DELETE FROM alert_feedback WHERE id <= (SELECT MAX(id) FROM alert_feedback) - ?", (MAX_FEEDBACK,)
        )
        conn.commit()


def load_feedback():
    """[(ip, rotulo, features_json), ...] do mais antigo ao mais novo."""
    with closing(connect()) as conn:
        return conn.execute("SELECT ip, label, features FROM alert_feedback ORDER BY id").fetchall()


def save_weights(weights_json, info_json, timestamp):
    with closing(connect()) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO pso_weights (id, weights, info, timestamp) VALUES (1, ?, ?, ?)",
            (weights_json, info_json, timestamp),
        )
        conn.commit()


def load_weights():
    with closing(connect()) as conn:
        return conn.execute("SELECT weights, info FROM pso_weights WHERE id = 1").fetchone()


def clear_weights():
    with closing(connect()) as conn:
        conn.execute("DELETE FROM pso_weights")
        conn.commit()