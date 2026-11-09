import asyncio
import ipaddress
import json
import os
import queue
import re
import subprocess
import threading
import time
from collections import Counter, deque
from urllib.parse import urlparse

import pyshark
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

import alertas
import database as db
import pso

# Carrega as configurações locais do arquivo .env (não publique esse arquivo).
load_dotenv()

# Configure NETWORK_INTERFACE e ROUTER_URL no arquivo .env.
INTERFACE = os.getenv("NETWORK_INTERFACE", "Wi-Fi").strip() or "Wi-Fi"
ROUTER_URL = os.getenv("ROUTER_URL", "").strip()

RECENT_LIMIT = 50      # pacotes exibidos na tabela
SERIES_SECONDS = 60    # janela do gráfico de tráfego
WINDOW = 120           # segundos de histórico mantidos em memória

app = Flask(__name__)

# --- Estado em memória (a API lê daqui, sem tocar no banco) ---
lock = threading.Lock()
recent = deque(maxlen=RECENT_LIMIT)
proto_counts = Counter()
src_counts = Counter()
totals = {"packets": 0, "bytes": 0}
buckets = {}  # segundo -> [pacotes, bytes]
# Atividade acumulada por dia da semana (0=segunda) e hora (0-23), desde a inicialização
heatmap_counts = [[0 for _ in range(24)] for _ in range(7)]
labels_by_ip = {}  # último rótulo conhecido: 1=ameaça, 0=legítimo
blocked = []
capture_state = {"error": None, "last": 0.0}
write_queue = queue.Queue(maxsize=100_000)

# Priorização de alertas (PSO): o roteador fica fora dos alertas
router_host = urlparse(ROUTER_URL).hostname if ROUTER_URL else None
analisador = alertas.Analisador(fixos_ignorados={router_host} if router_host else set())
retorno = {"ameacas": 0, "legitimos": 0}   # exemplos rotulados disponíveis para o PSO
pso_lock = threading.Lock()
PSO_MIN_POR_CLASSE = 2
PSO_MAX_AMOSTRAS = 200   # só os mais recentes: mantém a otimização em poucos segundos


def carregar_estado():
    db.init_db()
    protocols, sources, packets, size = db.load_summary()
    proto_counts.update(protocols)
    src_counts.update(sources)
    totals["packets"], totals["bytes"] = packets, size
    blocked.extend(db.list_blocked())
    recent.extend(db.load_recent(RECENT_LIMIT))  # tabela não começa vazia

    analisador.conhecer(src_counts.keys())
    for ip, rotulo, _ in db.load_feedback():   # o rótulo mais recente de cada IP vale
        analisador.marcar(ip, rotulo)
        labels_by_ip[ip] = int(rotulo)
    retorno["ameacas"] = sum(1 for rotulo in labels_by_ip.values() if rotulo == 1)
    retorno["legitimos"] = sum(1 for rotulo in labels_by_ip.values() if rotulo == 0)
    salvo = db.load_weights()
    if salvo:
        try:
            analisador.definir_pesos(json.loads(salvo[0]), json.loads(salvo[1]))
        except ValueError:
            pass


# --- Captura ---
def registrar(pkt):
    agora = time.time()
    # Pacote completo (como na primeira versão): levanta AttributeError se não for IP
    origem = pkt.ip.src
    destino = pkt.ip.dst
    proto = pkt.highest_layer
    tamanho = int(pkt.length)
    hora = time.strftime("%H:%M:%S", time.localtime(agora))
    sec = int(agora)

    local = time.localtime(agora)
    with lock:
        heatmap_counts[local.tm_wday][local.tm_hour] += 1
        recent.appendleft(
            {"horario": hora, "origem": origem, "destino": destino,
             "protocolo": proto, "tamanho": tamanho}
        )
        proto_counts[proto] += 1
        src_counts[origem] += 1
        if len(src_counts) > 5000:  # evita crescimento infinito
            keep = src_counts.most_common(1000)
            src_counts.clear()
            src_counts.update(dict(keep))
        totals["packets"] += 1
        totals["bytes"] += tamanho
        capture_state["last"] = agora
        capture_state["error"] = None

        b = buckets.get(sec)
        if b is None:
            b = buckets[sec] = [0, 0]
            for k in [k for k in buckets if k < sec - WINDOW]:
                del buckets[k]
        b[0] += 1
        b[1] += tamanho

    analisador.registrar(agora, origem, destino, proto, tamanho)

    try:
        write_queue.put_nowait((hora, origem, destino, proto, tamanho))
    except queue.Full:
        pass  # prefere descartar a travar a captura


def worker_captura():
    asyncio.set_event_loop(asyncio.new_event_loop())
    while True:
        try:
            capture = pyshark.LiveCapture(interface=INTERFACE, display_filter="ip")
            for pkt in capture.sniff_continuously():
                try:
                    registrar(pkt)
                except (AttributeError, ValueError):
                    continue
        except Exception as e:
            print(f"Erro no worker de captura: {e}. Tentando novamente em 3s...")
            capture_state["error"] = str(e)[:200]
            time.sleep(3)


# --- Escrita em lote no banco ---
def worker_escrita():
    conn = db.connect()
    ultima_poda = time.time()
    while True:
        batch = [write_queue.get()]
        time.sleep(0.5)  # junta pacotes para gravar numa única transação
        while len(batch) < 5000:
            try:
                batch.append(write_queue.get_nowait())
            except queue.Empty:
                break
        db.save_packets(conn, batch)
        if time.time() - ultima_poda > 60:
            db.prune(conn)
            ultima_poda = time.time()


def iniciar_workers():
    threading.Thread(target=worker_captura, daemon=True).start()
    threading.Thread(target=worker_escrita, daemon=True).start()


# --- Rotas da API REST ---
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def get_stats():
    agora = int(time.time())
    with lock:
        janela = range(agora - SERIES_SECONDS, agora)
        return jsonify({
            "packets": list(recent),
            "protocols": dict(proto_counts.most_common(8)),
            "top_sources": src_counts.most_common(6),
            "totals": dict(totals),
            "series": {
                "packets": [buckets.get(s, (0, 0))[0] for s in janela],
                "bytes": [buckets.get(s, (0, 0))[1] for s in janela],
            },
            "heatmap": [linha[:] for linha in heatmap_counts],
            "blocked": list(blocked),
            "interface": INTERFACE,
            "admin": is_admin(),
            "router_url": ROUTER_URL,
            "capture": {
                "error": capture_state["error"],
                "idle": (time.time() - capture_state["last"]) if capture_state["last"] else None,
            },
        })


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True  # fora do Windows não há como checar; deixa o netsh responder


def _ip_valido():
    data = request.get_json(silent=True) or {}
    try:
        return str(ipaddress.ip_address((data.get("ip") or "").strip()))
    except ValueError:
        return None


def _netsh(*args):
    # Lista de argumentos, sem shell=True: o IP vem do usuário e não pode virar comando
    return subprocess.run(
        ["netsh", "advfirewall", "firewall", *args],
        check=True, capture_output=True, text=True,
    )


MAC_RE = re.compile(r"[0-9a-fA-F]{2}([-:][0-9a-fA-F]{2}){5}")


def _mac_da_arp(ip):
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    for linha in out.splitlines():
        partes = linha.split()
        if len(partes) >= 2 and partes[0] == ip and MAC_RE.fullmatch(partes[1]):
            return partes[1].replace("-", ":").upper()
    return None


@app.route("/api/mac", methods=["POST"])
def get_mac():
    ip = _ip_valido()
    if not ip:
        return jsonify({"status": "error", "message": "Informe um endereço IP válido."}), 400
    if not ipaddress.ip_address(ip).is_private:
        return jsonify({"status": "error", "message": "O MAC só existe para IPs da rede local."}), 400

    mac = _mac_da_arp(ip)
    if not mac:
        # a tabela ARP só tem aparelhos que falaram com este PC há pouco: um ping a preenche
        try:
            subprocess.run(["ping", "-n", "1", "-w", "800", ip], capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        mac = _mac_da_arp(ip)
    if not mac:
        return jsonify({"status": "error",
                        "message": "MAC não encontrado. O aparelho pode estar desligado ou fora da sua rede local."}), 404
    return jsonify({"status": "success", "mac": mac})


@app.route("/api/block", methods=["POST"])
def block_ip():
    ip = _ip_valido()
    if not ip:
        return jsonify({"status": "error", "message": "Informe um endereço IP válido."}), 400

    if not is_admin():
        return jsonify({"status": "error",
                        "message": "Permissão negada. Execute o terminal como Administrador."}), 403

    try:
        _netsh("add", "rule", f"name=Bloqueio_Dash_{ip}", "dir=in",
               "action=block", f"remoteip={ip}")
    except subprocess.CalledProcessError as e:
        detalhe = (e.stdout or e.stderr or "").strip()[:200]
        return jsonify({"status": "error", "message": f"O netsh recusou o comando. {detalhe}"}), 500
    except FileNotFoundError:
        return jsonify({"status": "error",
                        "message": "netsh não encontrado. O bloqueio só funciona no Windows."}), 500

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    db.add_blocked(ip, ts)
    rotular(ip, 1)  # bloquear confirma a ameaça: vira exemplo para o PSO
    with lock:
        if not any(b["ip"] == ip for b in blocked):
            blocked.insert(0, {"ip": ip, "timestamp": ts})
    return jsonify({"status": "success", "message": f"IP {ip} bloqueado."})


# --- Alertas priorizados e PSO ---
def rotular(ip, rotulo):
    """Guarda o vetor de características do IP com o rótulo (1 = ameaça, 0 = legítimo)."""
    labels_by_ip[ip] = int(rotulo)
    analisador.marcar(ip, rotulo)
    vetor = analisador.vetor_de(ip)
    if vetor is None:  # sem atividade na janela: nada para aprender
        return False
    db.add_feedback(ip, rotulo, json.dumps(vetor), time.strftime("%Y-%m-%d %H:%M:%S"))
    retorno["ameacas" if rotulo else "legitimos"] += 1
    return True


def _estado_pso():
    return {
        "pesos": {n: round(w, 3) for n, w in zip(alertas.CARACTERISTICAS, analisador.pesos)},
        "rotulos": alertas.ROTULOS,
        "info": analisador.info_pso,
        "retorno": dict(retorno),
    }


@app.route("/api/alerts")
def get_alerts():
    with lock:
        bloqueados = {b["ip"] for b in blocked}
        ips_conhecidos = set(src_counts.keys())
    lista, aquecendo = analisador.alertas(bloqueados)

    # A classificação combina rótulos confirmados pelo usuário, bloqueios e alertas ativos.
    ameacas = {ip for ip, rotulo in labels_by_ip.items() if rotulo == 1}
    ameacas.update(bloqueados)
    ameacas.update(a["ip"] for a in lista)
    legitimos = {ip for ip, rotulo in labels_by_ip.items() if rotulo == 0} - ameacas
    nao_classificados = ips_conhecidos - ameacas - legitimos
    classificacao = {
        "ameacas": len(ameacas & ips_conhecidos),
        "legitimos": len(legitimos & ips_conhecidos),
        "nao_classificados": len(nao_classificados),
    }
    return jsonify({"alerts": lista, "aquecendo": aquecendo,
                    "classificacao": classificacao, **_estado_pso()})


@app.route("/api/alerts/legitimo", methods=["POST"])
def alert_legitimo():
    ip = _ip_valido()
    if not ip:
        return jsonify({"status": "error", "message": "Informe um endereço IP válido."}), 400
    rotular(ip, 0)
    return jsonify({"status": "success", "message": f"{ip} marcado como legítimo."})


@app.route("/api/pso/otimizar", methods=["POST"])
def pso_otimizar():
    amostras = []
    for _ip, rotulo, feats in db.load_feedback():
        try:
            v = json.loads(feats)
        except ValueError:
            continue
        if len(v) == len(alertas.CARACTERISTICAS):
            amostras.append((v, rotulo))
    amostras = amostras[-PSO_MAX_AMOSTRAS:]
    pos = sum(y for _, y in amostras)
    neg = len(amostras) - pos
    if pos < PSO_MIN_POR_CLASSE or neg < PSO_MIN_POR_CLASSE:
        return jsonify({"status": "error", "message":
            f"Faltam exemplos: preciso de {PSO_MIN_POR_CLASSE}+ IPs bloqueados e {PSO_MIN_POR_CLASSE}+ marcados como "
            f"legítimos (tenho {pos} e {neg})."}), 400
    if not pso_lock.acquire(blocking=False):
        return jsonify({"status": "error", "message": "Uma otimização já está em andamento."}), 409
    try:
        base = list(analisador.pesos)
        auc_antes = pso.auc(base, amostras)
        novos, _ = pso.otimizar(amostras, base)
        info = {"auc_antes": round(auc_antes, 3), "auc_depois": round(pso.auc(novos, amostras), 3),
                "amostras": len(amostras), "quando": time.strftime("%Y-%m-%d %H:%M:%S")}
        analisador.definir_pesos(novos, info)
        db.save_weights(json.dumps(novos), json.dumps(info), info["quando"])
    finally:
        pso_lock.release()
    return jsonify({"status": "success", "message":
        f"Pesos atualizados: AUC {info['auc_antes']:.2f} para {info['auc_depois']:.2f} em {info['amostras']} exemplos."})


@app.route("/api/pso/resetar", methods=["POST"])
def pso_resetar():
    analisador.definir_pesos(alertas.PESOS_PADRAO, None)
    db.clear_weights()
    return jsonify({"status": "success", "message": "Pesos padrão restaurados."})


@app.route("/api/unblock", methods=["POST"])
def unblock_ip():
    ip = _ip_valido()
    if not ip:
        return jsonify({"status": "error", "message": "Informe um endereço IP válido."}), 400

    try:
        _netsh("delete", "rule", f"name=Bloqueio_Dash_{ip}")
    except subprocess.CalledProcessError:
        return jsonify({"status": "error",
                        "message": "Não foi possível remover a regra. Execute como Administrador."}), 500
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "netsh não encontrado."}), 500

    db.remove_blocked(ip)
    with lock:
        blocked[:] = [b for b in blocked if b["ip"] != ip]
    return jsonify({"status": "success", "message": f"IP {ip} liberado."})


if __name__ == "__main__":
    carregar_estado()
    if not is_admin():
        print("AVISO: execute como Administrador para capturar pacotes e bloquear IPs.")
    iniciar_workers()
    # debug/reloader desligados: o reloader sobe o processo duas vezes e duplicaria a captura
    app.run(port=5000, debug=False, threaded=True)