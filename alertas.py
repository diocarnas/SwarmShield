"""Perfis por IP de origem e alertas priorizados.

Cada IP de origem vira um vetor de 7 características (0..1) sobre os últimos
JANELA segundos. A nota do alerta é a média ponderada desse vetor; os pesos são
ajustados pelo PSO (pso.py) a partir do seu retorno (bloqueios e "legítimo").
"""
import ipaddress
import math
import threading
import time
from collections import Counter, deque
from functools import lru_cache

from pso import pontuar

JANELA = 60              # segundos analisados
AQUECIMENTO = 90         # segundos após iniciar sem alertas (a captura ainda não viu os dois sentidos)
MIN_PACOTES = 5          # origens com menos pacotes na janela são ignoradas
MAX_POR_ORIGEM = 2000
MAX_ORIGENS = 3000
TTL_CONTATO = 900        # um destino externo contatado por nós "responde" por 15 min
LIMIAR_MIN = 25          # nota mínima para aparecer
MAX_ALERTAS = 10

CARACTERISTICAS = ["taxa", "volume", "fanout", "proto_raro", "nao_solicitado", "pacotes_pequenos", "novidade"]
ROTULOS = {
    "taxa": "Taxa de pacotes alta",
    "volume": "Volume alto",
    "fanout": "Muitos destinos na rede local",
    "proto_raro": "Protocolo incomum",
    "nao_solicitado": "Tráfego externo não solicitado",
    "pacotes_pequenos": "Pacotes muito pequenos",
    "novidade": "Origem nova",
}
# Ponto de partida (heurístico); o PSO refina com o seu retorno
PESOS_PADRAO = [0.15, 0.10, 0.25, 0.15, 0.20, 0.10, 0.05]


@lru_cache(maxsize=50_000)
def _classe(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "outro"
    if a.is_multicast or a.is_unspecified or a.is_loopback or a.is_link_local:
        return "especial"
    return "local" if a.is_private else "externo"


def nivel(nota):
    return "alto" if nota >= 60 else "medio" if nota >= 40 else "baixo"


class Analisador:
    def __init__(self, fixos_ignorados=()):
        self.lock = threading.Lock()
        self.pacotes = {}        # origem -> deque[(ts, destino, protocolo, tamanho)]
        self.primeira_vez = {}   # origem -> ts (0.0 = já conhecida de execuções anteriores)
        self.contatados = {}     # destino externo -> ts do último pacote nosso enviado a ele
        self.ignorados = set(fixos_ignorados)
        self.fixos = set(fixos_ignorados)
        self.pesos = list(PESOS_PADRAO)
        self.info_pso = None
        self.inicio = time.time()
        self._poda = 0.0
        self._cache = (0.0, {})

    # --- entrada ---
    def conhecer(self, ips):
        with self.lock:
            for ip in ips:
                self.primeira_vez.setdefault(ip, 0.0)

    def registrar(self, ts, src, dst, proto, tam):
        with self.lock:
            if ts - self._poda > 10:
                self._podar(ts)
            if _classe(src) == "local" and _classe(dst) == "externo":
                self.contatados[dst] = ts
            d = self.pacotes.get(src)
            if d is None:
                if len(self.pacotes) >= MAX_ORIGENS:
                    return
                d = self.pacotes[src] = deque(maxlen=MAX_POR_ORIGEM)
                self.primeira_vez.setdefault(src, ts)
            d.append((ts, dst, proto, tam))

    def _podar(self, agora):
        self._poda = agora
        corte = agora - JANELA
        for s in [s for s, d in self.pacotes.items() if d[-1][0] < corte]:
            del self.pacotes[s]
        if len(self.contatados) > 20_000:
            self.contatados = {k: t for k, t in self.contatados.items() if t > agora - TTL_CONTATO}
        if len(self.primeira_vez) > 20_000:
            recentes = sorted(self.primeira_vez.items(), key=lambda kv: kv[1], reverse=True)[:10_000]
            self.primeira_vez = dict(recentes)

    # --- análise ---
    def _perfis(self, agora):
        if agora - self._cache[0] < 3:
            return self._cache[1]
        corte = agora - JANELA
        with self.lock:
            janela = {}
            for s, d in self.pacotes.items():
                v = [p for p in d if p[0] >= corte]
                if len(v) >= MIN_PACOTES:
                    janela[s] = v
            solicitados = {s for s in janela if self.contatados.get(s, 0.0) > agora - TTL_CONTATO}
            primeira = {s: self.primeira_vez.get(s, agora) for s in janela}

        total = sum(len(v) for v in janela.values())
        globais = Counter()
        for v in janela.values():
            globais.update(p[2] for p in v)
        raros = {pr for pr, c in globais.items() if total >= 200 and c / total < 0.01}

        perfis = {}
        for src, v in janela.items():
            n = len(v)
            volume = sum(p[3] for p in v)
            dur = max(5.0, min(JANELA, agora - v[0][0]))
            para_local = sum(1 for p in v if _classe(p[1]) == "local") / n
            destinos_locais = {p[1] for p in v if _classe(p[1]) == "local"}
            protos = Counter(p[2] for p in v)
            nao_sol = para_local if _classe(src) == "externo" and src not in solicitados else 0.0
            pv = primeira[src]
            novidade = 0.0 if pv == 0.0 else max(0.0, 1.0 - (agora - pv) / 1800)
            vetor = [
                min(1.0, math.log10(1 + n / dur) / 2),          # 100 pacotes/s -> 1
                min(1.0, math.log10(1 + volume) / 8),           # 100 MB na janela -> 1
                min(1.0, len(destinos_locais) / 20),            # 20 destinos locais -> 1
                sum(c for pr, c in protos.items() if pr in raros) / n,
                nao_sol,
                sum(1 for p in v if p[3] <= 70) / n,
                novidade,
            ]
            perfis[src] = {"vetor": vetor, "pacotes": n, "bytes": volume,
                           "protocolos": [p for p, _ in protos.most_common(2)]}
        self._cache = (agora, perfis)
        return perfis

    def vetor_de(self, ip):
        perfil = self._perfis(time.time()).get(ip)
        return perfil["vetor"] if perfil else None

    def alertas(self, bloqueados=()):
        agora = time.time()
        restante = AQUECIMENTO - (agora - self.inicio)
        if restante > 0:
            return [], int(restante) + 1
        with self.lock:
            pesos = list(self.pesos)
            ignorar = self.ignorados | set(bloqueados)
        soma = sum(pesos) or 1.0
        saida = []
        for ip, p in self._perfis(agora).items():
            if ip in ignorar:
                continue
            nota = pontuar(p["vetor"], pesos)
            if nota < LIMIAR_MIN:
                continue
            contrib = sorted(((100 * w * f / soma, nome) for w, f, nome in
                              zip(pesos, p["vetor"], CARACTERISTICAS)), reverse=True)
            saida.append({
                "ip": ip, "nota": round(nota, 1), "nivel": nivel(nota),
                "motivos": [ROTULOS[nome] for pts, nome in contrib[:3] if pts >= 3],
                "pacotes": p["pacotes"], "bytes": p["bytes"], "protocolos": p["protocolos"],
            })
        saida.sort(key=lambda a: a["nota"], reverse=True)
        return saida[:MAX_ALERTAS], 0

    # --- ajustes vindos do retorno do usuário ---
    def definir_pesos(self, pesos, info):
        with self.lock:
            self.pesos, self.info_pso = list(pesos), info

    def marcar(self, ip, rotulo):
        with self.lock:
            if rotulo == 0:
                self.ignorados.add(ip)
            elif ip not in self.fixos:
                self.ignorados.discard(ip)  