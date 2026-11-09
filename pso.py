"""Otimização por enxame de partículas (PSO) dos pesos de priorização de alertas.

Cada partícula é um vetor de pesos (um por característica). A aptidão é a AUC do
ranking (ameaças confirmadas acima dos IPs marcados como legítimos), menos uma
penalidade por se afastar dos pesos de partida, o que evita sobreajuste com poucos
exemplos.
"""
import random

LAMBDA = 0.3  # força da penalidade por distância aos pesos de partida


def pontuar(vetor, pesos):
    """Média ponderada das características (0..1), em escala 0..100."""
    soma = sum(pesos)
    if soma <= 1e-9:
        return 0.0
    return 100.0 * sum(w * f for w, f in zip(pesos, vetor)) / soma


def auc(pesos, amostras):
    """Chance de uma ameaça receber nota maior que um legítimo (empate vale 0,5)."""
    pos = [pontuar(v, pesos) for v, y in amostras if y == 1]
    neg = [pontuar(v, pesos) for v, y in amostras if y == 0]
    if not pos or not neg:
        return 0.5
    ganho = sum(1.0 if p > n else 0.5 if p == n else 0.0 for p in pos for n in neg)
    return ganho / (len(pos) * len(neg))


def _aptidao(pesos, amostras, base):
    soma = sum(pesos)
    if soma <= 1e-9:
        return -1.0
    dist = sum((w / soma - b) ** 2 for w, b in zip(pesos, base))
    return auc(pesos, amostras) - LAMBDA * dist


def otimizar(amostras, base, particulas=24, iteracoes=60, seed=None):
    """Devolve (pesos normalizados, aptidão). `amostras` = [(vetor, rotulo 0/1), ...]."""
    rng = random.Random(seed)
    dim = len(base)
    inercia, c1, c2, vmax = 0.72, 1.49, 1.49, 0.4  # coeficientes de constrição de Clerc

    pos = [[rng.random() for _ in range(dim)] for _ in range(particulas)]
    pos[0] = list(base)  # uma partícula nasce nos pesos atuais: nunca começa pior
    vel = [[rng.uniform(-0.1, 0.1) for _ in range(dim)] for _ in range(particulas)]
    melhor = [p[:] for p in pos]
    melhor_f = [_aptidao(p, amostras, base) for p in pos]
    g = max(range(particulas), key=melhor_f.__getitem__)
    gbest, gbest_f = melhor[g][:], melhor_f[g]

    for _ in range(iteracoes):
        for i in range(particulas):
            for d in range(dim):
                v = (inercia * vel[i][d]
                     + c1 * rng.random() * (melhor[i][d] - pos[i][d])
                     + c2 * rng.random() * (gbest[d] - pos[i][d]))
                vel[i][d] = max(-vmax, min(vmax, v))
                pos[i][d] = max(0.0, min(1.0, pos[i][d] + vel[i][d]))
            f = _aptidao(pos[i], amostras, base)
            if f > melhor_f[i]:
                melhor[i], melhor_f[i] = pos[i][:], f
                if f > gbest_f:
                    gbest, gbest_f = pos[i][:], f

    soma = sum(gbest) or 1.0
    return [w / soma for w in gbest], gbest_f