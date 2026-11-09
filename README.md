# SwarmShield

**Dashboard open source de monitoramento e segurança para redes
domésticas, com priorização inteligente de alertas utilizando Otimização
por Enxame de Partículas (PSO).**

O SwarmShield é uma ferramenta desenvolvida para monitorar o tráfego de
rede, identificar atividades suspeitas e facilitar a análise de
dispositivos conectados. Seu principal objetivo é reduzir a fadiga de
logs, priorizando alertas relevantes em vez de apresentar grandes
volumes de informações sem contexto.

A solução combina captura de pacotes, análise de tráfego, classificação
de endereços IP e otimização de pesos por meio de PSO.

## Visão geral

O projeto possui um dashboard web que centraliza informações importantes
sobre a rede, permitindo acompanhar o tráfego e analisar possíveis
ameaças em uma interface simples e intuitiva.

### Principais funcionalidades

-   **Monitoramento em tempo real:** captura e análise de pacotes IP da
    interface de rede selecionada.
-   **Análise de protocolos:** identificação e contabilização dos
    protocolos observados.
-   **Monitoramento de IPs:** identificação dos principais endereços de
    origem e acompanhamento de suas atividades.
-   **Priorização inteligente de alertas:** utilização de PSO para
    otimizar os pesos das características utilizadas na análise de
    ameaças.
-   **Classificação de IPs:** identificação de endereços como ameaças,
    legítimos ou não classificados.
-   **Mapa de calor:** visualização da atividade da rede por horário.
-   **Gerenciamento de bloqueios:** possibilidade de bloquear e liberar
    endereços IP por meio do firewall do Windows.
-   **Persistência de dados:** armazenamento de pacotes, bloqueios,
    feedbacks e pesos utilizados pelo analisador.

## Dashboard

O painel reúne indicadores e visualizações para facilitar o
acompanhamento da rede.

### Visualizações disponíveis

  -----------------------------------------------------------------------
  Visualização                        Objetivo
  ----------------------------------- -----------------------------------
  Tráfego em tempo real               Acompanhar a quantidade de pacotes
                                      e bytes

  Protocolos                          Identificar os protocolos mais
                                      frequentes

  Principais IPs                      Visualizar os endereços de origem
                                      com maior atividade

  Mapa de calor                       Identificar períodos de maior
                                      atividade

  Classificação de IPs                Comparar ameaças, legítimos e não
                                      classificados

  Alertas                             Acompanhar atividades consideradas
                                      suspeitas
  -----------------------------------------------------------------------

## Tecnologias utilizadas

  Tecnologia           Aplicação
  -------------------- -------------------------------------
  Python               Linguagem principal
  Flask                Backend e API REST
  PyShark              Captura e análise de pacotes
  TShark / Wireshark   Infraestrutura de captura de rede
  SQLite               Persistência dos dados
  JavaScript           Interatividade do dashboard
  HTML e CSS           Estrutura e interface
  Chart.js             Visualização de dados
  PSO                  Otimização dos pesos de priorização

## Como funciona o PSO?

O SwarmShield utiliza **Particle Swarm Optimization (PSO)**, ou
Otimização por Enxame de Partículas, para ajustar os pesos das
características utilizadas pelo analisador de alertas.

O processo utiliza exemplos previamente classificados como ameaças ou
legítimos.

O algoritmo busca encontrar uma combinação de pesos que melhore a
capacidade de distinção entre essas classes, utilizando a métrica AUC
para comparar o desempenho antes e depois da otimização.

**Fluxo simplificado:**

1.  O sistema captura os pacotes da rede.
2.  O analisador registra características associadas aos IPs.
3.  Os alertas são avaliados e priorizados.
4.  O usuário pode classificar um IP como ameaça ou legítimo.
5.  Os exemplos classificados são armazenados.
6.  O PSO utiliza esses exemplos para otimizar os pesos do analisador.

A otimização exige pelo menos dois exemplos de cada classe.

## Estrutura do projeto

``` text
SwarmShield/
│
├── app.py
├── alertas.py
├── database.py
├── pso.py
│
├── templates/
│   └── index.html
│
├── database/
│   └── swarmshield.db
│
└── README.md
```

> Observação: ajuste os nomes e diretórios acima conforme a estrutura
> real do seu repositório.

## Instalação

### 1. Pré-requisitos

-   Python 3.10 ou superior.
-   Wireshark instalado com o TShark.
-   Windows para utilizar as funcionalidades de bloqueio pelo `netsh`.
-   Permissão administrativa para captura e gerenciamento de regras do
    firewall.

### 2. Clone o repositório

``` bash
git clone https://github.com/SEU-USUARIO/SwarmShield.git
```

``` bash
cd SwarmShield
```

### 3. Instale as dependências

``` bash
pip install flask pyshark
```

### 4. Configure a interface de rede

No arquivo principal, localize:

``` python
INTERFACE = "Wi-Fi"
```

Altere o valor para a interface que deseja monitorar, por exemplo:

``` python
INTERFACE = "Ethernet"
```

### 5. Execute o projeto

Abra o terminal como administrador e execute:

``` bash
python app.py
```

Acesse o dashboard pelo navegador:

``` text
http://127.0.0.1:5000
```

## API REST

O backend disponibiliza endpoints para consulta de informações e
gerenciamento do monitoramento.

  Endpoint                 Método   Descrição
  ------------------------ -------- ----------------------------------------
  `/api/stats`             GET      Consulta estatísticas e tráfego
  `/api/alerts`            GET      Consulta alertas e informações do PSO
  `/api/alerts/legitimo`   POST     Marca um IP como legítimo
  `/api/pso/otimizar`      POST     Executa a otimização dos pesos
  `/api/pso/resetar`       POST     Restaura os pesos padrão
  `/api/mac`               POST     Consulta o endereço MAC de um IP local
  `/api/block`             POST     Bloqueia um endereço IP
  `/api/unblock`           POST     Remove o bloqueio de um endereço IP

## Segurança e limitações

O SwarmShield é um projeto experimental e educacional voltado ao
monitoramento de redes.

-   A captura depende da interface de rede selecionada e das permissões
    do sistema.
-   A classificação de ameaças depende das características observadas e
    dos exemplos fornecidos.
-   O PSO otimiza os pesos com base nos dados disponíveis; isso não
    garante detecção de todas as ameaças.
-   O bloqueio utiliza regras do Firewall do Windows e não substitui um
    firewall de rede dedicado.
-   O mapa de calor mantido em memória perde seu histórico quando o
    servidor é reiniciado.

**Importante:** o projeto não deve ser considerado uma solução completa
de segurança ou substituto de ferramentas profissionais de monitoramento
e proteção.

## Objetivos do projeto

-   Explorar a aplicação de algoritmos de otimização em segurança de
    redes.
-   Reduzir a fadiga de alertas por meio de priorização inteligente.
-   Facilitar a visualização e interpretação de dados de tráfego.
-   Aplicar conceitos de captura de pacotes, análise de dados e
    inteligência computacional.
-   Desenvolver uma ferramenta acessível para estudo e monitoramento de
    redes domésticas.

## Contribuição

Contribuições são bem-vindas!

1.  Faça um fork do projeto.
2.  Crie uma branch para sua funcionalidade.
3.  Realize suas alterações.
4.  Envie um Pull Request descrevendo as melhorias.

## Licença

Este projeto é open source. Adicione um arquivo `LICENSE` ao repositório
para definir formalmente os termos de uso e distribuição.

------------------------------------------------------------------------

**SwarmShield --- Monitoramento inteligente, priorização de ameaças e
segurança para redes domésticas.**
 
