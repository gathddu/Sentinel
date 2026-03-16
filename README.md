# Sentinel

**Sentinel** é um sistema de detecção de instrusão (IDS) production-ready que detecta ataques de rede e anomalias em sistemas em tempo real. Diferente das outras soluções comerciais, Sentinel é open-source, escalável e customizável.

Sentinel protege sua rede monitorando tráfego de rede e atividades de sistema em tempo real, detectando:

- **Ataques conhecidos** — SQL Injection, XSS, Path Traversal, Command Injection, SSRF
- **Port Scanning** — Detecção de varreduras de portas
- **Brute Force** — Tentativas de força bruta contra serviços
- **Comportamento anômalo** — Atividades suspeitas via Machine Learning
- **Movimentação lateral** — Movimento de atacante dentro da rede
- **Exfiltração de dados** — Transferências de dados suspeitas

## Características

### Detecção Multi-Camada

**Network-Based IDS (NIDS)**
- Captura de pacotes em tempo real com libpcap (Rust)
- Análise de protocolos (IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP)
- Motor de assinaturas com 50+ regras de ataque
- Detecção de anomalias com Machine Learning
- Correlação de eventos para identificar ataques compostos

**Host-Based IDS (HIDS)**
- Monitoramento de processos (criação, execução, encerramento)
- Detecção de comportamento suspeito de processos
- Monitoramento de arquivos críticos (modificação, acesso)
- Análise de logs do sistema
- Detecção de privilege escalation

### Performance e Escalabilidade

- **Processamento em tempo real** — Latência < 100 ms para detecção
- **Captura sem perda** — Procsesa 10 Gbps de tráfego por sensor
- **Escalabilidade horizontal** — Múltiplos sensores distribuídos
- **Armazenamento eficiente** — ClickHouse para bilhões de eventos
- **Consultas rápidas** — Análise de histórico em < 1 segundo

### Observabilidade

- **Dashboard em tempo real** — Grafana com métricas live
- **Histórico de eventos** — Investigação forense
- **Alertas configuráveis** — Email, Slack, webhook, syslog
- **Integração SIEM** — Compatível com Splunk, ELK, Sumo Logic
- **API REST** — Integração programática com outros sistemas

### DevOps

- **Docker** — Imagens otimizadas para cada componente
- **Kubernetes** — Deploy com Helm charts
- **CI/CD** — GitHub Actions com testes e segurança
- **Infraestrutura como Código** — Terraform, Ansible
- **Multiplataforma** — Linux, Windows, macOS

## Autores
- Jess (@gathddu)
- Shaka (@nkenshaka)