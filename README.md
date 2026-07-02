# 🔍 Argus — Verificador de Domínios e URLs Maliciosos

> *Na mitologia grega, Argus Panoptes era o gigante de 100 olhos — nunca dormia, observava tudo ao mesmo tempo. Esta ferramenta observa domínios e URLs de múltiplas fontes simultaneamente.*

Argus é uma ferramenta de verificação de domínios e URLs maliciosos. Consulta três fontes de Threat Intelligence em paralelo, agrega os resultados num veredito único e oferece monitoramento contínuo automático com alertas no Slack — tudo com cache inteligente para respeitar os limites das APIs gratuitas.

---

## ✨ Funcionalidades

- **Verificação sob demanda** — domínio puro (`evil.com`) ou URL completa (`https://evil.com/phishing`)
- **3 fontes de Threat Intelligence** consultadas por verificação
- **Veredito agregado** com score: LIMPO / ATENÇÃO / SUSPEITO / CRÍTICO
- **Cache inteligente de 6h** — evita rebater nas APIs para alvos consultados recentemente
- **Monitoramento contínuo** — lista de alvos verificada automaticamente via GitHub Actions (cron 12h)
- **Alertas no Slack** para alvos SUSPEITO e CRÍTICO
- **Dashboard Gradio** com três abas: verificação, monitoramento e histórico

---

## 🔍 Fontes de Verificação

| Fonte | Especialidade | Autenticação |
|-------|--------------|--------------|
| **URLhaus (abuse.ch)** | Malware distribution | Auth-Key gratuita |
| **OpenPhish** | Phishing feed | Pública (sem key) |
| **VirusTotal** | Multi-engine (70+ scanners) | API Key gratuita |

---

## 📊 Sistema de Veredito

Cada fonte retorna um status independente (`malicioso`, `suspeito`, `limpo`, `erro`). O motor agrega os resultados:

| Score | Veredito |
|-------|---------|
| 0 | 🟢 LIMPO |
| 1 | 🟠 ATENÇÃO |
| 2-3 | 🟡 SUSPEITO |
| 4+ | 🔴 CRÍTICO |

---

## 🗂️ Estrutura do Projeto

```
argus/
├── .github/workflows/monitor.yml  # GitHub Actions — verifica monitorados (cron 12h)
├── db.py                          # Postgres — cache de resultados + lista monitorada
├── sources.py                     # Consultas às 3 fontes
├── checker.py                     # Motor de verificação e agregação de veredito
├── monitor.py                     # Script standalone para o GitHub Actions
├── app.py                         # Dashboard Gradio
├── requirements.txt
└── .env.example
```

---

## 🚀 Como Rodar Localmente

**Pré-requisitos:** Python 3.11+, conta no [Neon](https://neon.tech) (Postgres gratuito)

```bash
git clone https://github.com/SEU_USUARIO/argus
cd argus
pip install -r requirements.txt
cp .env.example .env
# Preencha o .env com suas credenciais
python app.py
```

**Variáveis de ambiente necessárias:**

| Variável | Descrição | Onde obter |
|----------|-----------|------------|
| `DATABASE_URL` | Connection string do Postgres | [neon.tech](https://neon.tech) |
| `VIRUSTOTAL_API_KEY` | API Key do VirusTotal | [virustotal.com](https://www.virustotal.com) |
| `URLHAUS_AUTH_KEY` | Auth-Key do abuse.ch | [auth.abuse.ch](https://auth.abuse.ch) |
| `SLACK_WEBHOOK_URL` | Webhook para alertas | [api.slack.com/apps](https://api.slack.com/apps) |

> Todas as APIs usadas têm tier gratuito. Nenhuma chave paga necessária.

---

## ⚙️ Automação via GitHub Actions

O workflow `monitor.yml` roda automaticamente a cada 12h e verifica todos os alvos da lista de monitorados. O intervalo de 12h foi escolhido pra respeitar o limite gratuito do VirusTotal (500 req/dia, 4 req/min).

Para disparar manualmente: **Actions → Monitor Argus → Run workflow**

---

## 🏗️ Infraestrutura

| Componente | Serviço | Custo |
|------------|---------|-------|
| Banco de dados | Neon (Postgres gerenciado) | Gratuito |
| Automação | GitHub Actions | Gratuito |
| Dashboard | Hugging Face Spaces | Gratuito |

**Custo total de infraestrutura: $0**

---

## 🔗 Projetos Relacionados

Este projeto faz parte de uma trilha de SOC tooling:

- [**Sentinela SOC**]([https://github.com/SEU_USUARIO/sentinela-soc](https://github.com/LucasFalavinhaFerreira/sentinela-soc)) — Pipeline de Threat Intelligence: coleta 7 feeds públicos de IPs maliciosos, enriquece via AbuseIPDB, persiste em Postgres e alerta via Slack. Automação via GitHub Actions (cron 6h).
- **Argus** ← você está aqui
- [**Huginn**](https://github.com/LucasFalavinhaFerreira/Huginn) — Playbook de investigação de IOC: IP, domínio, URL e hash com mapeamento automático de TTPs do MITRE ATT&CK e geração de relatório HTML.

---

## ⚠️ Aviso Legal

Este projeto usa exclusivamente APIs e feeds públicos de Threat Intelligence para fins educacionais e de portfólio pessoal. As APIs do VirusTotal têm termos de uso próprios — consulte-os antes de usar em ambiente corporativo ou comercial.

---

*Desenvolvido por [Lucas Falavinha Ferreira](https://linkedin.com/in/SEU_PERFIL)*
