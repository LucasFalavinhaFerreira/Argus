"""
Consultas às fontes externas de threat intelligence para domínios e URLs.

Fontes:
  - URLhaus (abuse.ch) — malware distribution, consulta ativa via API POST
  - OpenPhish            — feed de phishing, verificação por presença no feed
  - VirusTotal           — multi-engine, consulta via API REST (key necessária)
"""
import os
import time
import requests

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")

HEADERS_PADRAO = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
TIMEOUT = 8


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------

def consultar_urlhaus(alvo):
    """
    Consulta a API do URLhaus para uma URL ou domínio.
    Requer Auth-Key gratuita em auth.abuse.ch
    """
    if not URLHAUS_AUTH_KEY:
        return {"fonte": "URLhaus", "status": "erro", "detalhe": "Auth-Key ausente (auth.abuse.ch)"}

    try:
        headers = {"Auth-Key": URLHAUS_AUTH_KEY}
        resposta = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": alvo},
            headers=headers,
            timeout=TIMEOUT,
        )
        if resposta.status_code != 200:
            return {"fonte": "URLhaus", "status": "erro", "detalhe": f"HTTP {resposta.status_code}"}

        dados = resposta.json()
        query_status = dados.get("query_status", "")

        if query_status == "is_host":
            # Retornou por domínio — verifica se alguma URL está online/maliciosa
            urls = dados.get("urls", [])
            online = [u for u in urls if u.get("url_status") == "online"]
            if online:
                tags = online[0].get("tags") or []
                return {
                    "fonte": "URLhaus",
                    "status": "malicioso",
                    "detalhe": f"{len(online)} URL(s) ativa(s) — tags: {', '.join(tags) or 'sem tag'}",
                }
            return {"fonte": "URLhaus", "status": "suspeito", "detalhe": "Registrado, mas URLs offline"}

        if query_status == "is_url":
            url_status = dados.get("url_status", "")
            tags = dados.get("tags") or []
            if url_status == "online":
                return {
                    "fonte": "URLhaus",
                    "status": "malicioso",
                    "detalhe": f"URL ativa — tags: {', '.join(tags) or 'sem tag'}",
                }
            return {
                "fonte": "URLhaus",
                "status": "suspeito",
                "detalhe": f"Registrado mas offline — tags: {', '.join(tags) or 'sem tag'}",
            }

        return {"fonte": "URLhaus", "status": "limpo", "detalhe": "Não encontrado na base"}

    except Exception as e:
        return {"fonte": "URLhaus", "status": "erro", "detalhe": str(e)}


# ---------------------------------------------------------------------------
# OpenPhish
# ---------------------------------------------------------------------------

_openphish_cache = set()
_openphish_atualizado_em = 0
OPENPHISH_TTL = 3600  # recarrega o feed no máximo a cada 1h por instância


def _carregar_feed_openphish():
    global _openphish_cache, _openphish_atualizado_em
    agora = time.time()
    if agora - _openphish_atualizado_em < OPENPHISH_TTL and _openphish_cache:
        return
    try:
        resp = requests.get(
            "https://openphish.com/feed.txt",
            headers=HEADERS_PADRAO,
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            _openphish_cache = set(
                linha.strip().lower()
                for linha in resp.text.splitlines()
                if linha.strip()
            )
            _openphish_atualizado_em = agora
    except Exception as e:
        print(f"[sources] Falha ao carregar feed OpenPhish: {e}")


def consultar_openphish(alvo):
    """
    Verifica se o alvo (URL ou domínio) está presente no feed do OpenPhish.
    """
    try:
        _carregar_feed_openphish()
        alvo_lower = alvo.lower().strip()

        # Tenta match exato primeiro, depois verifica se o domínio aparece
        # dentro de alguma URL do feed (caso o usuário passe só o domínio)
        if alvo_lower in _openphish_cache:
            return {"fonte": "OpenPhish", "status": "malicioso", "detalhe": "URL encontrada no feed de phishing"}

        dominio_alvo = alvo_lower.replace("https://", "").replace("http://", "").split("/")[0]
        correspondencias = [u for u in _openphish_cache if dominio_alvo in u]
        if correspondencias:
            return {
                "fonte": "OpenPhish",
                "status": "malicioso",
                "detalhe": f"Domínio presente em {len(correspondencias)} URL(s) de phishing conhecidas",
            }

        return {"fonte": "OpenPhish", "status": "limpo", "detalhe": "Não encontrado no feed"}

    except Exception as e:
        return {"fonte": "OpenPhish", "status": "erro", "detalhe": str(e)}


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def consultar_virustotal(alvo):
    """
    Consulta o VirusTotal para uma URL ou domínio.
    Limite gratuito: 4 req/min, 500/dia.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"fonte": "VirusTotal", "status": "erro", "detalhe": "API key ausente"}

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        # Decide o endpoint baseado no tipo de alvo
        # Domínio puro (sem http) → /domains/; URL completa → /urls/
        if alvo.startswith("http://") or alvo.startswith("https://"):
            import base64
            url_id = base64.urlsafe_b64encode(alvo.encode()).decode().rstrip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{alvo}"

        resp = requests.get(endpoint, headers=headers, timeout=TIMEOUT)

        if resp.status_code == 404:
            return {"fonte": "VirusTotal", "status": "limpo", "detalhe": "Não encontrado na base do VirusTotal"}

        if resp.status_code != 200:
            return {"fonte": "VirusTotal", "status": "erro", "detalhe": f"HTTP {resp.status_code}"}

        dados = resp.json()
        stats = dados.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        if malicious > 2:
            return {
                "fonte": "VirusTotal",
                "status": "malicioso",
                "detalhe": f"{malicious}/{total} engines marcaram como malicioso",
            }
        if malicious > 0 or suspicious > 0:
            return {
                "fonte": "VirusTotal",
                "status": "suspeito",
                "detalhe": f"{malicious} malicioso(s), {suspicious} suspeito(s) de {total} engines",
            }
        return {
            "fonte": "VirusTotal",
            "status": "limpo",
            "detalhe": f"0/{total} engines detectaram ameaça",
        }

    except Exception as e:
        return {"fonte": "VirusTotal", "status": "erro", "detalhe": str(e)}
