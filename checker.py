"""
Motor de verificação do Argus.

Recebe um alvo (domínio ou URL), consulta as fontes disponíveis,
agrega os resultados num veredito único e salva no banco (com cache).

Pode ser importado pelo app.py (consulta manual) ou pelo monitor.py
(verificação automática via GitHub Actions).
"""
import time

from db import buscar_cache, salvar_resultado, atualizar_veredito_monitorado
from sources import consultar_urlhaus, consultar_openphish, consultar_virustotal

# Intervalo entre chamadas ao VirusTotal (respeita limite de 4 req/min)
VT_SLEEP = 16  # segundos


def detectar_tipo(alvo):
    alvo = alvo.strip()
    if alvo.startswith("http://") or alvo.startswith("https://"):
        return "url"
    return "dominio"


def calcular_veredito(resultados):
    pontos = {"malicioso": 2, "suspeito": 1, "limpo": 0, "erro": 0}
    score = sum(pontos.get(r["status"], 0) for r in resultados)

    if score >= 4:
        return "🔴 CRÍTICO", score
    if score >= 2:
        return "🟡 SUSPEITO", score
    if score >= 1:
        return "🟠 ATENÇÃO", score
    return "🟢 LIMPO", score


def verificar(alvo, forcar_reconsulta=False):
    alvo = alvo.strip()
    tipo = detectar_tipo(alvo)

    if not forcar_reconsulta:
        cached = buscar_cache(alvo)
        if cached:
            return {
                "alvo": alvo,
                "tipo": tipo,
                "veredito": cached["veredito"],
                "score": cached["score"],
                "fontes": [
                    {"fonte": "URLhaus",    "status": "-", "detalhe": cached["detalhe_urlhaus"] or "cache"},
                    {"fonte": "OpenPhish",  "status": "-", "detalhe": cached["detalhe_openphish"] or "cache"},
                    {"fonte": "VirusTotal", "status": "-", "detalhe": cached["detalhe_virustotal"] or "cache"},
                ],
                "cache": True,
            }

    resultado_urlhaus   = consultar_urlhaus(alvo)
    resultado_openphish = consultar_openphish(alvo)
    time.sleep(VT_SLEEP)
    resultado_vt = consultar_virustotal(alvo)

    fontes = [resultado_urlhaus, resultado_openphish, resultado_vt]
    veredito, score = calcular_veredito(fontes)

    detalhes = {
        "urlhaus":    resultado_urlhaus.get("detalhe"),
        "openphish":  resultado_openphish.get("detalhe"),
        "virustotal": resultado_vt.get("detalhe"),
    }
    salvar_resultado(alvo, tipo, veredito, score, detalhes)

    return {
        "alvo": alvo,
        "tipo": tipo,
        "veredito": veredito,
        "score": score,
        "fontes": fontes,
        "cache": False,
    }


def verificar_monitorados(lista_monitorados):
    """
    Verifica todos os alvos monitorados, forçando reconsulta (ignora cache).
    Usado pelo GitHub Actions no ciclo automático.
    """
    resultados = []
    for item in lista_monitorados:
        alvo = item["alvo"]
        print(f"[monitor] Verificando {alvo}...")
        resultado = verificar(alvo, forcar_reconsulta=True)
        atualizar_veredito_monitorado(alvo, resultado["veredito"])
        resultados.append(resultado)
        time.sleep(VT_SLEEP)
    return resultados


if __name__ == "__main__":
    from db import inicializar_banco
    inicializar_banco()

    alvos_teste = [
        "http://malware.testing.google.test/testing/malware/",
        "github.com",
    ]

    for alvo in alvos_teste:
        print(f"\n{'='*60}")
        print(f"Verificando: {alvo}")
        resultado = verificar(alvo, forcar_reconsulta=True)
        print(f"Veredito: {resultado['veredito']} (score: {resultado['score']})")
        for fonte in resultado["fontes"]:
            print(f"  {fonte['fonte']}: {fonte['status']} — {fonte['detalhe']}")
