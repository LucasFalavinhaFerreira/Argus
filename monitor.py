"""
Monitor automático do Argus.

Executado pelo GitHub Actions a cada ciclo configurado.
Verifica todos os domínios/URLs cadastrados na lista de monitorados,
atualiza o banco e dispara alertas no Slack para os críticos/suspeitos.
"""
import os
import requests

from db import inicializar_banco, listar_monitorados
from checker import verificar_monitorados


def disparar_alerta_slack(resultados_criticos):
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("[monitor] Slack não configurado, pulando alerta.")
        return

    if not resultados_criticos:
        print("[monitor] Nenhum alvo crítico/suspeito — sem alerta.")
        return

    linhas = ["🔍 *ARGUS — Alerta de Monitoramento de Domínios/URLs*\n"]
    for r in resultados_criticos:
        emoji = "🔴" if "CRÍTICO" in r["veredito"] else "🟡"
        linhas.append(f"{emoji} `{r['alvo']}` → {r['veredito']}")
        for fonte in r["fontes"]:
            if fonte["status"] not in ("limpo", "-", "erro"):
                linhas.append(f"   • {fonte['fonte']}: {fonte['detalhe']}")

    payload = {"text": "\n".join(linhas)}
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        if resp.status_code == 200:
            print("[monitor] Alerta enviado ao Slack.")
        else:
            print(f"[monitor] Slack retornou {resp.status_code}")
    except Exception as e:
        print(f"[monitor] Falha no Slack: {e}")


if __name__ == "__main__":
    inicializar_banco()
    monitorados = listar_monitorados()

    if not monitorados:
        print("[monitor] Nenhum alvo monitorado cadastrado. Adicione pelo dashboard.")
    else:
        print(f"[monitor] Verificando {len(monitorados)} alvo(s)...")
        resultados = verificar_monitorados(monitorados)
        criticos = [r for r in resultados if "CRÍTICO" in r["veredito"] or "SUSPEITO" in r["veredito"]]
        disparar_alerta_slack(criticos)
        print(f"[monitor] Ciclo concluído. {len(criticos)} alerta(s) gerado(s).")
