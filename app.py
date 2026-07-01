"""
Dashboard Argus — Verificador de Domínios e URLs maliciosos.
"""
import gradio as gr

from db import (
    inicializar_banco, listar_historico,
    adicionar_monitorado, listar_monitorados, remover_monitorado,
)
from checker import verificar, detectar_tipo

inicializar_banco()

theme_base = gr.themes.Default()


# ---------------------------------------------------------------------------
# Funções de interface
# ---------------------------------------------------------------------------

def formatar_resultado(resultado):
    linhas = [
        f"Alvo: {resultado['alvo']}",
        f"Tipo: {resultado['tipo'].upper()}",
        f"Veredito: {resultado['veredito']} (score: {resultado['score']})",
        f"Fonte do resultado: {'⚡ Cache (< 6h)' if resultado['cache'] else '🔄 Consulta nova'}",
        "",
        "─── Detalhes por Fonte ───",
    ]
    for fonte in resultado["fontes"]:
        status_emoji = {"malicioso": "🔴", "suspeito": "🟡", "limpo": "🟢", "erro": "⚠️"}.get(fonte["status"], "─")
        linhas.append(f"{status_emoji} {fonte['fonte']}: {fonte['detalhe']}")
    return "\n".join(linhas)


def executar_verificacao(alvo, forcar_reconsulta):
    if not alvo or not alvo.strip():
        return "⚠️ Digite um domínio ou URL para verificar."
    try:
        resultado = verificar(alvo.strip(), forcar_reconsulta=forcar_reconsulta)
        return formatar_resultado(resultado)
    except Exception as e:
        return f"Erro na verificação: {str(e)}"


def adicionar_ao_monitoramento(alvo):
    if not alvo or not alvo.strip():
        return "⚠️ Digite um alvo válido.", atualizar_tabela_monitorados()
    alvo = alvo.strip()
    tipo = detectar_tipo(alvo)
    sucesso = adicionar_monitorado(alvo, tipo)
    msg = f"✅ '{alvo}' adicionado ao monitoramento." if sucesso else f"⚠️ '{alvo}' já estava na lista."
    return msg, atualizar_tabela_monitorados()


def remover_do_monitoramento(alvo):
    if not alvo or not alvo.strip():
        return "⚠️ Digite o alvo a remover.", atualizar_tabela_monitorados()
    sucesso = remover_monitorado(alvo.strip())
    msg = f"🗑️ '{alvo}' removido." if sucesso else f"⚠️ '{alvo}' não encontrado na lista."
    return msg, atualizar_tabela_monitorados()


def atualizar_tabela_monitorados():
    monitorados = listar_monitorados()
    if not monitorados:
        return "Nenhum alvo monitorado ainda."
    linhas = [f"{'Alvo':<50} {'Tipo':<10} {'Último Veredito':<20} {'Última Verificação'}"]
    linhas.append("─" * 100)
    for m in monitorados:
        ultima = str(m["ultima_verificacao"])[:16] if m["ultima_verificacao"] else "—"
        veredito = m["ultimo_veredito"] or "—"
        linhas.append(f"{m['alvo']:<50} {m['tipo']:<10} {veredito:<20} {ultima}")
    return "\n".join(linhas)


def atualizar_historico():
    historico = listar_historico(limite=20)
    if not historico:
        return "Nenhuma consulta realizada ainda."
    linhas = [f"{'Data':<20} {'Tipo':<10} {'Veredito':<20} {'Alvo'}"]
    linhas.append("─" * 100)
    for h in historico:
        data = str(h["data_consulta"])[:16]
        linhas.append(f"{data:<20} {h['tipo']:<10} {h['veredito']:<20} {h['alvo']}")
    return "\n".join(linhas)


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

with gr.Blocks() as interface:
    gr.Markdown("🔍 Argus — Verificador de Domínios e URLs | URLhaus + OpenPhish + VirusTotal")

    with gr.Tabs():
        # ── Aba 1: Consulta manual ─────────────────────────────────────────
        with gr.Tab("🔎 Verificar Alvo"):
            with gr.Row():
                with gr.Column(scale=1, elem_classes=["cyber-box"]):
                    gr.Markdown("### 🎯 ALVO")
                    gr.Markdown(
                        "Digite um domínio (ex: `evil.com`) ou URL completa "
                        "(ex: `https://evil.com/phishing`). "
                        "Resultados recentes são servidos do cache (< 6h) pra "
                        "economizar cota da API."
                    )
                    input_alvo = gr.Textbox(
                        label="Domínio ou URL",
                        placeholder="evil.com ou https://evil.com/phishing",
                    )
                    forcar = gr.Checkbox(
                        label="Forçar nova consulta (ignorar cache)",
                        value=False,
                    )
                    btn_verificar = gr.Button("Verificar", elem_classes=["neon-btn"])
                    gr.Markdown(
                        "📊 Fontes:\n"
                        "* URLhaus (abuse.ch) — malware\n"
                        "* OpenPhish — phishing\n"
                        "* VirusTotal — multi-engine"
                    )

                with gr.Column(scale=2):
                    output_resultado = gr.Textbox(
                        label="RESULTADO DA VERIFICAÇÃO",
                        lines=15,
                        placeholder="Aguardando consulta...",
                        elem_classes=["terminal-console"],
                    )

            btn_verificar.click(
                fn=executar_verificacao,
                inputs=[input_alvo, forcar],
                outputs=output_resultado,
            )

        # ── Aba 2: Monitoramento contínuo ──────────────────────────────────
        with gr.Tab("📡 Monitoramento Contínuo"):
            gr.Markdown(
                "### 📡 LISTA DE ALVOS MONITORADOS\n"
                "Alvos aqui são verificados automaticamente pelo GitHub Actions "
                "a cada ciclo. Alertas críticos/suspeitos chegam no Slack."
            )
            with gr.Row():
                with gr.Column(scale=1, elem_classes=["cyber-box"]):
                    input_novo = gr.Textbox(
                        label="Adicionar alvo",
                        placeholder="dominio.com ou https://url.com",
                    )
                    btn_adicionar = gr.Button("Adicionar ao Monitoramento", elem_classes=["neon-btn"])
                    gr.Markdown("---")
                    input_remover = gr.Textbox(
                        label="Remover alvo",
                        placeholder="dominio.com",
                    )
                    btn_remover = gr.Button("Remover", size="sm")
                    btn_atualizar = gr.Button("Atualizar Lista", size="sm")
                    msg_status = gr.Textbox(label="Status", interactive=False, lines=1)

                with gr.Column(scale=2):
                    output_monitorados = gr.Textbox(
                        label="ALVOS MONITORADOS",
                        value=atualizar_tabela_monitorados(),
                        lines=18,
                        interactive=False,
                        elem_classes=["terminal-console"],
                    )

            btn_adicionar.click(
                fn=adicionar_ao_monitoramento,
                inputs=input_novo,
                outputs=[msg_status, output_monitorados],
            )
            btn_remover.click(
                fn=remover_do_monitoramento,
                inputs=input_remover,
                outputs=[msg_status, output_monitorados],
            )
            btn_atualizar.click(
                fn=atualizar_tabela_monitorados,
                inputs=None,
                outputs=output_monitorados,
            )

        # ── Aba 3: Histórico ───────────────────────────────────────────────
        with gr.Tab("📋 Histórico"):
            gr.Markdown("### 📋 ÚLTIMAS CONSULTAS\nÚltimas 20 verificações realizadas.")
            btn_atualizar_hist = gr.Button("Atualizar Histórico", elem_classes=["neon-btn"])
            output_historico = gr.Textbox(
                label="HISTÓRICO",
                value=atualizar_historico(),
                lines=20,
                interactive=False,
                elem_classes=["terminal-console"],
            )
            btn_atualizar_hist.click(
                fn=atualizar_historico,
                inputs=None,
                outputs=output_historico,
            )

if __name__ == "__main__":
    interface.queue()
    interface.launch(theme=theme_base, css="style.css")
