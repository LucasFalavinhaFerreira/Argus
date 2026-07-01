"""
Camada de acesso ao banco de dados do Argus.

Duas tabelas:
  - resultados: cache de verificações anteriores (evita rebater nas APIs
    pra alvos consultados recentemente)
  - monitorados: lista de domínios/URLs que o GitHub Actions verifica
    automaticamente a cada ciclo
"""
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta

DATABASE_URL = os.getenv("DATABASE_URL")

# Tempo de validade do cache: resultados com menos de N horas não
# precisam ser reconsultados nas APIs externas
CACHE_HORAS = 6


def get_connection():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL não definida. Configure a connection string do Neon "
            "como variável de ambiente / secret."
        )
    return psycopg2.connect(DATABASE_URL)


def inicializar_banco():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS resultados (
            id SERIAL PRIMARY KEY,
            alvo TEXT NOT NULL,
            tipo TEXT NOT NULL,
            data_consulta TIMESTAMP NOT NULL,
            veredito TEXT NOT NULL,
            score INTEGER NOT NULL DEFAULT 0,
            detalhe_urlhaus TEXT,
            detalhe_openphish TEXT,
            detalhe_virustotal TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitorados (
            id SERIAL PRIMARY KEY,
            alvo TEXT NOT NULL UNIQUE,
            tipo TEXT NOT NULL,
            adicionado_em TIMESTAMP NOT NULL,
            ultimo_veredito TEXT,
            ultima_verificacao TIMESTAMP
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()


def salvar_resultado(alvo, tipo, veredito, score, detalhes):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO resultados
                (alvo, tipo, data_consulta, veredito, score,
                 detalhe_urlhaus, detalhe_openphish, detalhe_virustotal)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            alvo, tipo, datetime.now(), veredito, score,
            detalhes.get("urlhaus"), detalhes.get("openphish"),
            detalhes.get("virustotal"),
        ))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[db] Falha ao salvar resultado de {alvo}: {e}")


def buscar_cache(alvo):
    """
    Retorna o resultado mais recente para o alvo se ainda estiver dentro
    do período de cache, ou None se precisar reconsultar.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        limite = datetime.now() - timedelta(hours=CACHE_HORAS)
        cursor.execute("""
            SELECT * FROM resultados
            WHERE alvo = %s AND data_consulta >= %s
            ORDER BY data_consulta DESC
            LIMIT 1
        """, (alvo, limite))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row
    except Exception as e:
        print(f"[db] Falha ao buscar cache de {alvo}: {e}")
        return None


def listar_historico(limite=20):
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT alvo, tipo, data_consulta, veredito, score
            FROM resultados
            ORDER BY data_consulta DESC
            LIMIT %s
        """, (limite,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Exception as e:
        print(f"[db] Falha ao listar histórico: {e}")
        return []


def adicionar_monitorado(alvo, tipo):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO monitorados (alvo, tipo, adicionado_em)
            VALUES (%s, %s, %s)
            ON CONFLICT (alvo) DO NOTHING
        """, (alvo, tipo, datetime.now()))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[db] Falha ao adicionar monitorado {alvo}: {e}")
        return False


def listar_monitorados():
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT * FROM monitorados ORDER BY adicionado_em DESC
        """)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Exception as e:
        print(f"[db] Falha ao listar monitorados: {e}")
        return []


def atualizar_veredito_monitorado(alvo, veredito):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE monitorados
            SET ultimo_veredito = %s, ultima_verificacao = %s
            WHERE alvo = %s
        """, (veredito, datetime.now(), alvo))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[db] Falha ao atualizar veredito de {alvo}: {e}")


def remover_monitorado(alvo):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM monitorados WHERE alvo = %s", (alvo,))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[db] Falha ao remover monitorado {alvo}: {e}")
        return False
