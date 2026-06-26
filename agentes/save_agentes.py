#!/usr/bin/env python3
"""Sincroniza agentes Wazuh da API diretamente para o CMDB a cada 30 segundos."""

from __future__ import annotations

import os
import time
import ipaddress
import logging
import requests
import urllib3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import psycopg
from psycopg.rows import dict_row

try:
    from dotenv import load_dotenv  # type: ignore[import-not-found]
except ImportError:
    def load_dotenv(dotenv_path: Path | None = None) -> bool:
        if dotenv_path is None or not dotenv_path.exists():
            return False

        loaded = False
        with dotenv_path.open("r", encoding="utf-8") as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
                    loaded = True

        return loaded

dotenv_path = Path(__file__).with_name(".env")
load_dotenv(dotenv_path=dotenv_path)

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Variavel de ambiente obrigatoria ausente: {name}")
    return value

# ==========================================
# CONFIGURAÇÕES DA API DO WAZUH
# ==========================================
WAZUH_VERIFY_SSL = env_bool("WAZUH_VERIFY_SSL", default=True)
WAZUH_CA_BUNDLE = os.getenv("WAZUH_CA_BUNDLE", "").strip() or None
WAZUH_REQUEST_TIMEOUT = int(os.getenv("WAZUH_TIMEOUT_SECONDS", "15"))
SYNC_INTERVAL_SECONDS = int(os.getenv("SYNC_INTERVAL_SECONDS", "30"))
RUN_FOREVER = env_bool("RUN_FOREVER", default=False)

WAZUH_CONFIG = {
    "base_url": os.getenv("WAZUH_BASE_URL", "https://127.0.0.1:55000").rstrip("/"),
    "user": require_env("WAZUH_USER"),
    "password": require_env("WAZUH_PASSWORD"),
    "limit": int(os.getenv("WAZUH_LIMIT", "500")),
}

# ==========================================
# CONFIGURAÇÕES DO BANCO DE DADOS
# ==========================================
DB_CONFIG = {
    "host": os.getenv("PGHOST"),
    "port": int(os.getenv("PGPORT")),
    "dbname": os.getenv("PGDATABASE"),
    "user": os.getenv("PGUSER"),
    "password": os.getenv("PGPASSWORD"),
}

if not WAZUH_VERIFY_SSL:
    # Mantem o aviso desativado apenas quando SSL verification foi explicitamente desativada.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_verify_option() -> bool | str:
    if not WAZUH_VERIFY_SSL:
        return False
    if WAZUH_CA_BUNDLE:
        return WAZUH_CA_BUNDLE
    return True


def build_http_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=0.8,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


HTTP_SESSION = build_http_session()

STATUS_MAP = {
    "active": "active",
    "inactive": "disconnected",
    "disconnected": "disconnected",
    "pending": "pending",
    "never_connected": "never_connected",
    "never connected": "never_connected",
    "never-connected": "never_connected",
}

# --- FUNÇÕES DE CONEXÃO DA API ---

def get_wazuh_token() -> str:
    logger.info("Autenticando na API do Wazuh...")
    auth_url = f"{WAZUH_CONFIG['base_url']}/security/user/authenticate?raw=true"
    response = HTTP_SESSION.get(
        auth_url,
        auth=(WAZUH_CONFIG['user'], WAZUH_CONFIG['password']),
        verify=get_verify_option(),
        timeout=WAZUH_REQUEST_TIMEOUT,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Falha na autenticacao. Codigo {response.status_code}: {response.text[:300]}")
    return response.text

def get_all_agents(token: str) -> list[dict]:
    all_agents = []
    offset = 0
    headers = {"Authorization": f"Bearer {token}"}
    limit = WAZUH_CONFIG['limit']

    logger.info("Buscando agentes na API...")
    while True:
        agents_url = f"{WAZUH_CONFIG['base_url']}/agents?limit={limit}&offset={offset}"
        response = HTTP_SESSION.get(
            agents_url,
            headers=headers,
            verify=get_verify_option(),
            timeout=WAZUH_REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            logger.error("Erro na API: %s - %s", response.status_code, response.text[:300])
            break

        data = response.json()
        items = data.get("data", {}).get("affected_items", [])

        if not items:
            break

        all_agents.extend(items)
        if len(items) < limit:
            break

        offset += limit

    return all_agents

# --- FUNÇÕES DE BANCO DE DADOS (MANTIDAS DO SEU SCRIPT) ---

@contextmanager
def get_conn():
    conn = psycopg.connect(**DB_CONFIG, row_factory=dict_row)
    try:
        yield conn
    finally:
        conn.close()

def normalize_status(value: str | None) -> str:
    if not value:
        return "active"
    return STATUS_MAP.get(value.strip().lower(), value.strip().lower())

def normalize_ip(value: str | None) -> str | None:
    normalized = str(value or "").strip().lower()
    if not normalized or normalized in {"any", "unknown", "n/a", "none", "null"}:
        return None
    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError:
        return None

def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

def resolve_tenant_id(cur: psycopg.Cursor, group_name: str, create_missing: bool = True) -> int:
    group_name = (group_name or "").strip()
    if not group_name:
        raise ValueError("Group name do Wazuh vazio")

    cur.execute("SELECT id_tenants FROM tenants WHERE customer_name = %s LIMIT 1", (group_name,))
    row = cur.fetchone()
    if row:
        return row["id_tenants"]

    if create_missing:
        cur.execute(
            """
            INSERT INTO tenants (customer_name, customer_domain, created_at)
            VALUES (%s, NULL, NOW())
            RETURNING id_tenants
            """,
            (group_name,),
        )
        created = cur.fetchone()
        if created:
            return created["id_tenants"]

    raise ValueError(f"Tenant não encontrado para grupo: {group_name}")

def resolve_product_vendor_id(cur: psycopg.Cursor, vendor_name: str | None) -> int | None:
    vendor_name = (vendor_name or "").strip()
    if not vendor_name:
        return None

    cur.execute("SELECT id_vendor FROM product_vendor WHERE vendor_name = %s LIMIT 1", (vendor_name,))
    row = cur.fetchone()
    if row:
        return row["id_vendor"]

    cur.execute(
        """
        INSERT INTO product_vendor (vendor_name, created_at)
        VALUES (%s, NOW())
        RETURNING id_vendor
        """,
        (vendor_name,),
    )
    created = cur.fetchone()
    return created["id_vendor"] if created else None

def resolve_product_name_id(cur: psycopg.Cursor, product_name: str | None) -> int:
    product_name = (product_name or "").strip() or "generic"

    cur.execute("SELECT id_product FROM product_name WHERE product_model = %s LIMIT 1", (product_name,))
    row = cur.fetchone()
    if row:
        return row["id_product"]

    cur.execute(
        """
        INSERT INTO product_name (product_model, created_at)
        VALUES (%s, NOW())
        RETURNING id_product
        """,
        (product_name,),
    )
    created = cur.fetchone()
    if created:
        return created["id_product"]
    raise ValueError(f"Erro ao criar product_name: {product_name}")

def sync_sequence(cur: psycopg.Cursor, table_name: str, id_column: str) -> None:
    cur.execute(
        "SELECT setval(pg_get_serial_sequence(%s, %s), COALESCE(MAX(" + id_column + "), 0) + 1, false) FROM " + table_name,
        (table_name, id_column),
    )

def sync_import_sequences(cur: psycopg.Cursor) -> None:
    sync_sequence(cur, "tenants", "id_tenants")
    sync_sequence(cur, "product_vendor", "id_vendor")
    sync_sequence(cur, "product_name", "id_product")
    sync_sequence(cur, "cmdb_assets", "id_asset")

def import_agent(cur: psycopg.Cursor, agent: dict, create_missing_tenants: bool = True) -> tuple[bool, str]:
    agent_id = str(agent.get("id") or "").strip()
    agent_name = str(agent.get("name") or "").strip()
    raw_group = agent.get("group")

    if isinstance(raw_group, list):
        group_list = raw_group
    elif isinstance(raw_group, str):
        normalized_group = raw_group.strip()
        group_list = [normalized_group] if normalized_group else []
    else:
        group_list = []

    os_info = agent.get("os") or {}

    if not agent_id:
        return False, "Campo 'id' vazio"
    if not agent_name:
        return False, "Campo 'name' vazio"

    tenant_group_name = str(group_list[0]).strip() if group_list and str(group_list[0]).strip() else None

    tenant_id = None
    if tenant_group_name:
        tenant_id = resolve_tenant_id(cur, tenant_group_name, create_missing=create_missing_tenants)

    platform_name = (os_info.get("platform") or agent.get("platform") or "").strip() or None
    product_name = (os_info.get("uname") or agent.get("uname") or os_info.get("name") or "").strip() or None
    product_id = resolve_product_name_id(cur, product_name)
    vendor_id = resolve_product_vendor_id(cur, platform_name)

    created_at = parse_timestamp(agent.get("dateAdd"))
    last_updated_agents = agent.get("lastKeepAlive")
    if last_updated_agents is not None:
        last_updated = parse_timestamp(agent.get("lastKeepAlive"))
    else:
        last_updated = parse_timestamp("1970-01-01T00:00:00Z")

    version_information = " ".join(
        part for part in [os_info.get("name"), os_info.get("version")] if part
    ) or None
    hostname = (agent.get("node_name") or "").strip() or agent_name
    status = normalize_status(agent.get("status"))
    ip_address = normalize_ip(agent.get("ip"))

    is_lec = 1 if len(group_list) > 1 and str(group_list[1]).strip().upper() == "LEC" else 0

    cur.execute(
        """
        UPDATE cmdb_assets
        SET
            asset_name = %s,
            hostname_fqdn = %s,
            ip_address = %s,
            operational_status = %s,
            version_information = %s,
            fk_tenant = %s,
            fk_product_name = %s,
            fk_product_vendor = %s,
            lec = %s,
            created_at = COALESCE(%s, created_at),
            last_updated = COALESCE(%s, NOW())
        WHERE id_asset_external = %s
        RETURNING id_asset
        """,
        (agent_name, hostname, ip_address, status, version_information, tenant_id,
         product_id, vendor_id, is_lec, created_at, last_updated, agent_id),
    )
    existing = cur.fetchone()
    if existing:
        return True, f"Ativo atualizado (ID: {existing['id_asset']})"

    cur.execute(
        """
        INSERT INTO cmdb_assets (
            id_asset_external, asset_name, hostname_fqdn, ip_address, operational_status,
            version_information, fk_tenant, fk_product_name, fk_product_vendor, lec,
            created_at, last_updated
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, COALESCE(%s, NOW()), COALESCE(%s, NOW()))
        RETURNING id_asset
        """,
        (agent_id, agent_name, hostname, ip_address, status, version_information,
         tenant_id, product_id, vendor_id, is_lec, created_at, last_updated),
    )
    inserted = cur.fetchone()
    if inserted:
        return True, f"Novo ativo criado (ID: {inserted['id_asset']})"

    return False, "Erro ao inserir ativo"

def process_agents(agents: list[dict], create_missing_tenants: bool = True) -> None:
    if not agents:
        logger.info("Nenhum agente para importar")
        return

    success_count = 0
    error_count = 0
    logger.info("Processando %s agente(s)...", len(agents))

    with get_conn() as conn:
        with conn.cursor() as cur:
            sync_import_sequences(cur)
            for agent in agents:
                cur.execute("SAVEPOINT local_agent_import")
                try:
                    ok, message = import_agent(cur, agent, create_missing_tenants=create_missing_tenants)
                except Exception as exc:
                    ok = False
                    message = str(exc)

                if ok:
                    cur.execute("RELEASE SAVEPOINT local_agent_import")
                    success_count += 1
                else:
                    cur.execute("ROLLBACK TO SAVEPOINT local_agent_import")
                    cur.execute("RELEASE SAVEPOINT local_agent_import")
                    logger.error("Erro [%s]: %s", agent.get("id"), message)
                    error_count += 1
        conn.commit()

    logger.info("Resultado do ciclo: %s sucesso(s), %s erro(s)", success_count, error_count)


def run_sync_cycle() -> None:
    logger.info("[%s] Iniciando sincronizacao Wazuh -> CMDB", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    try:
        token = get_wazuh_token()
        agents_payload = get_all_agents(token)
        process_agents(agents_payload)

    except requests.exceptions.RequestException as req_err:
        logger.error("Erro de conexao com a API: %s", req_err)
    except psycopg.Error as db_err:
        logger.error("Erro no banco de dados: %s", db_err)
    except Exception as err:
        logger.exception("Erro inesperado: %s", err)

    logger.info("[%s] Sincronizacao finalizada.", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

def main() -> None:
    if RUN_FOREVER:
        logger.info("Modo continuo habilitado. Intervalo: %s segundo(s)", SYNC_INTERVAL_SECONDS)
        while True:
            run_sync_cycle()
            time.sleep(SYNC_INTERVAL_SECONDS)
    else:
        run_sync_cycle()

if __name__ == "__main__":
    main()
