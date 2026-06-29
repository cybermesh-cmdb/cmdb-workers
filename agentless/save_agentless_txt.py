#!/usr/bin/env python3
"""
check_last_event.py

Verifica, para uma ou mais "location" no indice wazuh-alerts-*, qual foi o
ultimo evento recebido, ha quanto tempo isso ocorreu, e se esse tempo esta
dentro (OK) ou fora (FORA) de um threshold (limite) estipulado.

Equivalente em Python ao script bash original, mas permitindo:
  - Uma unica location via linha de comando (-l/--location), pode ser repetido
  - Uma lista de locations a partir de um arquivo CSV (-f/--file)
  - Definicao de Customer e Threshold (em minutos) por location
  - Configuracao de host, usuario, senha e janela de tempo via argumentos

Formato do arquivo CSV (-f), SEM cabecalho:

    BLAU,/var/log/firewalls/10.30.0.1.log,60
    BLAU,/var/log/firewalls/10.40.0.1.log,60
    GDM,/var/log/firewalls/10.58.0.1.log,120
    LNCC,/var/log/firewalls/SentinelOne.log,70

  Cada linha segue o formato: Customer,Location,Threshold (em minutos).
  Linhas em branco ou iniciadas com '#' sao ignoradas.

  Tambem sao aceitas linhas mais curtas, sem Customer:
    "location" ou "location,threshold"

Exemplos de uso:
  # Lista de locations a partir do CSV com Customer e Threshold
  python3 check_last_event.py -f locations.csv

  # Uma unica location via linha de comando: customer,location,threshold
  python3 check_last_event.py -l "BLAU,/var/log/firewalls/10.30.0.1.log,60"

  # Apenas location e threshold (sem customer)
  python3 check_last_event.py -l "/var/log/A.log,30"

  # Threshold padrao (aplicado quando a location nao define o proprio)
  python3 check_last_event.py -f locations.csv --threshold 60

  # Customizando host/usuario/senha/janela
  python3 check_last_event.py -f locations.csv \
      --host 172.31.0.9 --port 9200 \
      --user admin --password 'minha_senha' \
      --window 25h
"""

import argparse
import csv
import ipaddress
import os
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import urllib3

try:
    import psycopg
except ImportError:  # pragma: no cover - depende do ambiente de execucao
    psycopg = None

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


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}

AGENTLESS_HOST = os.getenv("AGENTLESS_HOST")
AGENTLESS_PORT = os.getenv("AGENTLESS_PORT")
AGENTLESS_USER = os.getenv("AGENTLESS_USER") 
AGENTLESS_PASSWORD = os.getenv("AGENTLESS_PASSWORD") 
AGENTLESS_CA_CERT = os.getenv("AGENTLESS_CA_CERT") or os.getenv("WAZUH_CA_BUNDLE", "")
AGENTLESS_INSECURE = env_bool("AGENTLESS_INSECURE", default=False)
AGENTLESS_SAVE_DB = env_bool("AGENTLESS_SAVE_DB", default=True)
AGENTLESS_CREATE_MISSING_TENANT = env_bool("AGENTLESS_CREATE_MISSING_TENANT", default=True)
AGENTLESS_INPUT_FILE = os.getenv("AGENTLESS_INPUT_FILE", "")

DB_CONFIG = {
    "host": os.getenv("PGHOST"),
    "port": int(os.getenv("PGPORT")),
    "dbname": os.getenv("PGDATABASE"),
    "user": os.getenv("PGUSER"),
    "password": os.getenv("PGPASSWORD"),
}

SCHEMA_CACHE: dict[str, str] = {}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Verifica o ultimo evento Wazuh para uma ou mais locations."
    )
    parser.add_argument(
        "-l", "--location",
        action="append",
        default=[],
        help="Location a consultar (pode ser usado multiplas vezes). "
             "Formatos aceitos: 'location' | 'location,threshold' | "
             "'customer,location,threshold'. Aceita wildcard, "
             "ex: '/var/log/*.log'"
    )
    parser.add_argument(
        "-f", "--file",
        default=AGENTLESS_INPUT_FILE,
        help="Arquivo CSV com colunas Customer,Location,Threshold "
             "(com cabecalho), ou arquivo simples com uma location por linha."
    )
    parser.add_argument(
        "--host",
        default=AGENTLESS_HOST,
        help="Host/IP do servidor Wazuh/OpenSearch (default: 172.31.0.9)"
    )
    parser.add_argument(
        "--port",
        default=AGENTLESS_PORT,
        help="Porta do servidor (default: 9200)"
    )
    parser.add_argument(
        "--user",
        default=AGENTLESS_USER,
        help="Usuario para autenticacao basica (default: admin)"
    )
    parser.add_argument(
        "--password",
        default=AGENTLESS_PASSWORD,
        help="Senha para autenticacao basica"
    )
    parser.add_argument(
        "--ca-cert",
        default=AGENTLESS_CA_CERT,
        help="Caminho para certificado CA customizado (opcional)."
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=AGENTLESS_INSECURE,
        help="Desativa validacao TLS (nao recomendado em producao)."
    )
    parser.add_argument(
        "--index",
        default="wazuh-alerts-*",
        help="Padrao do indice (default: wazuh-alerts-*)"
    )
    parser.add_argument(
        "--window",
        default="25h",
        help="Janela de tempo para busca, formato Elasticsearch (default: 25h)"
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Exibe a saida em formato CSV em vez de tabela alinhada"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Threshold padrao em minutos, usado para locations que nao "
             "definem o proprio threshold. Se omitido, locations sem "
             "threshold ficam sem verificacao de status."
    )
    parser.add_argument(
        "--only-out",
        action="store_true",
        help="Exibe apenas as locations com status FORA (ou com erro)."
    )
    parser.add_argument(
        "--save-db",
        dest="save_db",
        action="store_true",
        default=AGENTLESS_SAVE_DB,
        help="Salva/atualiza os dados na tabela lec (padrao via AGENTLESS_SAVE_DB)."
    )
    parser.add_argument(
        "--no-save-db",
        dest="save_db",
        action="store_false",
        help="Nao persiste os dados no banco."
    )

    args = parser.parse_args()

    if not args.location and not args.file:
        parser.error("Informe ao menos uma location via -l/--location ou um arquivo via -f/--file")

    if not args.user:
        parser.error("Informe --user ou configure AGENTLESS_USER/WAZUH_USER no ambiente")

    if not args.password:
        parser.error("Informe --password ou configure AGENTLESS_PASSWORD/WAZUH_PASSWORD no ambiente")

    return args


def parse_location_entry(raw, default_threshold):
    """
    Usado para entradas vindas de -l/--location (linha de comando) e para
    arquivos "simples" (sem cabecalho CSV).

    Aceita:
      "location"
      "location,threshold"
      "customer,location,threshold"

    Retorna um dicionario com os campos normalizados para processamento.
    """
    raw = raw.strip()
    if ";" in raw and "," not in raw:
        parts = [p.strip() for p in raw.split(";")]
    else:
        parts = [p.strip() for p in raw.split(",")]

    return parse_location_parts(parts, default_threshold)


def parse_location_parts(parts, default_threshold):
    parts = [str(p).strip() for p in parts]

    if len(parts) == 1:
        return {
            "customer": "-",
            "location": parts[0],
            "threshold": default_threshold,
            "hostname": "-",
            "host_ip": "-",
            "customer_name": "-",
            "device_type": "-",
            "manufacturer": "-",
        }

    if len(parts) == 2:
        location, threshold_str = parts
        return {
            "customer": "-",
            "location": location,
            "threshold": _parse_threshold(threshold_str, default_threshold, location),
            "hostname": "-",
            "host_ip": "-",
            "customer_name": "-",
            "device_type": "-",
            "manufacturer": "-",
        }


    customer, location, threshold_str = parts[0], parts[1], parts[2]
    extra = parts[3:8]
    while len(extra) < 5:
        extra.append("")

    hostname, host_ip, customer_name, device_type, manufacturer = extra
    return {
        "customer": customer or "-",
        "location": location,
        "threshold": _parse_threshold(threshold_str, default_threshold, location),
        "hostname": hostname or "-",
        "host_ip": host_ip or "-",
        "customer_name": customer_name or "-",
        "device_type": device_type or "-",
        "manufacturer": manufacturer or "-",
    }


def _parse_threshold(threshold_str, default_threshold, location):
    threshold_str = threshold_str.strip()
    if not threshold_str:
        return default_threshold
    try:
        return int(threshold_str)
    except ValueError:
        print(
            f"Aviso: threshold invalido '{threshold_str}' para '{location}', "
            f"usando valor padrao.",
            file=sys.stderr,
        )
        return default_threshold


def parse_csv_file(path, default_threshold):
    """
    Le um arquivo CSV detectando automaticamente delimitador ';' ou ','.
    Aceita com ou sem cabecalho, e com colunas extras apos o threshold.
    """
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=";,")
            delimiter = dialect.delimiter
        except csv.Error:
            delimiter = ";" if sample.count(";") > sample.count(",") else ","

        reader = csv.reader(f, delimiter=delimiter)
        rows = [row for row in reader if row and not row[0].strip().startswith("#")]

    entries = []
    for idx, row in enumerate(rows):
        if all(not c.strip() for c in row):
            continue
        if idx == 0 and is_header_row(row):
            continue
        entries.append(parse_location_parts(row, default_threshold))

    return entries


def is_header_row(row):
    normalized = [str(c).strip().lower() for c in row]
    has_location = any("location" in c for c in normalized)
    has_threshold = any("threshold" in c or "treashold" in c for c in normalized)
    has_tenant = any("tenant" in c or "customer" in c for c in normalized)
    return has_location and (has_threshold or has_tenant)


def load_locations(args):
    entries = [parse_location_entry(raw, args.threshold) for raw in args.location]

    if args.file:
        try:
            entries.extend(parse_csv_file(args.file, args.threshold))
        except OSError as e:
            print(f"Erro ao ler arquivo '{args.file}': {e}", file=sys.stderr)
            sys.exit(1)

    # remove duplicadas (por location) mantendo a ordem
    seen = set()
    unique_entries = []
    for entry in entries:
        location = entry["location"]
        if location not in seen:
            seen.add(location)
            unique_entries.append(entry)

    return unique_entries


def query_last_event(session, base_url, index, location, window, user, password, verify):
    url = f"{base_url}/{index}/_search?pretty"
    body = {
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"wildcard": {"location": location}}
                ],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{window}",
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        }
    }

    try:
        resp = session.post(
            url,
            json=body,
            auth=(user, password),
            verify=verify,
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        return None, f"Erro na requisicao: {e}"

    data = resp.json()
    hits = data.get("hits", {}).get("hits", [])
    if not hits:
        return None, "No events found"

    last_ts = hits[0].get("_source", {}).get("@timestamp")
    if not last_ts:
        return None, "No events found"

    return last_ts, None


def parse_optional_int(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_last_event(value: str) -> datetime | None:
    raw = (value or "").strip()
    if not raw or raw.lower().startswith("erro") or raw == "No events found":
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_ip_for_db(value: str) -> str | None:
    raw = (value or "").strip()
    if not raw or raw == "-":
        return None
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def normalize_text(value: str) -> str | None:
    raw = (value or "").strip()
    return None if not raw or raw == "-" else raw


def get_table_columns(cur, table_name: str) -> set[str]:
    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        """,
        (table_name,),
    )
    return {row[0] for row in cur.fetchall()}


def get_schema_column(cur, cache_key: str, table_name: str, preferred: list[str]) -> str:
    cached = SCHEMA_CACHE.get(cache_key)
    if cached:
        return cached

    columns = get_table_columns(cur, table_name)
    for col in preferred:
        if col in columns:
            SCHEMA_CACHE[cache_key] = col
            return col

    raise RuntimeError(
        f"Nenhuma coluna compativel encontrada em {table_name}. Esperado uma de: {', '.join(preferred)}"
    )


@contextmanager
def get_conn():
    if psycopg is None:
        raise RuntimeError("Dependencia 'psycopg' nao instalada. Rode: pip install psycopg[binary]")
    conn = psycopg.connect(**DB_CONFIG)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def resolve_tenant_id(cur, tenant_name: str, customer_name: str | None, create_missing: bool) -> int:
    tenant_name_col = get_schema_column(
        cur,
        cache_key="tenants.name_col",
        table_name="tenants",
        preferred=["customer_name", "custom_name"],
    )

    candidates = [tenant_name, customer_name]
    for candidate in candidates:
        normalized = normalize_text(candidate or "")
        if not normalized:
            continue
        cur.execute(
            f"SELECT id_tenants FROM tenants WHERE {tenant_name_col} = %s LIMIT 1",
            (normalized,),
        )
        row = cur.fetchone()
        if row:
            return row[0]

    if not create_missing:
        raise ValueError(f"Tenant nao encontrado para '{tenant_name}'")

    tenant_to_create = normalize_text(tenant_name) or normalize_text(customer_name or "")
    if not tenant_to_create:
        raise ValueError("Tenant vazio para criacao")

    cur.execute(
        f"INSERT INTO tenants ({tenant_name_col}) VALUES (%s) RETURNING id_tenants",
        (tenant_to_create,),
    )
    created = cur.fetchone()
    if not created:
        raise ValueError(f"Falha ao criar tenant '{tenant_to_create}'")
    return created[0]


def save_row_to_db(cur, row: tuple[str, ...], create_missing_tenant: bool) -> None:
    lec_customer_col = get_schema_column(
        cur,
        cache_key="lec.customer_col",
        table_name="lec",
        preferred=["customer_name", "custom_name"],
    )

    tenant = row[0]
    customer_name = normalize_text(row[1])
    location = normalize_text(row[2])
    hostname = normalize_text(row[3])
    host_ip = normalize_ip_for_db(row[4])
    device_type = normalize_text(row[5])
    manufacturer = normalize_text(row[6])
    last_event = parse_last_event(row[7])
    seconds_since = parse_optional_int(row[8])
    minutes_since = parse_optional_int(row[9])
    hours_since = parse_optional_int(row[10])
    threshold_minutes = parse_optional_int(row[11])
    status_label = (row[12] or "").strip().upper()
    no_events_found = row[7] == "No events found"

    if not location:
        raise ValueError("file_location vazio")

    fk_tenant = resolve_tenant_id(cur, tenant, customer_name, create_missing=create_missing_tenant)

    if status_label == "OK":
        status_lec = "ok"
    elif status_label == "FORA":
        status_lec = "fora"
    elif row[7].startswith("Erro"):
        status_lec = "erro"
    else:
        status_lec = "sem_dados"

    cur.execute(
        "SELECT id_lec FROM lec WHERE fk_tenant = %s AND file_location = %s LIMIT 1",
        (fk_tenant, location),
    )
    existing = cur.fetchone()

    if existing:
        cur.execute(
            f"""
            UPDATE lec
            SET
                last_event = CASE WHEN %s THEN last_event ELSE %s END,
                seconds_since = %s,
                minutes_since = %s,
                hours_since = %s,
                threshold_minutes = %s,
                ip_host = %s,
                device_name = %s,
                {lec_customer_col} = %s,
                hostname_lec = %s,
                manufacturer = %s,
                status_lec = %s,
                updated_at = NOW()
            WHERE id_lec = %s
            """,
            (
                no_events_found,
                last_event,
                seconds_since,
                minutes_since,
                hours_since,
                threshold_minutes,
                host_ip,
                device_type,
                customer_name,
                hostname,
                manufacturer,
                status_lec,
                existing[0],
            ),
        )
    else:
        cur.execute(
            f"""
            INSERT INTO lec (
                fk_tenant,
                file_location,
                last_event,
                seconds_since,
                minutes_since,
                hours_since,
                threshold_minutes,
                ip_host,
                device_name,
                {lec_customer_col},
                hostname_lec,
                manufacturer,
                status_lec,
                created_at,
                updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            """,
            (
                fk_tenant,
                location,
                last_event,
                seconds_since,
                minutes_since,
                hours_since,
                threshold_minutes,
                host_ip,
                device_type,
                customer_name,
                hostname,
                manufacturer,
                status_lec,
            ),
        )


def build_row(entry: dict[str, Any], last_ts: str):
    """
    Retorna uma tupla
    (customer, location, lastEvent, secondsSince, minutesSince, hoursSince, threshold, status
)
    como strings, prontas para exibicao em tabela.

    status e "OK" se minutesSince <= threshold, "FORA" caso contrario,
    ou "-" se nenhum threshold foi definido para a location.
    """
    customer = str(entry.get("customer", "-"))
    location = str(entry.get("location", "-"))
    threshold = entry.get("threshold")
    hostname = str(entry.get("hostname", "-") or "-")
    host_ip = str(entry.get("host_ip", "-") or "-")
    customer_name = str(entry.get("customer_name", "-") or "-")
    device_type = str(entry.get("device_type", "-") or "-")
    manufacturer = str(entry.get("manufacturer", "-") or "-")
    threshold_str = str(threshold) if threshold is not None else "-"

    # Normaliza timestamp ISO 8601 (com ou sem 'Z') para datetime com timezone
    ts = last_ts.replace("Z", "+00:00")
    try:
        last_dt = datetime.fromisoformat(ts)
    except ValueError:
        return (
            customer,
            customer_name,
            location,
            hostname,
            host_ip,
            device_type,
            manufacturer,
            f"erro ao interpretar: {last_ts}",
            "-",
            "-",
            "-",
            threshold_str,
            "-",
        )

    if last_dt.tzinfo is None:
        last_dt = last_dt.replace(tzinfo=timezone.utc)

    now_dt = datetime.now(timezone.utc)
    diff_seconds = int((now_dt - last_dt).total_seconds())

    minutes = diff_seconds // 60
    hours = diff_seconds // 3600

    if threshold is None:
        status = "-"
    else:
        status = "OK" if minutes <= threshold else "FORA"

    return (
        customer,
        customer_name,
        location,
        hostname,
        host_ip,
        device_type,
        manufacturer,
        last_ts,
        str(diff_seconds),
        str(minutes),
        str(hours),
        threshold_str,
        status,
    )


HEADERS = (
    "Tenant",
    "CustomerName",
    "Location",
    "HostName",
    "HostIP",
    "DeviceType",
    "Manufacturer",
    "LastEvent",
    "SecondsSince",
    "MinutesSince",
    "HoursSince",
    "Threshold(min)",
    "Status",
)


def print_table(rows, sep=" | "):
    all_rows = [HEADERS] + rows
    widths = [max(len(row[col]) for row in all_rows) for col in range(len(HEADERS))]

    def format_row(row):
        return sep.join(str(cell).ljust(width) for cell, width in zip(row, widths))

    print(format_row(HEADERS))
    print(sep.join("-" * w for w in widths))
    for row in rows:
        print(format_row(row))


def print_csv(rows):
    writer = csv.writer(sys.stdout)
    writer.writerow(HEADERS)
    for row in rows:
        writer.writerow(row)


def main():
    args = parse_args()
    entries = load_locations(args)
    total_entries = len(entries)

    base_url = f"https://{args.host}:{args.port}"
    verify_option = False if args.insecure else (args.ca_cert or True)
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    db_conn = None
    db_cur = None

    if args.save_db:
        try:
            db_ctx = get_conn()
            db_conn = db_ctx.__enter__()
            db_cur = db_conn.cursor()
        except Exception as exc:
            print(f"Erro ao conectar no banco: {exc}", file=sys.stderr)
            sys.exit(2)

    exit_code = 0
    rows = []
    saved_to_db = 0
    no_events_found_rows = 0
    db_save_errors = 0

    try:
        for entry in entries:
            customer = str(entry.get("customer", "-"))
            customer_name = str(entry.get("customer_name", "-") or "-")
            location = str(entry.get("location", "-"))
            hostname = str(entry.get("hostname", "-") or "-")
            host_ip = str(entry.get("host_ip", "-") or "-")
            device_type = str(entry.get("device_type", "-") or "-")
            manufacturer = str(entry.get("manufacturer", "-") or "-")
            threshold = entry.get("threshold")

            last_ts, error = query_last_event(
                session, base_url, args.index, location, args.window,
                args.user, args.password, verify_option
            )

            threshold_str = str(threshold) if threshold is not None else "-"

            if error:
                status_value = "FORA" if error == "No events found" else "-"
                row = (
                    customer,
                    customer_name,
                    location,
                    hostname,
                    host_ip,
                    device_type,
                    manufacturer,
                    error,
                    "-",
                    "-",
                    "-",
                    threshold_str,
                    status_value,
                )
                if error != "No events found":
                    exit_code = 1
            else:
                row = build_row(entry, last_ts)

            if row[7] == "No events found":
                no_events_found_rows += 1

            if db_cur is not None:
                try:
                    save_row_to_db(db_cur, row, create_missing_tenant=AGENTLESS_CREATE_MISSING_TENANT)
                    saved_to_db += 1
                except Exception as exc:
                    print(f"Erro ao salvar linha '{location}' no banco: {exc}", file=sys.stderr)
                    db_save_errors += 1
                    exit_code = 1

            if args.only_out and row[-1] not in ("FORA", "-") and not error:
                continue

            rows.append(row)
    finally:
        if db_conn is not None:
            db_conn.commit()
        if db_cur is not None:
            db_cur.close()
        if db_conn is not None:
            db_conn.close()

    if args.csv:
        print_csv(rows)
    else:
        print_table(rows)

    print(
        "\nResumo: "
        f"total_linhas={total_entries} | "
        f"salvas_no_banco={saved_to_db} | "
        f"linhas_no_events_found={no_events_found_rows} | "
        f"erros_ao_salvar={db_save_errors}"
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
