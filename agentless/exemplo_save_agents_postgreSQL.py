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
import sys
from datetime import datetime, timezone

import requests
import urllib3

# Desabilita warnings de certificado autoassinado (equivalente ao -k do curl)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
        help="Arquivo CSV com colunas Customer,Location,Threshold "
             "(com cabecalho), ou arquivo simples com uma location por linha."
    )
    parser.add_argument(
        "--host",
        default="172.31.0.9",
        help="Host/IP do servidor Wazuh/OpenSearch (default: 172.31.0.9)"
    )
    parser.add_argument(
        "--port",
        default="9200",
        help="Porta do servidor (default: 9200)"
    )
    parser.add_argument(
        "--user",
        default="admin",
        help="Usuario para autenticacao basica (default: admin)"
    )
    parser.add_argument(
        "--password",
        default="v?.95l.gLhCbU16QwZid78asEuSJDJzK",
        help="Senha para autenticacao basica"
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

    args = parser.parse_args()

    if not args.location and not args.file:
        parser.error("Informe ao menos uma location via -l/--location ou um arquivo via -f/--file")

    return args


def parse_location_entry(raw, default_threshold):
    """
    Usado para entradas vindas de -l/--location (linha de comando) e para
    arquivos "simples" (sem cabecalho CSV).

    Aceita:
      "location"
      "location,threshold"
      "customer,location,threshold"

    Retorna a tupla (customer, location, threshold).
    """
    raw = raw.strip()
    parts = [p.strip() for p in raw.split(",")]

    if len(parts) == 1:
        return "-", parts[0], default_threshold

    if len(parts) == 2:
        location, threshold_str = parts
        return "-", location, _parse_threshold(threshold_str, default_threshold, location)

    # 3 ou mais campos: customer, location, threshold (ignora excedentes)
    customer, location, threshold_str = parts[0], parts[1], parts[2]
    return customer, location, _parse_threshold(threshold_str, default_threshold, location)


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
    Le um arquivo CSV SEM cabecalho, no formato:
        Customer,Location,Threshold

    Tambem aceita linhas mais curtas:
        Location,Threshold
        Location

    Retorna lista de tuplas (customer, location, threshold).
    """
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        rows = [row for row in reader if row and not row[0].strip().startswith("#")]

    entries = []
    for row in rows:
        if all(not c.strip() for c in row):
            continue
        raw_line = ",".join(c.strip() for c in row)
        entries.append(parse_location_entry(raw_line, default_threshold))

    return entries


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
    for customer, location, threshold in entries:
        if location not in seen:
            seen.add(location)
            unique_entries.append((customer, location, threshold))

    return unique_entries


def query_last_event(session, base_url, index, location, window, user, password):
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
            verify=False,
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


def build_row(customer, location, last_ts, threshold):
    """
    Retorna uma tupla
    (customer, location, lastEvent, secondsSince, minutesSince, hoursSince, threshold, status
)
    como strings, prontas para exibicao em tabela.

    status e "OK" se minutesSince <= threshold, "FORA" caso contrario,
    ou "-" se nenhum threshold foi definido para a location.
    """
    threshold_str = str(threshold) if threshold is not None else "-"

    # Normaliza timestamp ISO 8601 (com ou sem 'Z') para datetime com timezone
    ts = last_ts.replace("Z", "+00:00")
    try:
        last_dt = datetime.fromisoformat(ts)
    except ValueError:
        return (customer, location, f"erro ao interpretar: {last_ts}", "-", "-", "-", threshold_str, "-")

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
        customer, location, last_ts, str(diff_seconds), str(minutes), str(hours),
        threshold_str, status,
    )


HEADERS = (
    "Customer", "Location", "LastEvent", "SecondsSince", "MinutesSince",
    "HoursSince", "Threshold(min)", "Status",
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
    entries = load_locations(args)  # lista de (customer, location, threshold)

    base_url = f"https://{args.host}:{args.port}"

    session = requests.Session()
    exit_code = 0
    rows = []

    for customer, location, threshold in entries:
        last_ts, error = query_last_event(
            session, base_url, args.index, location, args.window,
            args.user, args.password
        )

        threshold_str = str(threshold) if threshold is not None else "-"

        if error:
            row = (customer, location, error, "-", "-", "-", threshold_str, "-")
            exit_code = 1
        else:
            row = build_row(customer, location, last_ts, threshold)
            if row[-1] == "FORA":
                exit_code = 1

        if args.only_out and row[-1] not in ("FORA", "-") and not error:
            continue

        rows.append(row)

    if args.csv:
        print_csv(rows)
    else:
        print_table(rows)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
