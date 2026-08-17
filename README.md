# BeagleRecon


I want to develop a tool that automates banner grabbing and software version collection during the initial reconnaissance phase. The tool is mainly intended for CTFs, to help identify easy “low-hanging fruit” vulnerabilities.

The CVEs and exploits will come from:

    https://gitlab.com/exploit-database/exploitdb
    https://github.com/github/advisory-database

My first idea was to build a RAG system with a vector store to embed and index the data. However, embeddings require too much compute time, and the results weren’t significantly better than simply using full-text search over the JSON and CSV files stored in a SQLite database. I decided to use full-text search instead. Lesson learned: AI isn’t always the right solution—it depends on the data and the purpose.

The work is still under construction:
### To Do

    Compare the BeagleRecon tool against a known vulnerability scanner: OpenVAS vs. BeagleRecon.



## Reconnaissance pipeline with a CVE intelligence backend:

```
nmap scan (all ports 0-65535, TCP+UDP, open only) -> banner grabbing -> version scan (-sV)
        -> SQLite FTS5 keyword search -> Ollama LLM summarizes the findings
        -> markdown report
```

## Search backend

SQLite FTS5 keyword index over the CSV/JSON: builds in ~30 seconds, pure CPU,
no Ollama needed for ingestion. Queries return bm25-ranked hits which are filtered
by product/version tokens and then summarized into the report by the Ollama LLM.

## Data sources

- [ExploitDB `files_exploits.csv`](https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv)
- [GitHub Advisory Database](https://github.com/github/advisory-database) (sparse checkout of `advisories/github-reviewed`)
- Only entries published in or after `MIN_CVE_YEAR` (default `2010`) are ingested

## Setup

```bash
pip install -r requirements.txt
ollama pull granite4:3b    # or any chat model
```

## Usage

```bash
# 1. Build the search index (~30s; --update-data refreshes sources)
python main.py ingest --update-data

# 2. Scan a target (by default: full TCP + UDP 0-65535, open ports only)
python main.py scan 192.168.0.1
python main.py scan example.com --no-udp --skip-scripts
python main.py scan 10.0.0.5 --ports 1-10000 --model Gemma3:4B

# The bare form is equivalent to 'scan': python main.py 192.168.0.1
```

Reports are written to `output/YYYY-MM-DD_HH-MM-SS_<ip>_<dns>.md` and contain:
scanned IP, DNS name, open ports with service/product/version, per-port banners and
tool output, and the vulnerability analysis (possible CVEs, vendors, severities).
If Ollama is unreachable the report falls back to an exact, non-LLM listing of the
findings.

Note: a full 0-65535 UDP scan takes a long time (30+ min). Privileges:
nmap needs root for `-sU` and `-sS`. Without privileges the UDP scan is skipped
with a warning and TCP uses `-sT` automatically.

## Running without sudo

To run the full TCP+UDP scan as a normal user, grant nmap the raw-socket
capabilities (requires nmap >= 7.95 — older builds like Ubuntu 24.04's 7.94
check for uid 0 and ignore capabilities):

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
```

Re-apply after every nmap package update (the capabilities are lost on upgrade).
Verify with:

```bash
getcap /usr/bin/nmap
# /usr/bin/nmap cap_net_bind_service,cap_net_admin,cap_net_raw=eip
```

Alternatives: run with `sudo python3 main.py <target>`, or pass `--no-udp`
(TCP connect scan works fully unprivileged).

## CLI

`python main.py [COMMAND]` (Click-based; `-h` for help, `--version`).

| Command | Purpose |
|---|---|
| `scan <target>` (or just `<target>`) | run the recon pipeline |
| `ingest` | build/update the FTS index |

`scan` options:

| Flag | Purpose |
|---|---|
| `--ports <range>` | override the TCP port range (default `0-65535`) |
| `--udp / --no-udp` | enable/disable the UDP scan (default on) |
| `--skip-scripts` | skip the nmap service scripts |
| `--no-intel` | skip the CVE search + LLM analysis |
| `--model <name>` | Ollama chat model (default `granite4:3b`) |

`ingest` options:

| Flag | Purpose |
|---|---|
| `--update-data` | re-download CSV + `git pull` advisories before building |
| `--reset` | wipe the index first (asks for confirmation, full rebuild ~30s) |
| `--limit <n>` | max chunks per source (testing) |

## Updating the index

```bash
python main.py ingest --update-data
```

- re-downloads `files_exploits.csv` and `git pull`s the advisory database
- new entries are inserted; unchanged entries (content hash) are skipped
- full rebuilds are cheap: `python main.py ingest --update-data --reset` (~30s)
- changed `MIN_CVE_YEAR` requires a `--reset` rebuild

## Configuration

`config.py` holds all knobs (env var override in parentheses):

| Key | Default | Purpose |
|---|---|---|
| `min_cve_year` (`MIN_CVE_YEAR`) | `2010` | Only ingest CVEs/exploits published this year or later |
| `ports` (`PORTS`) | `0-65535` | TCP port range for the scan |
| `udp_ports` (`UDP_PORTS`) | `0-65535` | UDP port range |
| `scan_udp` | `True` | Enable the UDP scan |
| `chat_model` (`OLLAMA_CHAT_MODEL`) | `granite4:3b` | Ollama chat model (CPU-friendly default) |
| `ollama_base_url` (`OLLAMA_BASE_URL`) | `http://localhost:11434` | Ollama endpoint |
| `data_dir` / `output_dir` | `data` / `output` | Storage locations |
| `run_nmap_scripts`, `use_intel`, `banner_timeout` | `True/True/5.0` | Pipeline toggles |

## Docker

CPU-only (default):

```bash
docker compose up -d            # ollama (CPU) + model puller + vulnerable target
docker compose --profile scan run --rm beaglerecon --ingest --reset
docker compose --profile scan run --rm beaglerecon vulnerable
```

With NVIDIA GPU:

```bash
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d
docker compose --profile scan run --rm beaglerecon --ingest --reset
docker compose --profile scan run --rm beaglerecon vulnerable
```

- `ollama` — local LLM server (models in the `ollama_models` volume)
- `model-puller` — one-shot service pulling `OLLAMA_CHAT_MODEL`
- `vulnerable` — [heywoodlh/vulnerable](https://hub.docker.com/r/heywoodlh/vulnerable) smoke-test target (SSH, ProFTPD, Apache, Samba, CUPS, MySQL, UnrealIRCd, ...)
- `beaglerecon` — one-shot scanner (profile `scan`); reports in `./output`, data in `./data`

---

# Developer Guide

## Project layout

```
config.py                  # all tunables (single source of truth)
main.py                    # Click CLI + composition root (wires everything together)
core/
  pipeline.py              # ReconPipeline: runs the stages in order
  port_scanner.py          # PortScanner: nmap open-port scan (TCP+UDP)
  version_scanner.py       # VersionScanner: nmap -sV service/version detection
  dns_resolver.py          # DnsResolver: reverse DNS
  nmap_script_runner.py    # NmapScriptRunner: runs nmap --script per service
  report_writer.py         # MarkdownReportWriter: file naming + saving
  open_port.py / service_info.py / cve_finding.py / scan_result.py   # data models
services/                  # per-service modules (the extension point for tools)
  service_module.py        # ServiceModule base class (ABC)
  tool.py                  # Tool dataclass (name, description, callable)
  service_registry.py      # ServiceRegistry: port -> module lookup
  __init__.py              # create_default_registry(): register modules here
  ssh_module.py, http_module.py, ftp_module.py, ...    # one class per file
intel/
  fts_index.py             # FtsIndex: SQLite FTS5 build + bm25 search
  fts_retriever.py         # FtsRetriever: retriever interface for the FTS index
  intel_service.py         # IntelService: retrieval orchestration + LLM synthesis
  query_planner.py         # QueryPlanner: LLM builds search queries, heuristic fallback
  relevance_filter.py      # RelevanceFilter: keeps hits matching product/version tokens
  cve_validator.py         # CveValidator: drops hallucinated CVE IDs
  ollama_llm.py            # OllamaLlm: chat/JSON wrapper
  chunker.py               # TextChunker: splits long advisory texts
  chunk.py / retrieval_result.py / search_query.py / port_analysis.py   # data models
  sources/                 # data source adapters (the extension point for new data)
    data_source.py         # DataSource ABC (ensure_local + iter_chunks)
    exploitdb_source.py    # ExploitDbSource (CSV, MIN_CVE_YEAR filtered)
    advisory_source.py     # AdvisoryDatabaseSource (GHSA JSON, MIN_CVE_YEAR filtered)
    data_downloader.py     # DataDownloader: HTTP file + git sparse sync
```

## Adding a service module (new protocol / tool support)

1. Create `services/<name>_module.py` with one class, e.g. `RedisModule`:

```python
from services.service_module import ServiceModule
from services.tool import Tool

class RedisModule(ServiceModule):
    service_name = "redis"          # key used in reports
    default_ports = (6379,)         # ports this module handles
    protocol = "tcp"                # or "udp"

    def grab_banner(self, ip, port):
        return self._recv_banner(ip, port, probe=b"INFO\r\n")

    def nmap_scripts(self):         # optional: nmap --script names
        return ["redis-info"]

    def additional_tools(self):     # optional: extra checks run per service
        return [Tool(name="redis-noauth", description="...", run=self._check_auth)]

    def _check_auth(self, ip, port):
        ...
```

2. Register it in `services/__init__.py` inside `create_default_registry()`:

```python
registry.register(RedisModule(timeout))
```

That is all — the pipeline automatically grabs its banner, runs its nmap scripts
and tools, and includes the output in the report. `_recv_banner(ip, port,
probe=..., use_ssl=...)` in `service_module.py` is a helper for TCP/TLS banners.

## Adding a new data source

1. Create `intel/sources/<name>_source.py` subclassing `DataSource`:

```python
class MySource(DataSource):
    name = "myfeed"           # printed in logs
    collection = "myfeed"     # grouping label for chunks
    id_prefix = "my"          # chunk id prefix

    def ensure_local(self, update=False):   # download/sync, return path
        ...

    def iter_chunks(self, limit=0):         # yield intel.chunk.Chunk objects
        ...
```

`Chunk` fields: `id` (unique), `text` (what gets FTS-indexed),
`collection`, `metadata` (dict with `cves`, `url`, etc. for the report).

2. Register it in `build_sources()` in `main.py` (add to the `sources` list).

## Adding a pipeline stage

`core/pipeline.py` → `ReconPipeline.run()` executes the stages in order:
DNS → port scan → banners → version scan → scripts/tools → CVE search → report.
Add your step there and keep single-responsibility methods (one method = one stage).

## Where things are tuned

- Version matching strictness: `intel/relevance_filter.py`
- LLM behaviour: `SYNTHESIS_SYSTEM_PROMPT` in `intel/intel_service.py`,
  `QUERY_SYSTEM_PROMPT` in `intel/query_planner.py`
- Report layout: `ReconPipeline._build_report()` in `core/pipeline.py`

## Testing

```bash
python main.py ingest --limit 500         # quick partial ingest
python main.py 127.0.0.1 --ports 22,631 --no-udp   # quick scan
```

Full integration test target: the `vulnerable` container from docker-compose
(SSH, ProFTPD, Apache, Samba, CUPS, MySQL, UnrealIRCd, ...).
