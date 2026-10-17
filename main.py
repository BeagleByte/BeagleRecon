#!/usr/bin/env python3
import click

from config import Config
from core.dns_resolver import DnsResolver
from core.nmap_script_runner import NmapScriptRunner
from core.pipeline import ReconPipeline
from core.port_scanner import PortScanner
from core.report_writer import MarkdownReportWriter
from core.version_scanner import VersionScanner
from intel.fts_index import FtsIndex
from intel.fts_retriever import FtsRetriever
from intel.intel_service import IntelService
from intel.ollama_llm import OllamaLlm
from intel.query_planner import QueryPlanner
from intel.sources.advisory_source import AdvisoryDatabaseSource
from intel.sources.exploitdb_source import ExploitDbSource
from services import create_default_registry

VERSION = "0.2.0"

BANNER = r"""
 .oPYo.                      8           .oPYo.                            
 8   `8                      8           8   `8                            
o8YooP' .oPYo. .oPYo. .oPYo. 8 .oPYo.   o8YooP' .oPYo. .oPYo. .oPYo. odYo. 
 8   `b 8oooo8 .oooo8 8    8 8 8oooo8    8   `b 8oooo8 8    ' 8    8 8' `8 
 8    8 8.     8    8 8    8 8 8.        8    8 8.     8    . 8    8 8   8 
 8oooP' `Yooo' `YooP8 `YooP8 8 `Yooo'    8    8 `Yooo' `YooP' `YooP' 8   8 
:......::.....::.....::....8 ..:.....::::..:::..:.....::.....::.....:..::..
::::::::::::::::::::::::ooP'.::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::...::::::::::::::::::::::::::::::::::::::::::::::::
"""


class BeagleGroup(click.Group):
    """Group that treats a bare target as the 'scan' command."""

    def parse_args(self, ctx, args):
        if args and not args[0].startswith("-") and args[0] not in self.commands:
            args.insert(0, "scan")
        return super().parse_args(ctx, args)


def build_sources(config: Config) -> list:
    return [ExploitDbSource(config), AdvisoryDatabaseSource(config)]


def build_intel_service(config: Config) -> IntelService:
    llm = OllamaLlm(config)
    planner = QueryPlanner(config, llm)
    index = FtsIndex(config)
    return IntelService(config, llm, planner, FtsRetriever(index))


def build_pipeline(config: Config) -> ReconPipeline:
    intel_service = build_intel_service(config) if config.use_intel else None
    return ReconPipeline(
        config=config,
        port_scanner=PortScanner(config),
        version_scanner=VersionScanner(config),
        dns_resolver=DnsResolver(),
        script_runner=NmapScriptRunner(),
        registry=create_default_registry(timeout=config.banner_timeout),
        intel_service=intel_service,
        report_writer=MarkdownReportWriter(config),
    )


@click.group(cls=BeagleGroup, invoke_without_command=True, no_args_is_help=True,
             context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(VERSION, prog_name="BeagleRecon")
def cli():
    """BeagleRecon - nmap scan, banner grabbing, CVE intelligence, LLM report."""
    pass


@cli.command()
@click.argument("target")
@click.option("--ports", help="nmap port range (default: 0-65535)")
@click.option("--all-ports", is_flag=True, help="scan all TCP ports (default)")
@click.option("--udp/--no-udp", default=True, help="enable/disable the UDP scan")
@click.option("--skip-scripts", is_flag=True, help="skip the nmap service scripts")
@click.option("--no-intel", is_flag=True, help="skip the CVE search + LLM analysis")
@click.option("--model", help="ollama chat model")
@click.option("--data-dir", type=click.Path(file_okay=False), help="raw data directory")
@click.option("--output-dir", type=click.Path(file_okay=False), help="report output directory")
def scan(target, ports, all_ports, udp, skip_scripts, no_intel, model, data_dir, output_dir):
    """Scan TARGET and write a vulnerability report to the output directory."""
    config = Config(target=target)
    if ports:
        config.ports = ports
    if all_ports:
        config.ports = "1-65535"
    config.scan_udp = udp
    if skip_scripts:
        config.run_nmap_scripts = False
    if no_intel:
        config.use_intel = False
    if model:
        config.chat_model = model
    if data_dir:
        config.data_dir = data_dir
    if output_dir:
        config.output_dir = output_dir

    click.secho(BANNER, fg="cyan", bold=True)
    click.secho(f"Scanning {target} ...", fg="cyan")
    try:
        report_path = build_pipeline(config).run(target)
    except Exception as exc:
        raise click.ClickException(f"scan failed: {exc}") from exc
    click.secho(f"Report written to {report_path}", fg="green", bold=True)


@cli.command()
@click.option("--update-data", is_flag=True, help="re-download CSV and git pull advisories first")
@click.option("--reset", is_flag=True, help="wipe the index first (full rebuild, ~30s)")
@click.option("--limit", type=int, default=0, help="max chunks per source (testing)")
@click.option("--data-dir", type=click.Path(file_okay=False), help="raw data directory")
def ingest(update_data, reset, limit, data_dir):
    """Build or update the FTS search index."""
    config = Config()
    if limit:
        config.source_limit = limit
    if data_dir:
        config.data_dir = data_dir

    index = FtsIndex(config)
    if reset and index.exists():
        click.secho(f"Index exists with {index.count():,} rows.", fg="yellow")
        click.confirm("Wipe the index and rebuild from scratch?", abort=True)

    click.secho("Building search index ...", fg="cyan")
    try:
        index.build(build_sources(config), update=update_data, reset=reset, limit=limit)
    except Exception as exc:
        raise click.ClickException(f"ingest failed: {exc}") from exc
    click.secho(f"Index ready: {index.count():,} rows", fg="green", bold=True)

@cli.command()
@click.argument("domain")
@click.option("--ip", required=True, help="target IP (from the stage-1 scan)")
@click.option("--ports", default=None, help="HTTP ports, comma list (default: auto from latest scan report)")
@click.option("--wordlist", type=click.Path(exists=True), default=None, help="directory wordlist")
@click.option("--api-wordlist", type=click.Path(exists=True), default=None, help="API wordlist")
@click.option("--vhost-wordlist", type=click.Path(exists=True), default=None, help="vhost wordlist")
@click.option("--threads", type=int, default=50, help="ferox/ffuf threads")
def web(domain, ip, ports, wordlist, api_wordlist, vhost_wordlist, threads):
    """Stage 2 (manual): run feroxbuster + ffuf agents against DOMAIN.

    Set the domain in /etc/hosts first - CTFs have no DNS server."""
    from AG2.agents.web_team import WebReconTeam

    config = Config()
    if ports:
        port_list = [int(p.strip()) for p in ports.split(",")]
    else:
        port_list = WebReconTeam(config).discover_http_ports(ip)
        if not port_list:
            raise click.ClickException(
                "no HTTP ports found in scan reports - pass --ports 80,443"
            )
    wordlists = {
        "dirs": wordlist or config.ferox_wordlist,
        "api": api_wordlist or config.ffuf_api_wordlist,
        "vhost": vhost_wordlist or config.ffuf_vhost_wordlist,
    }
    click.secho(f"Web recon: {domain} ({ip}) ports {port_list}", fg="cyan")
    try:
        report = WebReconTeam(config).run(domain, ip, port_list, wordlists)
    except Exception as exc:
        raise click.ClickException(f"web recon failed: {exc}") from exc
    click.secho(f"Report: {report}", fg="green", bold=True)

if __name__ == "__main__":
    cli()
