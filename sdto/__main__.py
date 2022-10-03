import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import List, Tuple, Optional

import sdto
from sdto.sdto import Options, scan, fingerprints_from, RegexFingerprint

try:
    import click
except ImportError:
    print(
        "You need to reinstall this library with 'pip install sdto[cli]' to be able to use it as a CLI tool\n",
        file=sys.stderr,
    )
    raise


@click.command(help="sdto - subdomain takeover scanner")
@click.option(
    "--target",
    "-t",
    help="domain(s) to scan",
    multiple=True,
)
@click.option("--targets-list", "-l", help="domains list in a file")
@click.option(
    "--header",
    "-H",
    type=(str, str),
    help="HTTP headers",
    multiple=True,
)
@click.option(
    "--concurrency",
    default=5,
    help="max number of concurrent requests",
    type=click.IntRange(1, 100),
)
@click.option(
    "--timeout",
    "-T",
    help="HTTP requests timeout (seconds)",
    type=click.FloatRange(0, 120, min_open=True),
)
@click.option("--proxy", "-p", help="proxy to use")
@click.option("--output", "-o", help="output to")
@click.option(
    "--output-format",
    "-F",
    type=click.Choice(["txt", "json"], case_sensitive=False),
    default="txt",
    help="output format. either 'txt' or 'json'",
)
@click.option("--fingerprints", "-f", help="fingerprints file path")
@click.option(
    "--no-ssl",
    is_flag=True,
    default=True,
)
@click.option("-v", "--verbose", count=True)
def main(
    target: List[str],
    header: List[Tuple[str, str]],
    concurrency: int,
    verbose: int,
    proxy: Optional[str],
    output: Optional[str],
    output_format: str,
    targets_list: Optional[str],
    fingerprints: Optional[str],
    no_ssl: bool,
    timeout: Optional[float],
):
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    logger = logging.getLogger(__name__)
    if verbose == 0:
        logging.basicConfig(format=log_format, level=logging.WARNING)
    elif verbose == 1:
        logging.basicConfig(format=log_format, level=logging.INFO)
    else:
        logging.basicConfig(format=log_format, level=logging.DEBUG)
    options = Options(
        domains=domains_from(targets_list, target),
        headers=headers_from(header),
        concurrency=concurrency,
        verbosity=verbose,
        proxy=proxy,
        fingerprints=fingerprints_from(fingerprints),
        ssl=not no_ssl,
        timeout=timeout,
    )
    print_banner(sdto.__version__)
    matches = asyncio.run(scan(options, logger=logger))
    write(matches, output_format, output)


def print_banner(version: str):
    p = lambda t: print(t, file=sys.stderr)
    p("\n")
    p("   _______  __________ ")
    p("  / __/ _ \\/_  __/ __ \\")
    p(" _\\ \\/ // / / / / /_/ /")
    p(f"/___/____/ /_/  \\____/\t\t{version}")
    p(f"\t\t\tscanfactory.io")
    p(f"https://github.com/scanfactory/sdto")
    p("\n")


def write(
    matches: List[Tuple[str, RegexFingerprint]],
    fmt: str,
    output_to: Optional[str],
):
    if not output_to:
        print(to_string(matches, fmt))
    else:
        Path(output_to).write_text(to_string(matches, fmt))


def to_string(matches: List[Tuple[str, RegexFingerprint]], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(
            [{"target": target, "match": f.name} for target, f in matches]
        )
    return "\n".join(
        f"✨✨✨ Potential takeover: [{target}] -> {f.name} ✨✨✨" for target, f in matches
    )


def headers_from(headers_param: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    headers = [(n.lower(), v) for n, v in headers_param]
    names = frozenset(h for h, _ in headers)
    if "user-agent" not in names:
        headers.append(
            (
                "user-agent",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            )
        )
    if "accept-language" not in names:
        headers.append(("accept-language", "en-US,en;q=0.5"))
    return headers


def domains_from(domains_path: str, domains: List[str]) -> List[str]:
    if domains_path:
        return [i.strip() for i in Path(domains_path).read_text().split() if i.strip()]
    if domains:
        return domains
    raise TypeError("Either --domain or --domains-list must be specified")


if __name__ == "__main__":
    main()
