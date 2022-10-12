import asyncio
import dataclasses
import json
import logging
import re
from pathlib import Path
from typing import List, Optional, Tuple, Pattern
from urllib.parse import urlparse

import aiohttp

default_fingerprints = {
    "AWS/S3": {"pattern": r"The specified bucket does not exist"},
    "BitBucket": {"pattern": r"Repository not found"},
    "Github": {"pattern": r"There isn\'t a Github Pages site here\."},
    "Shopify": {"pattern": r"Sorry\, this shop is currently unavailable\."},
    "Fastly": {"pattern": r"Fastly pattern\: unknown domain\:"},
    "Ghost": {
        "pattern": r"The thing you were looking for is no longer here\, or never was"
    },
    "Heroku": {
        "pattern": r"no-such-app.html|<title>no such app</title>|herokucdn.com/pattern-pages/no-such-app.html"
    },
    "Pantheon": {
        "pattern": r"The gods are wise, but do not know of the site which you seek."
    },
    "Tumbler": {
        "pattern": r"Whatever you were looking for doesn\'t currently exist at this address."
    },
    "Wordpress": {"pattern": r"Do you want to register"},
    "TeamWork": {"pattern": r"Oops - We didn\'t find your site."},
    "Helpjuice": {"pattern": r"We could not find what you\'re looking for."},
    "Helpscout": {"pattern": r"No settings were found for this company:"},
    "Cargo": {"pattern": r"<title>404 &mdash; File not found</title>"},
    "Uservoice": {"pattern": r"This UserVoice subdomain is currently available!"},
    "Surge": {"pattern": r"project not found"},
    "Intercom": {
        "pattern": r"This page is reserved for artistic dogs\.|Uh oh\. That page doesn\'t exist</h1>"
    },
    "Webflow": {
        "pattern": r"<p class=\"description\">The page you are looking for doesn\'t exist or has been moved.</p>"
    },
    "Kajabi": {"pattern": r"<h1>The page you were looking for doesn\'t exist.</h1>"},
    "Thinkific": {
        "pattern": r"You may have mistyped the address or the page may have moved."
    },
    "Tave": {"pattern": r"<h1>pattern 404: Page Not Found</h1>"},
    "Wishpond": {"pattern": r"<h1>https://www.wishpond.com/404?campaign=true"},
    "Aftership": {
        "pattern": r"Oops.</h2><p class=\"text-muted text-tight\">The page you\'re looking for doesn\'t exist."
    },
    "Aha": {"pattern": r"There is no portal here \.\.\. sending you back to Aha!"},
    "Tictail": {
        "pattern": r"to target URL: <a href=\"https://tictail.com|Start selling on Tictail."
    },
    "Brightcove": {
        "pattern": r"<p class=\"bc-gallery-pattern-code\">pattern Code: 404</p>"
    },
    "Bigcartel": {"pattern": r"<h1>Oops! We couldn&#8217;t find that page.</h1>"},
    "ActiveCampaign": {"pattern": r"alt=\"LIGHTTPD - fly light.\""},
    "Campaignmonitor": {
        "pattern": r"Double check the URL or <a href=\"mailto:help@createsend.com"
    },
    "Acquia": {
        "pattern": r"The site you are looking for could not be found.|If you are an Acquia Cloud customer and expect to see your site at this address"
    },
    "Proposify": {
        "pattern": r"If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz"
    },
    "Simplebooklet": {
        "pattern": r"We can\'t find this <a href=\"https://simplebooklet.com"
    },
    "GetResponse": {
        "pattern": r"With GetResponse Landing Pages, lead generation has never been easier"
    },
    "Vend": {"pattern": r"Looks like you\'ve traveled too far into cyberspace."},
    "Jetbrains": {"pattern": r"is not a registered InCloud YouTrack."},
    "Smartling": {"pattern": r"Domain is not configured"},
    "Pingdom": {"pattern": r"pingdom"},
    "Tilda": {"pattern": r"Domain has been assigned"},
    "Surveygizmo": {"pattern": r"data-html-name"},
    "Mashery": {"pattern": r"Unrecognized domain <strong>"},
    "Divio": {"pattern": r"Application not responding"},
    "feedpress": {"pattern": r"The feed has not been found."},
    "readme": {"pattern": r"Project doesnt exist... yet!"},
    "statuspage": {"pattern": r"You are being <a href=\'https>"},
    "zendesk": {"pattern": r"Help Center Closed"},
    "worksites.net": {"pattern": r"Hello! Sorry, but the webs>"},
    "wix": {"pattern": r"Looks Like This Domain Isn\'t Connected To A Website Yet!"},
}


@dataclasses.dataclass()
class RegexFingerprint:
    name: str
    pattern: Pattern
    process_200: bool


@dataclasses.dataclass
class Options:
    domains: List[str]
    headers: List[Tuple[str, str]]
    concurrency: int
    verbosity: int
    proxy: str
    fingerprints: List[RegexFingerprint]
    ssl: bool
    timeout: Optional[float]


async def token_bucket(concurrency: int) -> asyncio.Queue:
    tokens = asyncio.Queue(maxsize=-1)
    for _ in range(concurrency):
        await tokens.put(None)
    return tokens


async def scan(
    options: Options, logger: logging.Logger = logging.getLogger(__name__)
) -> List[Tuple[str, RegexFingerprint]]:
    results = []
    tasks = []
    tokens = await token_bucket(options.concurrency)
    async with aiohttp.ClientSession(
        headers=options.headers,
        timeout=aiohttp.ClientTimeout(total=options.timeout)
        if options.timeout
        else aiohttp.client.sentinel,
    ) as cs:
        for d in options.domains:
            await tokens.get()
            tasks.append(
                asyncio.create_task(
                    scan_one(
                        cs,
                        d,
                        options.ssl,
                        options.fingerprints,
                        options.proxy,
                        tokens,
                        results,
                        logger,
                    )
                )
            )
        await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
    return results


def url_of(t: str, ssl: bool):
    parsed = urlparse(t)
    if parsed.scheme in ("http", "https"):
        return t
    if not parsed.scheme:
        return f"https://{t}/" if ssl else f"http://{t}/"
    raise ValueError(f"Bad url scheme in {t!r}")


async def scan_one(
    cs: aiohttp.ClientSession,
    target: str,
    ssl: bool,
    fingerprints: List[RegexFingerprint],
    proxy: Optional[str],
    tokens: asyncio.Queue,
    results: List[Tuple[str, RegexFingerprint]],
    logger: logging.Logger,
):

    logger.info(f"Checking {target!r}...")
    try:
        match = await check_target(cs, target, ssl, proxy, fingerprints)
        if match:
            results.append((target, match))
    except Exception as e:
        logger.exception(f"Got exception while checking {target!r}: {e!r}", exc_info=e)
    else:
        logger.info(
            f"Finished {target!r}. {'Matched %s' % match.name if match else 'No matches'}."
        )
    finally:
        await tokens.put(None)


def fingerprints_from(path: Optional[str]) -> List[RegexFingerprint]:
    if path:
        fingerprints = json.loads(Path(path).read_text())
    else:
        fingerprints = default_fingerprints
    try:
        return [
            RegexFingerprint(
                name,
                re.compile(data["pattern"], re.IGNORECASE),
                data.get("process_200", False),
            )
            for name, data in fingerprints.items()
        ]
    except Exception as e:
        raise ValueError("Bad fingerprints format") from e


async def check_target(
    cs: aiohttp.ClientSession,
    target: str,
    ssl: bool,
    proxy: Optional[str],
    fingerprints: List[RegexFingerprint],
) -> Optional[RegexFingerprint]:
    async with cs.get(url_of(target, ssl), proxy=proxy) as resp:
        try:
            text = await resp.text()
        except UnicodeDecodeError:
            return None
    return find_match(fingerprints, text, resp.status)


def find_match(
    fingerprints: List[RegexFingerprint], text: str, status_code: int
) -> Optional[RegexFingerprint]:
    for f in fingerprints:
        if (status_code in range(201, 599) or f.process_200) and f.pattern.findall(
            text
        ):
            return f
    return None
