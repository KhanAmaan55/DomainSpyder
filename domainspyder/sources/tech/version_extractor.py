"""
Version extraction from technology signals.

Extracts version numbers from HTTP headers, meta generator tags,
script URLs, and HTML body patterns. Returns a mapping of
technology name → version string.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)


def extract_versions(
    headers: dict[str, str],
    body: str,
    scripts: list[str],
    meta_generator: str | None,
) -> dict[str, str]:
    """
    Extract version numbers from provided signals and collect them into a mapping.
    
    Scans the optional meta generator string, HTTP headers, script URLs, and HTML body for known technology/version patterns and aggregates the first-found version for each technology into a dictionary.
    
    Parameters:
        meta_generator (str | None): Optional generator/meta tag content to parse for known CMS or static-site generator versions.
    
    Returns:
        dict[str, str]: Mapping from technology name (e.g., "React", "nginx") to the extracted version string; empty if no versions were found.
    """
    versions: dict[str, str] = {}

    # --- From meta generator tag ---
    if meta_generator:
        _extract_generator_version(meta_generator, versions)

    # --- From HTTP headers ---
    _extract_header_versions(headers, versions)

    # --- From script URLs ---
    _extract_script_versions(scripts, versions)

    # --- From HTML body ---
    _extract_body_versions(body, versions)

    logger.debug("Version extractor: found %d versions: %s", len(versions), versions)
    return versions


def _extract_generator_version(
    generator: str,
    versions: dict[str, str],
) -> None:
    """
    Extracts a technology version from a meta generator string and records it in the provided versions mapping.
    
    Parameters:
        generator (str): Meta generator string to parse (e.g., "WordPress 6.5.3").
        versions (dict[str, str]): Mutable mapping to populate with technology name -> version. The function adds the first matching technology and its version (trailing periods removed) and returns immediately after a successful match.
    """
    # Common pattern: "Name Version" or "Name/Version"
    patterns = [
        (r"wordpress\s+([\d.]+)", "WordPress"),
        (r"drupal\s+([\d.]+)", "Drupal"),
        (r"joomla[!\s]*([\d.]+)", "Joomla"),
        (r"ghost\s+([\d.]+)", "Ghost"),
        (r"hugo\s+([\d.]+)", "Hugo"),
        (r"jekyll\s+v?([\d.]+)", "Jekyll"),
        (r"hexo\s+([\d.]+)", "Hexo"),
        (r"gatsby\s+([\d.]+)", "Gatsby"),
        (r"nuxt\s+([\d.]+)", "Nuxt.js"),
        (r"next\.js\s+([\d.]+)", "Next.js"),
    ]

    gen_lower = generator.lower()
    for pattern, name in patterns:
        match = re.search(pattern, gen_lower)
        if match:
            versions[name] = match.group(1).rstrip(".")
            logger.debug(
                "Version from generator: %s = %s", name, versions[name],
            )
            return


def _extract_header_versions(
    headers: dict[str, str],
    versions: dict[str, str],
) -> None:
    """
    Extract technology version numbers from HTTP headers and add them to `versions`.
    
    This inspects Server, X-Powered-By and related headers for known product/version patterns
    (e.g., nginx, Apache, IIS, LiteSpeed, Caddy, PHP, Express, ASP.NET) and, on match,
    inserts technology -> version into `versions` without overwriting existing entries.
    
    Parameters:
        headers (dict[str, str]): Mapping of header names to values. Header keys are expected
            to be in lower-case (e.g., "server", "x-powered-by", "x-aspnet-version").
        versions (dict[str, str]): Mutable mapping to populate with extracted technology versions;
            existing keys in this dict will not be changed.
    """
    _header_patterns = [
        ("server", r"nginx/([\d.]+)", "nginx"),
        ("server", r"apache/([\d.]+)", "Apache"),
        ("server", r"microsoft-iis/([\d.]+)", "IIS"),
        ("server", r"litespeed[/ ]([\d.]+)", "LiteSpeed"),
        ("server", r"caddy[/ ]([\d.]+)", "Caddy"),
        ("x-powered-by", r"php/([\d.]+)", "PHP"),
        ("x-powered-by", r"express[/ ]([\d.]+)", "Express"),
        ("x-powered-by", r"asp\.net[/ ]([\d.]+)", "ASP.NET"),
        ("x-aspnet-version", r"([\d.]+)", "ASP.NET"),
    ]

    for header_key, pattern, name in _header_patterns:
        value = headers.get(header_key, "")
        if not value:
            continue
        match = re.search(pattern, value, re.IGNORECASE)
        if match and name not in versions:
            versions[name] = match.group(1).rstrip(".")
            logger.debug(
                "Version from header %s: %s = %s",
                header_key, name, versions[name],
            )


def _extract_script_versions(
    scripts: list[str],
    versions: dict[str, str],
) -> None:
    """
    Extracts technology version numbers from a list of script source URLs and records them into the provided versions mapping.
    
    Scans the concatenated script URLs for known library/framework version patterns (e.g., React, Vue, jQuery, Bootstrap, Angular, etc.) and, for each match, stores the captured version string (with any trailing period removed) under the corresponding human-readable technology name in `versions`. Existing entries in `versions` are not overwritten.
    
    Parameters:
        scripts (list[str]): List of script `src` values or URLs to scan for version substrings.
        versions (dict[str, str]): Mutable mapping to populate with detected technologies and their versions.
    """
    _script_version_patterns = [
        (r"react[@/]([\d.]+)", "React"),
        (r"react-dom[@/]([\d.]+)", "React"),
        (r"vue[@/]([\d.]+)", "Vue"),
        (r"angular[@/]([\d.]+)", "Angular"),
        (r"jquery[/-]([\d.]+)", "jQuery"),
        (r"bootstrap[/-]([\d.]+)", "Bootstrap"),
        (r"lodash[@/]([\d.]+)", "Lodash"),
        (r"moment[@/]([\d.]+)", "Moment.js"),
        (r"d3[@/]v?([\d.]+)", "D3.js"),
        (r"chart\.js[@/]([\d.]+)", "Chart.js"),
        (r"three[@/]([\d.]+)", "Three.js"),
        (r"axios[@/]([\d.]+)", "Axios"),
        (r"socket\.io[@/]([\d.]+)", "Socket.IO"),
        (r"gsap[@/]([\d.]+)", "GSAP"),
        (r"swiper[@/]([\d.]+)", "Swiper.js"),
    ]

    blob = " ".join(scripts)
    for pattern, name in _script_version_patterns:
        if name not in versions:
            match = re.search(pattern, blob, re.IGNORECASE)
            if match:
                versions[name] = match.group(1).rstrip(".")
                logger.debug(
                    "Version from script URL: %s = %s", name, versions[name],
                )


def _extract_body_versions(
    body: str,
    versions: dict[str, str],
) -> None:
    """
    Extract technology versions from HTML body text and populate the provided mapping.
    
    Scans the HTML body for known version markers (Angular, React, jQuery, Bootstrap, Vue) and, for each match not already present in `versions`, stores the captured version string (with trailing periods removed) under the technology name.
    
    Parameters:
        body (str): HTML body text to scan for version markers.
        versions (dict[str, str]): Mutable mapping to populate with technology -> version; existing keys are preserved.
    """
    _body_patterns = [
        (r'ng-version="([\d.]+)"', "Angular"),
        (r'data-reactroot.*react@([\d.]+)', "React"),
        (r'jquery v([\d.]+)', "jQuery"),
        (r'bootstrap v([\d.]+)', "Bootstrap"),
        (r'vue\.js v([\d.]+)', "Vue"),
    ]

    for pattern, name in _body_patterns:
        if name not in versions:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                versions[name] = match.group(1).rstrip(".")
                logger.debug(
                    "Version from body: %s = %s", name, versions[name],
                )
