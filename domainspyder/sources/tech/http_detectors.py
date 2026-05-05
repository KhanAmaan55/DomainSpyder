"""
HTTP header-based technology detectors.

Detects web servers, backend frameworks, and CDN/edge providers
by inspecting HTTP response headers and cookies.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from domainspyder.sources.tech.helpers import (
    boost,
    finalize_all,
    header_blob,
    new_candidate,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Server detection
# ------------------------------------------------------------------

def detect_server(headers: dict[str, str]) -> list[dict[str, Any]]:
    """
    Detect the likely web server from HTTP response headers.
    
    Parameters:
        headers (dict[str, str]): Response headers (keys expected lower/upper-case agnostic).
    
    Returns:
        list[dict[str, Any]]: Ranked list of candidate server dictionaries with scoring metadata.
    """
    server_val = headers.get("server", "").lower()

    candidates = {
        name: new_candidate()
        for name in [
            "nginx", "Apache", "IIS", "Caddy",
            "LiteSpeed", "Gunicorn", "Cloudflare", "Kestrel",
        ]
    }

    if "nginx" in server_val:
        boost(candidates["nginx"], 2, 9)
    if "apache" in server_val:
        boost(candidates["Apache"], 2, 9)
    if "microsoft-iis" in server_val or "iis" in server_val:
        boost(candidates["IIS"], 2, 9)
    if "caddy" in server_val:
        boost(candidates["Caddy"], 2, 9)
    if "litespeed" in server_val or "lsws" in server_val:
        boost(candidates["LiteSpeed"], 2, 9)
    if "gunicorn" in server_val:
        boost(candidates["Gunicorn"], 2, 9)
    if "cloudflare" in server_val:
        boost(candidates["Cloudflare"], 2, 9)
    if "kestrel" in server_val:
        boost(candidates["Kestrel"], 2, 9)

    return finalize_all(candidates)


# ------------------------------------------------------------------
# Backend detection
# ------------------------------------------------------------------

def detect_backend(
    headers: dict[str, str],
    cookies: dict[str, str],
) -> list[dict[str, Any]]:
    """
    Infer the most likely backend language or framework from HTTP response headers and cookies.
    
    This function examines header values (e.g., `X-Powered-By`, `Server`, `Set-Cookie`) and cookie names to build and score candidate backends, then returns a ranked list.
    
    Parameters:
        headers (dict[str, str]): Response headers (header names and their values).
        cookies (dict[str, str]): Cookie names mapped to their values.
    
    Returns:
        list[dict[str, Any]]: Ranked candidate dictionaries describing possible backends (e.g., name, score, metadata).
    """
    x_powered = headers.get("x-powered-by", "").lower()
    server_val = headers.get("server", "").lower()
    set_cookie = headers.get("set-cookie", "").lower()
    blob = f"{x_powered} {server_val} {set_cookie}"

    candidates = {
        name: new_candidate()
        for name in [
            "PHP", "Node.js", "Java", "Python",
            "Ruby", "ASP.NET", "Go",
        ]
    }

    # PHP
    if "php" in blob:
        boost(candidates["PHP"], 2, 8)
    if "phpsessid" in cookies:
        boost(candidates["PHP"], 1, 3)
    if re.search(r"php/[\d.]", x_powered):
        boost(candidates["PHP"], 1, 2)

    # Node.js / Express / Next
    if any(t in blob for t in ["express", "node.js", "next.js"]):
        boost(candidates["Node.js"], 2, 7)
    if any(n in cookies for n in [
        "connect.sid", "__next_preview_data", "next-auth.session-token",
    ]):
        boost(candidates["Node.js"], 1, 3)
    if headers.get("x-powered-by", "").lower() == "next.js":
        boost(candidates["Node.js"], 1, 3)

    # Java / Spring / JEE
    if any(t in blob for t in ["jsp", "servlet", "spring", "jsessionid", "java"]):
        boost(candidates["Java"], 2, 7)
    if "jsessionid" in cookies:
        boost(candidates["Java"], 1, 3)

    # Python (Django / Flask / FastAPI)
    if any(t in blob for t in [
        "django", "flask", "fastapi", "python", "werkzeug", "uvicorn",
    ]):
        boost(candidates["Python"], 2, 7)
    if "csrftoken" in cookies:
        boost(candidates["Python"], 1, 3)
    if "sessionid" in cookies and "csrftoken" in cookies:
        boost(candidates["Python"], 1, 2)

    # Ruby on Rails
    if any(t in blob for t in ["ruby", "rails", "rack", "passenger", "phusion"]):
        boost(candidates["Ruby"], 2, 7)
    if "_session_id" in cookies or "_rails_session" in cookies:
        boost(candidates["Ruby"], 1, 3)

    # ASP.NET / .NET Core
    if any(t in blob for t in [
        "asp.net", "aspnetcore", ".net", "aspxerrorpath", "webmatrix",
    ]):
        boost(candidates["ASP.NET"], 2, 8)
    if "asp.net_sessionid" in cookies or ".aspxauth" in cookies:
        boost(candidates["ASP.NET"], 1, 3)
    if "x-aspnet-version" in headers or "x-aspnetmvc-version" in headers:
        boost(candidates["ASP.NET"], 2, 5)

    # Go
    if any(t in blob for t in ["go ", "golang", "gin-gonic", "gorilla", "echo"]):
        boost(candidates["Go"], 2, 6)
    if server_val in ("", "go") or "go/" in server_val:
        boost(candidates["Go"], 1, 3)

    return finalize_all(candidates)


# ------------------------------------------------------------------
# CDN / edge detection
# ------------------------------------------------------------------

def detect_cdn(headers: dict[str, str]) -> list[dict[str, Any]]:
    """
    Infer likely CDN or edge providers from HTTP response headers and return ranked candidates.
    
    Parameters:
        headers (dict[str, str]): HTTP response headers; header names are typically lowercased (values may be any case).
    
    Returns:
        list[dict[str, Any]]: A ranked list of candidate CDN/edge providers with associated scoring metadata.
    """
    candidates = {
        name: new_candidate()
        for name in [
            "Cloudflare", "AWS CloudFront", "Vercel", "Fastly",
            "Akamai", "Azure CDN", "Google Cloud", "BunnyCDN", "Netlify",
        ]
    }

    server_val = headers.get("server", "").lower()
    via_val = headers.get("via", "").lower()
    x_cache = headers.get("x-cache", "").lower()

    # Cloudflare
    if "cf-ray" in headers:
        boost(candidates["Cloudflare"], 2, 9)
    if "cloudflare" in server_val:
        boost(candidates["Cloudflare"], 2, 9)
    if "cf-cache-status" in headers:
        boost(candidates["Cloudflare"], 1, 3)
    if "__cf_bm" in headers.get("set-cookie", "").lower():
        boost(candidates["Cloudflare"], 1, 3)

    # AWS CloudFront
    if "x-amz-cf-id" in headers:
        boost(candidates["AWS CloudFront"], 2, 9)
    if "cloudfront" in via_val or "cloudfront" in x_cache:
        boost(candidates["AWS CloudFront"], 2, 8)
    if "x-amz-cf-pop" in headers:
        boost(candidates["AWS CloudFront"], 1, 3)
    if "from cloudfront" in x_cache:
        boost(candidates["AWS CloudFront"], 2, 8)

    # Vercel
    if "x-vercel-id" in headers:
        boost(candidates["Vercel"], 2, 9)
    if "vercel" in server_val or "vercel" in via_val:
        boost(candidates["Vercel"], 1, 5)

    # Fastly
    if "x-served-by" in headers and "cache-" in headers.get("x-served-by", "").lower():
        boost(candidates["Fastly"], 1, 4)
    if "fastly" in via_val or "fastly" in x_cache:
        boost(candidates["Fastly"], 2, 8)
    if "x-fastly-request-id" in headers:
        boost(candidates["Fastly"], 2, 9)
    if "surrogate-control" in headers:
        boost(candidates["Fastly"], 1, 3)

    # Akamai
    if "x-check-cacheable" in headers:
        boost(candidates["Akamai"], 1, 5)
    if "akamai" in via_val or "akamaiedge" in via_val:
        boost(candidates["Akamai"], 2, 8)
    if "x-akamai-transformed" in headers or "akamai-cache-status" in headers:
        boost(candidates["Akamai"], 2, 7)
    if "edgescape" in headers.get("x-akamai-session-info", "").lower():
        boost(candidates["Akamai"], 1, 3)

    # Azure CDN / Front Door
    if "x-azure-ref" in headers:
        boost(candidates["Azure CDN"], 2, 9)
    if "x-fd-int-roxy-purgeid" in headers or "x-msedge-ref" in headers:
        boost(candidates["Azure CDN"], 2, 8)
    if "azure" in via_val:
        boost(candidates["Azure CDN"], 1, 5)

    # Google Cloud CDN / Firebase Hosting
    if "x-goog-storage-status" in headers or "x-guploader-uploadid" in headers:
        boost(candidates["Google Cloud"], 1, 5)
    if "gcs" in x_cache or "google" in via_val:
        boost(candidates["Google Cloud"], 1, 4)
    if "firebase" in server_val:
        boost(candidates["Google Cloud"], 2, 7)

    # BunnyCDN
    if "bunnycdn" in headers.get("server", "").lower():
        boost(candidates["BunnyCDN"], 2, 9)
    if "cdn-pullzone" in headers or "cdn-uid" in headers:
        boost(candidates["BunnyCDN"], 2, 9)
    if "bunny-cache-status" in headers:
        boost(candidates["BunnyCDN"], 1, 3)

    # Netlify
    if "x-nf-request-id" in headers:
        boost(candidates["Netlify"], 2, 9)
    if "netlify" in server_val:
        boost(candidates["Netlify"], 2, 9)
    if "x-netlify-vary" in headers or "x-netlify-cache" in headers:
        boost(candidates["Netlify"], 1, 3)

    return finalize_all(candidates)
