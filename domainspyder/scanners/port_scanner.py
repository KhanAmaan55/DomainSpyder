"""
DomainSpyder port scanner.

Performs TCP connect scans with concurrency, statistics,
and structured output similar to lightweight Nmap behavior.
"""

from __future__ import annotations

import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from domainspyder.config import (
    DEFAULT_PORTS,
    PORT_SCAN_TIMEOUT,
    PORT_SCAN_THREADS,
)

logger = logging.getLogger(__name__)


class PortScanner:
    """
    Production-grade TCP port scanner.

    Features:
    - Concurrent scanning
    - Structured results
    - Scan statistics
    - Safe execution
    """

    def __init__(self, *, debug: bool = False) -> None:
        self._debug = debug

    def scan(
        self,
        target: str,
        ports: list[int] | None = None,
        threads: int = PORT_SCAN_THREADS,
        timeout: float = PORT_SCAN_TIMEOUT,
        mode: str = "balanced",
    ) -> dict[str, Any]:
        """
        Run port scan on target.

        Returns structured result:
        {
            "target": str,
            "ip": str,
            "ports_scanned": int,
            "open_ports": list[dict],
            "closed_count": int,
            "open_count": int,
            "duration": float,
        }
        """
        start_time = time.time()

        ports = self._normalize_ports(ports or DEFAULT_PORTS)
        
        grab_banner = True

        if mode == "fast":
            timeout = min(timeout, 0.4)
            threads = min(200, threads * 2)
            grab_banner = False

        elif mode == "deep":
            timeout = max(timeout, 1.0)
            threads = threads
            grab_banner = True

        else:  # balanced
            if len(ports) > 1000:
                timeout = 0.5
                threads = min(150, threads)
                grab_banner = False

        # ------------------------------------------------------------------

        ip = self._resolve_target(target)
        if not ip:
            logger.error("Failed to resolve target: %s", target)
            return {}
        
        reverse_dns = self._reverse_dns(ip)
        provider = self._detect_provider(ip, reverse_dns)

        open_ports: list[dict[str, Any]] = []
        closed_count = 0

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._scan_port, ip, port, timeout, grab_banner): port
                for port in ports
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:
                    logger.debug("Worker error: %s", exc)
                    continue

                if result:
                    open_ports.append(result)
                else:
                    closed_count += 1

        duration = round(time.time() - start_time, 3)

        return {
            "target": target,
            "ip": ip,
            "provider": provider,
            "reverse_dns": reverse_dns,
            "ports_scanned": len(ports),
            "open_ports": sorted(open_ports, key=lambda x: x["port"]),
            "open_count": len(open_ports),
            "closed_count": closed_count,
            "duration": duration,
        }

    # ------------------------------------------------------------------

    def _resolve_target(self, target: str) -> str | None:
        """Resolve domain to IP (IPv4 for now)."""
        try:
            return socket.gethostbyname(target)
        except Exception as exc:
            logger.debug("DNS resolution failed: %s", exc)
            return None

    def _reverse_dns(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "-"

    def _scan_port(
        self,
        ip: str,
        port: int,
        timeout: float,
        grab_banner: bool,
    ) -> dict[str, Any] | None:
        """Attempt TCP connect scan."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))

                if result == 0:
                    banner = (
                        self._grab_banner(ip, port, timeout)
                        if grab_banner
                        else "-"
                    )

                    return {
                        "port": port,
                        "state": "open",
                        "service": self._identify_service(port),
                        "banner": banner,
                    }

        except Exception as exc:
            logger.debug("Port %d error: %s", port, exc)

        return None
    
    def _detect_provider(self, ip: str, reverse_dns: str = "") -> str:
        """
        Detect infrastructure provider using reverse DNS + IP heuristics.

        Priority:
        1. Reverse DNS (most reliable)
        2. IP range fallback
        """

        rdns = (reverse_dns or "").lower()

        # ------------------------------------------------------------------
        # AWS EDGE / LOAD BALANCERS
        # ------------------------------------------------------------------
        if "cloudfront" in rdns:
            return "AWS (CloudFront CDN)"
    
        if "awsglobalaccelerator" in rdns:
            return "AWS (Global Accelerator)"
    
        if "elb.amazonaws.com" in rdns:
            return "AWS (Elastic Load Balancer)"
    
        if "compute.amazonaws.com" in rdns:
            return "AWS EC2"
    
        if "amazonaws" in rdns:
            return "AWS (Amazon Web Services)"
    
        # ------------------------------------------------------------------
        # GOOGLE CLOUD LOAD BALANCERS
        # ------------------------------------------------------------------
        if "googleusercontent" in rdns:
            return "Google Cloud (GCP)"
    
        if "bc.googleusercontent" in rdns:
            return "Google Cloud (GCP)"
    
        if "google" in rdns and "lb" in rdns:
            return "Google Cloud Load Balancer"
    
        # ------------------------------------------------------------------
        # AZURE LOAD BALANCERS
        # ------------------------------------------------------------------
        if "azure" in rdns or "cloudapp.azure.com" in rdns:
            return "Microsoft Azure"
    
        if "azurefd" in rdns:
            return "Azure Front Door"
    
        # ------------------------------------------------------------------
        # CDN / EDGE NETWORKS
        # ------------------------------------------------------------------
        if "cloudflare" in rdns:
            return "Cloudflare CDN"
    
        if "akamai" in rdns:
            return "Akamai CDN"
        
        if "edgesuite" in rdns or "edgekey" in rdns:
            return "Akamai Edge"
    
        if "fastly" in rdns:
            return "Fastly CDN"
    
        # ------------------------------------------------------------------
        # MODERN HOSTING / EDGE PLATFORMS
        # ------------------------------------------------------------------
        if "vercel" in rdns:
            return "Vercel Edge Network"
    
        if "netlify" in rdns:
            return "Netlify Edge"
    
        if "heroku" in rdns:
            return "Heroku Platform"
    
        if "render" in rdns:
            return "Render Platform"
    
        # ------------------------------------------------------------------
        # WEBSITE BUILDERS
        # ------------------------------------------------------------------
        if "wixsite" in rdns or "wix" in rdns:
            return "Wix Hosting"
    
        if "wordpress" in rdns:
            return "WordPress Hosting"
    
        if "squarespace" in rdns:
            return "Squarespace"
    
        if "shopify" in rdns:
            return "Shopify"
    
        # ------------------------------------------------------------------
        # More Cloud Providers
        # ------------------------------------------------------------------
        if "digitalocean" in rdns:
            return "DigitalOcean"

        if "linode" in rdns:
            return "Linode"

        if "vultr" in rdns:
            return "Vultr"


        # ------------------------------------------------------------------
        # IP FALLBACK (IMPORTANT)
        # ------------------------------------------------------------------
    
        # Cloudflare
        if ip.startswith((
            "104.",
            "172.64.",
            "172.65.",
            "188.114.",
            "162.158.",
            "162.159."
        )):
            return "Cloudflare CDN"
    
        # AWS
        if ip.startswith(("13.", "15.", "18.", "52.", "54.")):
            return "AWS (Amazon Web Services)"
    
        # GCP
        if ip.startswith(("34.", "35.")):
            return "Google Cloud (GCP)"
    
        # Azure (rough)
        if ip.startswith(("20.", "40.", "51.", "52.")):
            return "Microsoft Azure"
    
        # ------------------------------------------------------------------
        return "Unknown"

    def analyze(self, data: dict) -> list[str]:
        """Analyze port exposure and return prioritized insights."""
        insights: list[str] = []

        open_ports = [p.get("port") for p in data.get("open_ports", [])]

        if not open_ports:
            insights.append("[INFO] No open ports detected")
            return insights

        # ------------------------------------------------------------------
        # CRITICAL
        # ------------------------------------------------------------------
        if 3306 in open_ports:
            insights.append("[CRITICAL] Database port exposed (MySQL)")

        if any(p in open_ports for p in [5432, 6379, 27017]):
            insights.append("[CRITICAL] Database service exposed")

        # ------------------------------------------------------------------
        # WARNINGS
        # ------------------------------------------------------------------
        if 22 in open_ports:
            insights.append("[WARNING] SSH exposed (remote access)")

        if 21 in open_ports:
            insights.append("[WARNING] FTP exposed (insecure protocol)")

        if 25 in open_ports:
            insights.append("[WARNING] SMTP exposed (mail server)")

        if any(p in open_ports for p in [110, 143]):
            insights.append("[WARNING] Mail services exposed (POP3/IMAP)")

        # ------------------------------------------------------------------
        # INFO
        # ------------------------------------------------------------------
        if set(open_ports) == {80, 443}:
            insights.append("[INFO] Only web ports exposed (80, 443)")

        if len(open_ports) > 5:
            insights.append("[INFO] Multiple services exposed (broad attack surface)")

        return insights
    
    def _grab_banner(self, ip: str, port: int, timeout: float) -> str:
        """Basic banner grabbing (safe + non-blocking)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))

                if port in (80, 8080):
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 443:
                    return "TLS (banner skipped)"
                else:
                    sock.sendall(b"\n")

                data = sock.recv(1024)
                return data.decode(errors="ignore").split("\n")[0][:50]

        except Exception:
            return "-"

    def _normalize_ports(self, ports: list[int]) -> list[int]:
        """Validate, deduplicate, and sort ports."""
        valid_ports = set()

        for port in ports:
            if isinstance(port, int) and 1 <= port <= 65535:
                valid_ports.add(port)
            else:
                logger.debug("Invalid port skipped: %s", port)

        return sorted(valid_ports)

    @staticmethod
    def _identify_service(port: int) -> str:
        """Basic port-to-service mapping."""
        common = {
            21: "ftp",
            22: "ssh",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            139: "netbios",
            143: "imap",
            443: "https",
            445: "smb",
            3306: "mysql",
            3389: "rdp",
            8080: "http-alt",
            8443: "https-alt",
        }
        return common.get(port, "unknown")