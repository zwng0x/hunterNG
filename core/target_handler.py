# hunterNG/core/target_handler.py

import re
import socket
import yaml
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List
from enum import Enum
from dataclasses import dataclass
from pathlib import Path

import tldextract
from utils.cli_utils import console

WORKFLOW_CONFIG_FILE = Path(__file__).parent.parent / "config" / "workflow_config.yaml"

class TargetType(Enum):
    # Basic types
    DOMAIN = "domain"                   # example.com
    SUBDOMAIN = "subdomain"             # api.example.com
    IPV4 = "ipv4"                       # 192.168.1.1
    
    # URL types
    URL = "url"                         # https://example.com/path
    URL_WITH_PORT = "url_with_port"     # https://example.com:8443/api
    URL_WITH_IP = "url_with_ip"         # http://192.168.1.1/path
    URL_WITH_IP_PORT = "url_with_ip_port" # http://192.168.1.1:8080/api
    
    # Host:Port types  
    DOMAIN_WITH_PORT = "domain_with_port"       # example.com:8080
    SUBDOMAIN_WITH_PORT = "subdomain_with_port" # api.example.com:3000
    IPV4_WITH_PORT = "ipv4_with_port"           # 192.168.1.1:8080
    
    # Special cases
    LOCALHOST = "localhost"             # localhost, localhost:8080
    HOSTNAME = "hostname"               # internal-server, server.local

@dataclass
class TargetInfo:
    original_input: str
    target_type: TargetType
    domain: Optional[str] = None
    subdomain: Optional[str] = None
    hostname: Optional[str] = None # For non-resolvable hostnames like 'internal-server'
    ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    path: Optional[str] = None
    base_url: Optional[str] = None

class TargetHandler:
    def __init__(self):
        # Updated Regex patterns for more specific matching
        self.ipv4_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        self.host_port_pattern = re.compile(r'^([a-zA-Z0-9.-]+):(\d+)$')
        self.hostname_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$') # Hostname without dots
        self.domain_like_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') # General pattern for domain-like structures
        self.workflows = self._load_workflow_config()
        
    def _load_workflow_config(self) -> Dict[str, Any]:
        """Loads workflow configurations from the YAML file."""
        if not WORKFLOW_CONFIG_FILE.exists():
            raise FileNotFoundError(f"Workflow configuration file not found: {WORKFLOW_CONFIG_FILE}")
        try:
            with open(WORKFLOW_CONFIG_FILE, 'r', encoding='utf-8') as file:
                config = yaml.safe_load(file)
                if not isinstance(config, dict):
                    raise ValueError("Workflow configuration file is invalid or empty.")
                return config
        except Exception as e:
            raise RuntimeError(f"Error loading workflow configuration file: {e}") from e

    def identify_target_type(self, target: str) -> TargetInfo:
        """
        Identify and parse target information based on the new detailed TargetType structure.
        The order of checks is crucial for accuracy.
        """
        target = target.strip()

        # 1. Check for URLs (http:// or https://)
        if target.startswith(('http://', 'https://')):
            return self._parse_url(target)
        
        # 2. Check for localhost (special case)
        if target.lower().startswith('localhost'):
            return self._parse_localhost(target)
        
        # 3. Check for IPv4 with port (more specific than general host:port)
        if ':' in target:
            parts = target.split(':')
            if len(parts) == 2:
                host_part = parts[0]
                # ✅ Make sure it's not localhost (already handled above)
                if host_part.lower() != 'localhost' and self.ipv4_pattern.match(host_part):
                    try:
                        port = int(parts[1])
                        self._validate_port(port)
                        return TargetInfo(
                            original_input=target,
                            target_type=TargetType.IPV4_WITH_PORT,
                            ip=host_part,
                            port=port
                        )
                    except (ValueError, RuntimeError):
                        pass  # Fall through to other checks

        # 4. Check for general host:port formats
        match = self.host_port_pattern.match(target)
        if match:
            host, port_str = match.groups()
            # ✅ Skip if it's localhost (already handled)
            if host.lower() != 'localhost':
                try:
                    port = int(port_str)
                    self._validate_port(port)
                    return self._parse_host_with_port(target, host, port)
                except (ValueError, RuntimeError) as e:
                    console.print(f"[red]Invalid port in target {target}: {e}[/red]")
                    # Continue with host without port

        # 5. Check for plain IPv4
        if self.ipv4_pattern.match(target):
            return self._parse_ipv4(target)

        # 6. Differentiate between domain, subdomain, and simple hostname
        if self.domain_like_pattern.match(target):
            return self._parse_domain_or_subdomain(target)
        
        # 7. Simple hostname
        if self._is_valid_hostname(target):
             return TargetInfo(
                original_input=target,
                target_type=TargetType.HOSTNAME,
                hostname=target
            )

        # Fallback for unrecognized formats
        console.print(f"[yellow]Warning: Target format not recognized, treating as generic hostname: {target}[/yellow]")
        return TargetInfo(original_input=target, target_type=TargetType.HOSTNAME, hostname=target)
    
    def _validate_port(self, port: int) -> None:
        """Validate port number range."""
        if not (1 <= port <= 65535):
            raise RuntimeError(f"Port must be between 1 and 65535, got: {port}")
        
    def _is_valid_hostname(self, target: str) -> bool:
        """Enhanced hostname validation including underscores for internal hostnames."""
        # Allow underscores for internal hostnames but maintain RFC compliance for others
        if '_' in target:
            # More permissive pattern for internal hostnames
            internal_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,61}[a-zA-Z0-9])?$')
            return internal_pattern.match(target) is not None
        else:
            # Standard RFC compliant pattern
            return self.hostname_pattern.match(target) is not None
    
    def _parse_url(self, target: str) -> TargetInfo:
        """Parse various URL types with special handling for localhost."""
        parsed = urlparse(target)
        hostname = parsed.hostname or ''
        port = parsed.port
        
        # ✅ FIX: Use the full original URL instead of just scheme://netloc
        full_url = target  # Keep the original URL with path
        base_url = f"{parsed.scheme}://{parsed.netloc}"  # Base URL without path (for internal use)
        
        # ✅ Special handling for localhost and 127.0.0.1 URLs
        if hostname.lower() == 'localhost' or hostname == '127.0.0.1':
            return TargetInfo(
                original_input=target,
                target_type=TargetType.LOCALHOST,  # Use LOCALHOST type for both localhost and 127.0.0.1
                hostname='localhost' if hostname.lower() == 'localhost' else None,
                ip='127.0.0.1',
                port=port,
                protocol=parsed.scheme,
                path=parsed.path,
                base_url=full_url  # ✅ Use full URL instead of base_url
            )
        
        # Check if hostname is IP
        is_ip = self.ipv4_pattern.match(hostname) is not None
        
        if is_ip:
            if port:
                return TargetInfo(
                    original_input=target, target_type=TargetType.URL_WITH_IP_PORT, ip=hostname,
                    port=port, protocol=parsed.scheme, path=parsed.path,
                    base_url=full_url  # ✅ Use full URL
                )
            else:
                return TargetInfo(
                    original_input=target, target_type=TargetType.URL_WITH_IP, ip=hostname,
                    protocol=parsed.scheme, path=parsed.path,
                    base_url=full_url  # ✅ Use full URL
                )
        else: # Domain-based URL
            domain = self._extract_domain(hostname)
            is_subdomain = hostname != domain
            if port:
                return TargetInfo(
                    original_input=target, target_type=TargetType.URL_WITH_PORT,
                    domain=domain, subdomain=hostname if is_subdomain else None, port=port,
                    protocol=parsed.scheme, path=parsed.path,
                    base_url=full_url  # ✅ Use full URL
                )
            else:
                return TargetInfo(
                    original_input=target, target_type=TargetType.URL,
                    domain=domain, subdomain=hostname if is_subdomain else None,
                    protocol=parsed.scheme, path=parsed.path,
                    base_url=full_url  # ✅ Use full URL
                )


    def _parse_localhost(self, target: str) -> TargetInfo:
        """Parse localhost with or without a port."""
        parts = target.lower().split(':')
        port = int(parts[1]) if len(parts) > 1 else None
        return TargetInfo(
            original_input=target,
            target_type=TargetType.LOCALHOST,
            hostname='localhost',
            ip='127.0.0.1',
            port=port
        )

    def _parse_host_with_port(self, original_input: str, host: str, port: int) -> TargetInfo:
        """Parse various host:port combinations."""
        if self.ipv4_pattern.match(host):
            return TargetInfo(original_input=original_input, target_type=TargetType.IPV4_WITH_PORT, ip=host, port=port)
        
        domain = self._extract_domain(host)
        is_subdomain = host != domain
        
        if is_subdomain:
            return TargetInfo(
                original_input=original_input, target_type=TargetType.SUBDOMAIN_WITH_PORT,
                subdomain=host, domain=domain, port=port
            )
        else:
            return TargetInfo(
                original_input=original_input, target_type=TargetType.DOMAIN_WITH_PORT,
                domain=domain, port=port
            )

    def _parse_ipv4(self, target: str) -> TargetInfo:
        """Parse plain IPv4."""
        return TargetInfo(original_input=target, target_type=TargetType.IPV4, ip=target)

    def _parse_domain_or_subdomain(self, target: str) -> TargetInfo:
        """Parse domain or subdomain."""
        domain = self._extract_domain(target)
        is_subdomain = target != domain
        
        return TargetInfo(
            original_input=target,
            target_type=TargetType.SUBDOMAIN if is_subdomain else TargetType.DOMAIN,
            domain=domain,
            subdomain=target if is_subdomain else None,
        )

    def _extract_domain(self, hostname: str) -> str:
        """Extracts the root domain (e.g., example.com) from a hostname."""
        extracted = tldextract.extract(hostname)
        if not extracted.suffix: # Handle cases like 'localhost' or simple hostnames
            return hostname
        return f"{extracted.domain}.{extracted.suffix}"

    def get_workflow_config(self, target_info: TargetInfo) -> Dict[str, Any]:
        """Get appropriate workflow configuration based on target type from the loaded config."""
        return self.workflows.get(target_info.target_type.value, self.workflows.get('domain', {}))

    def enhance_global_state(self, target_info: TargetInfo, global_state: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance global state with target information."""
        global_state.update({
            "target_info": {
                "original_input": target_info.original_input,
                "target_type": target_info.target_type.value,
                "domain": target_info.domain,
                "subdomain": target_info.subdomain,
                "hostname": target_info.hostname,
                "ip": target_info.ip,
                "port": target_info.port,
                "protocol": target_info.protocol,
                "path": target_info.path,
                "base_url": target_info.base_url,
            }
        })
        scan_targets = self._generate_scan_targets(target_info)
        global_state["scan_targets"] = scan_targets
        return global_state

    def _generate_scan_targets(self, target_info: TargetInfo) -> Dict[str, List[str]]:
        """Generate scan targets with better duplicate prevention."""
        scan_targets = {"domain": [], "ip": [], "url": [], "host": []}
        
        # ✅ Use sets to prevent duplicates
        domains_set = set()
        ips_set = set()
        urls_set = set()
        hosts_set = set()

        ttype = target_info.target_type

        # Handle domain/subdomain parts
        if target_info.subdomain:
            domains_set.add(target_info.subdomain)
        elif target_info.domain:
            domains_set.add(target_info.domain)

        # Handle IP parts
        if target_info.ip:
            ips_set.add(target_info.ip)
        
        # Handle URL parts
        if target_info.base_url:
            urls_set.add(target_info.base_url)

        # Handle host (for port scanning, etc.)
        host = target_info.hostname or target_info.subdomain or target_info.domain or target_info.ip
        if host:
            if target_info.port:
                hosts_set.add(f"{host}:{target_info.port}")
            else:
                hosts_set.add(host)

        # Add original input for non-URL targets
        if (ttype not in [TargetType.URL, TargetType.URL_WITH_PORT, TargetType.URL_WITH_IP, TargetType.URL_WITH_IP_PORT, TargetType.LOCALHOST] 
            and not target_info.base_url):
            hosts_set.add(target_info.original_input)

        # ✅ Convert sets back to lists
        scan_targets["domain"] = list(domains_set)
        scan_targets["ip"] = list(ips_set)
        scan_targets["url"] = list(urls_set)
        scan_targets["host"] = list(hosts_set)

        return scan_targets