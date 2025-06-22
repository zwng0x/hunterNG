# hunterNG/modules/recon/recon_module.py

import re
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Set
from modules.base_module import BaseModule

class ReconModule(BaseModule):
    def __init__(self, module_name: str,
                 target: str,
                 output_dir: Path,
                 global_state: Dict[str, Any],
                 verbose: bool = False):
        super().__init__(module_name, target, output_dir, global_state, verbose)
        
        # Enhanced suspicious keywords for URL filtering with severity levels
        self.suspicious_keywords = {
            'path': {
                'critical': ['admin', 'password', 'pwd', 'secret', 'config', 'backup', 'cmd', 'exec'],
                'high': ['login', 'auth', 'signin', 'signup', 'register', 'debug', 'db', 'phpmyadmin'],
                'medium': ['dev', 'staging', 'api-docs', 'swagger', 'test', 'upload', 'download', 'dashboard'],
                'low': ['console', 'wp-admin', 'cpanel', 'status', 'health', 'monitor', 'git', 'env']
            },
            'params': {
                'critical': ['password', 'pwd', 'secret', 'cmd', 'exec', 'eval', 'system', 'shell'],
                'high': ['admin', 'login', 'auth', 'token', 'key'],
                'medium': ['id', 'user', 'redirect', 'url', 'file', 'path', 'dir'],
                'low': []
            },
            'extensions': {
                'critical': ['.sql', '.db', '.sqlite', '.env'],
                'high': ['.bak', '.backup', '.old', '.config', '.conf', '.log'],
                'medium': ['.tmp', '.swp', '.git'],
                'low': []
            }
        }

    def _is_suspicious_url(self, url: str) -> tuple[bool, str, str]:
        """Check if URL is suspicious based on path, parameters, and file extensions
        Returns: (is_suspicious, reason, severity)"""
        try:
            parsed = urllib.parse.urlparse(url)
            reasons = []
            max_severity = 'low'
            
            # Check path for suspicious keywords
            path = parsed.path.lower()
            for severity, keywords in self.suspicious_keywords['path'].items():
                for keyword in keywords:
                    if f'/{keyword}' in path or f'{keyword}/' in path or path.endswith(f'/{keyword}'):
                        reasons.append(f"suspicious path: {keyword}")
                        if self._is_higher_severity(severity, max_severity):
                            max_severity = severity
            
            # Check for suspicious file extensions
            for severity, extensions in self.suspicious_keywords['extensions'].items():
                for ext in extensions:
                    if path.endswith(ext.lower()):
                        reasons.append(f"suspicious extension: {ext}")
                        if self._is_higher_severity(severity, max_severity):
                            max_severity = severity
            
            # Check query parameters for suspicious names
            if parsed.query:
                query_params = urllib.parse.parse_qs(parsed.query.lower())
                for param_name in query_params.keys():
                    for severity, keywords in self.suspicious_keywords['params'].items():
                        for keyword in keywords:
                            if keyword in param_name:
                                reasons.append(f"suspicious parameter: {param_name}")
                                if self._is_higher_severity(severity, max_severity):
                                    max_severity = severity
                
            return bool(reasons), "; ".join(reasons), max_severity
            
        except Exception as e:
            return False, f"parsing error: {e}", 'low'

    def _is_higher_severity(self, new_severity: str, current_severity: str) -> bool:
        """Compare severity levels"""
        severity_order = ['low', 'medium', 'high', 'critical']
        return severity_order.index(new_severity) > severity_order.index(current_severity)

    def _filter_suspicious_urls_advanced(self, urls_content: str) -> str:
        """Advanced filtering for suspicious URLs using Python logic with severity"""
        if not urls_content or not urls_content.strip():
            return ""
        
        suspicious_urls = []
        urls = [url.strip() for url in urls_content.strip().splitlines() if url.strip()]
        
        # Sort URLs by severity for better organization
        url_data = []
        for url in urls:
            is_suspicious, reason, severity = self._is_suspicious_url(url)
            if is_suspicious:
                url_data.append((url, reason, severity))
        
        # Sort by severity (critical first, then high, medium, low)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        url_data.sort(key=lambda x: severity_order.get(x[2], 3))
        
        # Format output with enhanced information
        for url, reason, severity in url_data:
            # Add severity indicator to the reason
            severity_indicator = {
                'critical': '🔴',
                'high': '🟠', 
                'medium': '🟡',
                'low': '🔵'
            }.get(severity, '⚪')
            
            suspicious_urls.append(f"{url}  # {severity_indicator} {reason}")
        
        return "\n".join(suspicious_urls)

    def _beautify_whatweb_simple(self, whatweb_content: str) -> str:
        """Simple beautification of WhatWeb output"""
        if not whatweb_content or not whatweb_content.strip():
            return "No WhatWeb data available"
        
        lines = whatweb_content.strip().split('\n')
        beautified_lines = []
        
        for line in lines:
            if not line.strip():
                continue
            
            # Extract URL and status
            url_match = re.match(r'^(https?://[^\s]+)\s+\[([^\]]+)\]', line)
            if not url_match:
                continue
            
            url = url_match.group(1)
            status = url_match.group(2)
            
            # Extract technologies part
            tech_part = line[url_match.end():].strip()
            
            # Simple parsing - split by comma but be careful with brackets
            tech_items = []
            current = ""
            bracket_count = 0
            
            for char in tech_part:
                if char == '[':
                    bracket_count += 1
                elif char == ']':
                    bracket_count -= 1
                elif char == ',' and bracket_count == 0:
                    tech_items.append(current.strip())
                    current = ""
                    continue
                current += char
            
            if current.strip():
                tech_items.append(current.strip())
            
            # Format output
            result_lines = []
            result_lines.append(f"🌐 URL: {url}")
            result_lines.append(f"📊 Status: {status}")
            result_lines.append("─" * 50)
            
            # Group technologies by type
            server_info = []
            programming = []
            other_info = []
            
            for item in tech_items:
                item = item.strip()
                if not item:
                    continue
                    
                item_lower = item.lower()
                if any(x in item_lower for x in ['nginx', 'apache', 'iis', 'httpserver', 'server']):
                    server_info.append(f"  • {item}")
                elif any(x in item_lower for x in ['php', 'asp', 'python', 'ruby', 'java', 'script', 'powered-by']):
                    programming.append(f"  • {item}")
                else:
                    other_info.append(f"  • {item}")
            
            if server_info:
                result_lines.append("\n🖥️ Server Info:")
                result_lines.extend(server_info)
            
            if programming:
                result_lines.append("\n💻 Programming:")
                result_lines.extend(programming)
            
            if other_info:
                result_lines.append("\n📋 Other Technologies:")
                result_lines.extend(other_info)
            
            beautified_lines.append('\n'.join(result_lines))
        
        return '\n\n'.join(beautified_lines)

    def run(self, **kwargs) -> Dict[str, Any]:
        super().run(**kwargs)

        focus_domain = kwargs.get("focus_domain", False)

        target_info = self.global_state.get('target_info', {})
        target_type = target_info.get('target_type', 'domain')

        results: Dict[str, Any] = {
            "target": self.target,
            "module_name": self.module_name,
            "output_dir": str(self.module_output_dir),
            "target_type": target_type,
            "focus_domain": focus_domain,
        }

        # Basic recon
        self._save_task_results(
            self._execute_command_task("whois").stdout,
            "whois"
        )
        self._save_task_results(
            self._execute_command_task("nslookup").stdout,
            "nslookup"
        )

        # Enum subdomain
        self.console.print(f"[blue]Enumerate subdomain[/blue]")
        subdomains = self._execute_command_task("enum_subdomains", show_output=False)
        self._save_task_results(subdomains.stdout, "subdomains")
        
        if focus_domain:
            self._save_task_results(self._get_primary_scan_target(), "live_hosts")
        else:
            live_subdomains_result = self._execute_command_task("check_live_hosts", stdin_data=subdomains.stdout)
            primary_target = self._get_primary_scan_target()
            
            combined_live_hosts = f"{primary_target}\n{live_subdomains_result.stdout.strip()}"
            self._save_task_results(combined_live_hosts, "live_hosts")

        # Retrieving archived URL
        self.console.print(f"[blue]Getting all URL from Wayback Machine, Alien Vault...[/blue]")
        gau = self._execute_command_task("gau", stdin_data=self._load_task_results("live_hosts"))
        self._save_task_results(gau.stdout, "archived_url")

        # Crawling URL
        self.console.print(f"[blue]Crawling more URL from web pages[/blue]")
        katana = self._execute_command_task("katana", self._load_task_results("live_hosts"))
        self._save_task_results(katana.stdout, "crawled_url")

        # Finding param URL
        self.console.print(f"[blue]Crawling URL with query parameters[/blue]")
        katana_qurl = self._execute_command_task("katana_qurl", self._load_task_results("live_hosts"))
        self._save_task_results(katana_qurl.stdout, "crawled_qurl")

        # Deduplicate and check live URL
        self.console.print(f"[blue]Deduplicate and check live URL[/blue]")
        archived_url = self._execute_pipeline_tasks(
            ["uro", "check_live_url"],
            pipeline_data=self._load_task_results("archived_url"),
            show_output=False
        )
        crawled_url = self._load_task_results("crawled_url")
        crawled_qurl = self._load_task_results("crawled_qurl")
        combined_url = archived_url["check_live_url"].stdout.strip() + "\n" + crawled_url.strip() + "\n" + crawled_qurl.strip()
        
        uniq_url = self._execute_command_task("uro", stdin_data=combined_url, show_output=False).stdout
        self._save_task_results(uniq_url, "uniq_url")

        # ENHANCED: Advanced suspicious URL filtering with severity
        self.console.print(f"[blue]Advanced filtering for suspicious URLs with severity analysis[/blue]")
        suspicious_urls = self._filter_suspicious_urls_advanced(uniq_url)
        self._save_task_results(suspicious_urls, "suspicious_url")

        # Continue with param URLs
        param_url = self._execute_command_task("grep_qurl", stdin_data=uniq_url, show_output=False).stdout

        uniq_url_set = set(uniq_url.splitlines())
        param_url_set = set(param_url.splitlines())

        non_param_url = "\n".join(sorted(list(uniq_url_set - param_url_set)))

        self._save_task_results(non_param_url, "url_no_param")
        self._save_task_results(
            self._execute_command_task("param_fuzz", stdin_data=param_url).stdout,
            "url_param"
        )

        # Identify technology with simple beautification
        self.console.print(f"[blue]Identifying web technology[/blue]")
        whatweb = self._execute_command_task(
            "whatweb",
            stdin_data=self._load_task_results("live_hosts"),
            show_output=False
        )
        
        # Save both raw and beautified WhatWeb results
        self._save_task_results(whatweb.stdout, "whatweb_raw")
        
        # Beautify WhatWeb output using simple method
        if whatweb.stdout and whatweb.stdout.strip():
            beautified_whatweb = self._beautify_whatweb_simple(whatweb.stdout)
            self._save_task_results(beautified_whatweb, "whatweb")
            self.console.print(f"[green]WhatWeb results beautified and saved[/green]")
        else:
            self._save_task_results("No WhatWeb data available", "whatweb")

        # Wappalyzer
        self._execute_command_task(
            "wappalyzer",
            stdin_data=self._load_task_results("live_hosts"),
            show_output=False
        )

        self._save_module_results(results)
        return results