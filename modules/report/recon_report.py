# hunterNG/modules/report/recon_report.py

import html
import shutil
import re
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple
from rich.console import Console

class ReconReport:
    def __init__(self, template_dir: Path, module_output_dir: Path, global_state: Dict[str, Any], console: Console, verbose: bool = False):
        self.template_dir = template_dir
        self.module_output_dir = module_output_dir
        self.global_state = global_state
        self.console = console
        self.verbose = verbose

    def _count_lines_in_file(self, file_path: Path) -> int:
        """Count non-empty lines in a file"""
        if not file_path.exists():
            return 0
        try:
            content = file_path.read_text(encoding='utf-8').strip()
            if not content:
                return 0
            return len([line for line in content.splitlines() if line.strip()])
        except Exception:
            return 0

    def _calculate_recon_stats(self, recon_dir: Path) -> Dict[str, int]:
        """Calculate statistics for reconnaissance data"""
        return {
            'subdomains_count': self._count_lines_in_file(recon_dir / "subdomains.txt"),
            'live_hosts_count': self._count_lines_in_file(recon_dir / "live_hosts.txt"),
            'url_no_param_count': self._count_lines_in_file(recon_dir / "url_no_param.txt"),
            'url_param_count': self._count_lines_in_file(recon_dir / "url_param.txt"),
            'suspicious_urls_count': self._count_lines_in_file(recon_dir / "suspicious_url.txt"),
            'total_urls_count': (
                self._count_lines_in_file(recon_dir / "url_no_param.txt") + 
                self._count_lines_in_file(recon_dir / "url_param.txt")
            )
        }

    def _clean_nslookup_data(self, nslookup_content: str) -> str:
        """Remove the first two lines from nslookup output (Server info)"""
        if not nslookup_content or not nslookup_content.strip():
            return "No NSLookup data available"
        
        lines = nslookup_content.strip().splitlines()
        
        # Remove first two lines if they contain server information
        if len(lines) >= 2:
            # Check if first line starts with "Server:" and second with "Address:"
            if (lines[0].strip().startswith("Server:") and 
                lines[1].strip().startswith("Address:")):
                # Remove first two lines and any empty lines that follow
                cleaned_lines = lines[2:]
                while cleaned_lines and not cleaned_lines[0].strip():
                    cleaned_lines = cleaned_lines[1:]
                return '\n'.join(cleaned_lines)
        
        # If format is different, return as is
        return nslookup_content

    def _parse_suspicious_url_line(self, line: str) -> Tuple[str, List[str]]:
        """Parse a suspicious URL line and extract URL and reasons"""
        # Format: "URL # reason1; reason2; reason3"
        if '#' in line:
            url_part, reason_part = line.split('#', 1)
            url = url_part.strip()
            
            # Parse reasons
            reasons = []
            reason_text = reason_part.strip()
            
            # Split by semicolon and parse each reason
            for reason in reason_text.split(';'):
                reason = reason.strip()
                if reason:
                    reasons.append(reason)
            
            return url, reasons
        else:
            # Fallback for lines without reasons
            return line.strip(), ["Unknown risk"]

    def _categorize_risk_reason(self, reason: str) -> Tuple[str, str, str]:
        """Categorize a risk reason and return (category, icon, formatted_text)"""
        reason_lower = reason.lower()
        
        if 'suspicious path:' in reason_lower:
            keyword = reason.split(':', 1)[1].strip()
            return 'path', 'fas fa-folder-open', f'Suspicious Path: {keyword}'
        elif 'suspicious parameter:' in reason_lower:
            keyword = reason.split(':', 1)[1].strip()
            if keyword in ['cmd', 'exec', 'system']:
                icon = 'fas fa-terminal'
            elif keyword in ['id', 'user']:
                icon = 'fas fa-user'
            elif keyword in ['file', 'path', 'dir']:
                icon = 'fas fa-file'
            else:
                icon = 'fas fa-key'
            return 'param', icon, f'Suspicious Parameter: {keyword}'
        elif 'suspicious extension:' in reason_lower:
            keyword = reason.split(':', 1)[1].strip()
            return 'extension', 'fas fa-file', f'Suspicious Extension: {keyword}'
        elif 'multiple parameters' in reason_lower:
            return 'param', 'fas fa-list', 'Multiple Parameters'
        elif 'numeric id parameter' in reason_lower:
            return 'param', 'fas fa-hashtag', 'Numeric ID Parameter'
        else:
            return 'other', 'fas fa-exclamation-circle', reason

    def _generate_suspicious_urls_html(self, suspicious_urls_content: str) -> str:
        """Generate beautiful HTML for suspicious URLs"""
        if not suspicious_urls_content or not suspicious_urls_content.strip():
            return '''
            <div class="alert alert-success border-0 shadow" role="alert">
                <h4 class="alert-heading">
                    <i class="fas fa-shield-alt text-success me-2"></i>No Suspicious URLs Found
                </h4>
                <p class="mb-0">Great! No URLs with suspicious patterns were detected during reconnaissance.</p>
            </div>
            '''
        
        lines = [line.strip() for line in suspicious_urls_content.strip().splitlines() if line.strip()]
        
        if not lines:
            return '''
            <div class="alert alert-success border-0 shadow" role="alert">
                <h4 class="alert-heading">
                    <i class="fas fa-shield-alt text-success me-2"></i>No Suspicious URLs Found
                </h4>
                <p class="mb-0">Great! No URLs with suspicious patterns were detected during reconnaissance.</p>
            </div>
            '''

        # Parse all URLs and categorize risks
        parsed_urls = []
        risk_categories = {'path': 0, 'param': 0, 'extension': 0}
        
        for line in lines:
            url, reasons = self._parse_suspicious_url_line(line)
            categorized_reasons = []
            url_risk_types = set()
            
            for reason in reasons:
                category, icon, formatted_text = self._categorize_risk_reason(reason)
                if category in risk_categories:  # Only count valid categories
                    categorized_reasons.append((category, icon, formatted_text))
                    url_risk_types.add(category)
                    risk_categories[category] += 1
            
            if categorized_reasons:  # Only add URLs with valid risk categories
                parsed_urls.append({
                    'url': url,
                    'reasons': categorized_reasons,
                    'risk_types': list(url_risk_types)
                })

        # Generate summary statistics
        total_urls = len(parsed_urls)

        # Generate filter buttons
        filter_buttons = f'''
        <div class="mb-3">
            <div class="btn-group flex-wrap" role="group" aria-label="Risk filter">
                <button type="button" class="btn btn-outline-primary active" data-filter="all">
                    <i class="fas fa-list me-1"></i>All Threats ({total_urls})
                </button>
        '''
        
        if risk_categories['path'] > 0:
            filter_buttons += f'''
                <button type="button" class="btn btn-outline-warning" data-filter="path">
                    <i class="fas fa-folder me-1"></i>Path Issues ({risk_categories['path']})
                </button>
            '''
        
        if risk_categories['param'] > 0:
            filter_buttons += f'''
                <button type="button" class="btn btn-outline-danger" data-filter="param">
                    <i class="fas fa-key me-1"></i>Parameter Issues ({risk_categories['param']})
                </button>
            '''
        
        if risk_categories['extension'] > 0:
            filter_buttons += f'''
                <button type="button" class="btn btn-outline-info" data-filter="extension">
                    <i class="fas fa-file me-1"></i>File Extensions ({risk_categories['extension']})
                </button>
            '''

        filter_buttons += '''
            </div>
        </div>
        '''

        # Generate URL entries
        url_entries = ''
        for i, url_data in enumerate(parsed_urls):
            risk_types_str = ' '.join(url_data['risk_types'])
            
            url_entries += f'''
            <div class="suspicious-url-entry" data-risks="{risk_types_str}" data-index="{i}">
                <div class="url-text" onclick="copyToClipboard(this)" title="Click to copy URL">
                    <i class="fas fa-link me-2 text-danger"></i>
                    {html.escape(url_data['url'])}
                </div>
                <div class="risk-reasons">
            '''
            
            for category, icon, formatted_text in url_data['reasons']:
                badge_class = f'risk-{category}'
                url_entries += f'''
                    <span class="badge {badge_class} me-1 mb-1">
                        <i class="{icon} me-1"></i>
                        {html.escape(formatted_text)}
                    </span>
                '''
            
            url_entries += '''
                </div>
            </div>
            '''

        # Generate risk legend - FIXED to only show 3 categories
        legend_html = '''
        <div class="row mt-4">
            <div class="col-12">
                <h6><i class="fas fa-info-circle text-info me-2"></i>Risk Categories</h6>
                <div class="row">
                    <div class="col-md-6">
                        <div class="d-flex align-items-center mb-2">
                            <span class="badge risk-path me-2">
                                <i class="fas fa-folder-open me-1"></i>Path Risk
                            </span>
                            <small class="text-muted">Suspicious directory or file names</small>
                        </div>
                        <div class="d-flex align-items-center mb-2">
                            <span class="badge risk-param me-2">
                                <i class="fas fa-key me-1"></i>Parameter Risk
                            </span>
                            <small class="text-muted">Dangerous parameter names</small>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="d-flex align-items-center mb-2">
                            <span class="badge risk-extension me-2">
                                <i class="fas fa-file me-1"></i>Extension Risk
                            </span>
                            <small class="text-muted">Sensitive file extensions</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        '''

        # Combine all HTML parts
        final_html = filter_buttons + '<div id="suspicious-urls-list">' + url_entries + '</div>' + legend_html

        # Add required CSS and JavaScript
        final_html += '''
        <style>
        .suspicious-url-entry {
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 0.5rem;
            padding: 1rem;
            margin-bottom: 0.75rem;
            box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1);
            transition: all 0.2s ease;
            border-left: 4px solid #dc2626;
        }

        .suspicious-url-entry:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
        }

        .url-text {
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.875rem;
            word-break: break-all;
            color: #2563eb;
            font-weight: 500;
            margin-bottom: 0.5rem;
            cursor: pointer;
        }

        .url-text:hover {
            color: #1d4ed8;
        }

        .risk-reasons {
            display: flex;
            flex-wrap: wrap;
            gap: 0.25rem;
        }

        .badge.risk-path {
            background-color: #fef2f2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }

        .badge.risk-param {
            background-color: #fff7ed;
            color: #9a3412;
            border: 1px solid #fed7aa;
        }

        .badge.risk-extension {
            background-color: #fefce8;
            color: #a16207;
            border: 1px solid #fef3c7;
        }
        </style>

        <script>
        // Filter functionality for suspicious URLs
        document.addEventListener('DOMContentLoaded', function() {
            const filterButtons = document.querySelectorAll('[data-filter]');
            const urlEntries = document.querySelectorAll('.suspicious-url-entry');

            filterButtons.forEach(button => {
                button.addEventListener('click', () => {
                    // Update active button
                    filterButtons.forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');

                    const filter = button.getAttribute('data-filter');

                    // Filter entries
                    urlEntries.forEach(entry => {
                        if (filter === 'all') {
                            entry.style.display = 'block';
                        } else {
                            const risks = entry.getAttribute('data-risks');
                            entry.style.display = risks.includes(filter) ? 'block' : 'none';
                        }
                    });
                });
            });
        });

        // Copy URL functionality
        function copyToClipboard(element) {
            const url = element.textContent.trim().replace(/.*\\s/, '');
            navigator.clipboard.writeText(url).then(() => {
                const originalHTML = element.innerHTML;
                element.innerHTML = '<i class="fas fa-check text-success me-2"></i>URL Copied!';
                setTimeout(() => {
                    element.innerHTML = originalHTML;
                }, 2000);
            }).catch(() => {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = url;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                
                const originalHTML = element.innerHTML;
                element.innerHTML = '<i class="fas fa-check text-success me-2"></i>URL Copied!';
                setTimeout(() => {
                    element.innerHTML = originalHTML;
                }, 2000);
            });
        }
        </script>
        '''

        return final_html

    def _load_data_from_module(self, module_output_dir: Path, filename: str) -> Optional[str]:
        """Load text data from a file in a module's output directory."""
        path = module_output_dir / f"{filename}.txt"
        if path.exists() and path.stat().st_size > 0:
            try:
                data = path.read_text(encoding='utf-8').strip()
                return data if data else None
            except Exception as e:
                self.console.print(f"[red]Error reading {path}: {e}[/red]")
                return None
        else:
            if self.verbose:
                self.console.print(f"[yellow]Warning: File not found or empty: {path}[/yellow]")
            return None

    def _generate_placeholder_page(self, page_title: str, results_key: str) -> str:
        self.console.print(f"[blue]Generating placeholder for {page_title}...[/blue]")
        try:
            template = (self.template_dir / "placeholder_content.html").read_text()
            return template.replace("{{ page_title }}", page_title)
        except FileNotFoundError:
            return f'''
            <div class="page-header">
                <div class="container">
                    <h1><i class="fas fa-exclamation-circle"></i> {page_title}</h1>
                    <p class="subtitle">Module data not available</p>
                </div>
            </div>
            <div class="container">
                <div class="alert alert-warning border-0 shadow">
                    <h4 class="alert-heading"><i class="fas fa-info-circle me-2"></i>No Data Available</h4>
                    <p>The {page_title} module has not been executed or no data was generated.</p>
                    <hr>
                    <p class="mb-0">Please run the {page_title.lower()} module first to generate this report.</p>
                </div>
            </div>
            '''

    def generate(self) -> str:
        self.console.print("[blue]Generating report for Recon module...[/blue]")
        if 'recon_results' not in self.global_state:
            return self._generate_placeholder_page("Reconnaissance", "recon_results")

        recon_dir = Path(self.global_state['recon_results'].get('output_dir', ''))
        try:
            content = (self.template_dir / "recon_content.html").read_text()
        except FileNotFoundError:
            self.console.print("[red]Error: recon_content.html not found[/red]")
            return "<h3>Unable to load Reconnaissance template.</h3>"

        # GET TARGET NAME FROM GLOBAL STATE
        target_name = self.global_state.get('target', 'Unknown Target')
        content = content.replace("{{ target_name }}", html.escape(target_name))

        # Calculate statistics
        stats = self._calculate_recon_stats(recon_dir)
        
        # Replace statistics in template
        for stat_name, stat_value in stats.items():
            content = content.replace(f"{{{{ {stat_name} }}}}", str(stat_value))

        # Load and replace file data
        files = {
            "whois": "whois_data",
            "live_hosts": "live_hosts_data",
            "whatweb": "whatweb_data",
            "subdomains": "subdomains_data",
            "url_no_param": "url_no_param_data",
            "url_param": "url_param_data",
        }

        for f, p in files.items():
            data = self._load_data_from_module(recon_dir, f)
            content = content.replace(f"{{{{ {p} }}}}", html.escape(data or "No data available."))

        # SPECIAL HANDLING FOR NSLOOKUP - CLEAN THE DATA
        nslookup_data = self._load_data_from_module(recon_dir, "nslookup")
        cleaned_nslookup = self._clean_nslookup_data(nslookup_data or "")
        content = content.replace("{{ nslookup_data }}", html.escape(cleaned_nslookup))

        # Special handling for suspicious URLs - generate beautiful HTML instead of plain text
        suspicious_urls_data = self._load_data_from_module(recon_dir, "suspicious_url")
        suspicious_urls_html = self._generate_suspicious_urls_html(suspicious_urls_data or "")
        content = content.replace("{{ sus_url_data }}", suspicious_urls_html)

        # Handle Wappalyzer content
        wappalyzer_source_path = recon_dir / "wappalyzer.html"
        wappalyzer_dest_path = self.module_output_dir / "wappalyzer.html"

        if wappalyzer_source_path.exists() and wappalyzer_source_path.stat().st_size > 0:
            try:
                shutil.copy(str(wappalyzer_source_path), str(wappalyzer_dest_path))
                self.console.print(f"[green]Copied Wappalyzer report to: {wappalyzer_dest_path}[/green]")
                wappalyzer_content_html = '''
                <iframe src="wappalyzer.html" style="width: 100%; height: 80vh; border: none; border-radius: 0.5rem;" 
                        class="shadow">
                    Your browser does not support iframes.
                </iframe>
                '''
            except Exception as e:
                self.console.print(f"[red]Error copying wappalyzer.html: {e}[/red]")
                wappalyzer_content_html = '<div class="alert alert-danger" role="alert"><i class="fas fa-exclamation-triangle me-2"></i>Error processing Wappalyzer report.</div>'
        else:
            self.console.print(f"[yellow]Warning: Not found or empty file: {wappalyzer_source_path}[/yellow]")
            wappalyzer_content_html = '<div class="alert alert-secondary" role="alert"><i class="fas fa-info-circle me-2"></i>No data from Wappalyzer.</div>'

        return content.replace("{{ wappalyzer_content_area }}", wappalyzer_content_html)