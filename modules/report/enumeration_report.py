# hunterNG/modules/report/enumeration_report.py

import html
import re
from pathlib import Path
from typing import Any, Dict, Optional
from rich.console import Console

class EnumerationReport:
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

    def _calculate_enumeration_stats(self, enum_dir: Path) -> Dict[str, int]:
        """Calculate statistics for enumeration data"""
        # Count open ports from nmap output
        open_ports_count = 0
        nmap_file = enum_dir / "nmap.txt"
        if nmap_file.exists():
            try:
                nmap_content = nmap_file.read_text()
                # Count lines containing "open" (typical nmap output format)
                open_ports_count = len([line for line in nmap_content.splitlines() 
                                     if "open" in line.lower() and "/" in line])
            except Exception:
                open_ports_count = 0

        # Count directories from content discovery
        directories_count = self._count_lines_in_file(enum_dir / "content_discovery.txt")
        
        # Count hidden parameters
        hidden_params_count = 0
        hidden_param_file = enum_dir / "hidden_param.txt"
        if hidden_param_file.exists():
            try:
                content = hidden_param_file.read_text()
                # Look for parameter indicators in Arjun output
                hidden_params_count = len(re.findall(r'Found parameter:', content))
            except Exception:
                hidden_params_count = 0

        return {
            'open_ports_count': open_ports_count,
            'directories_count': directories_count,
            'hidden_params_count': hidden_params_count
        }

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
        self.console.print("[blue]Generating report for Enumeration module...[/blue]")
        if 'enumeration_results' not in self.global_state:
            return self._generate_placeholder_page("Enumeration", "enumeration_results")

        enum_dir = Path(self.global_state['enumeration_results'].get('output_dir', ''))
        try:
            content = (self.template_dir / "enumeration_content.html").read_text()
        except FileNotFoundError:
            self.console.print("[red]Error: enumeration_content.html not found[/red]")
            return "<h3>Unable to load Enumeration template.</h3>"

        # Calculate and insert statistics
        stats = self._calculate_enumeration_stats(enum_dir)
        for stat_name, stat_value in stats.items():
            content = content.replace(f"{{{{ {stat_name} }}}}", str(stat_value))

        # Load and replace file data
        files = {
            "nmap": "nmap_data",
            "content_discovery": "content_discovery_data",
            "hidden_param": "hidden_param_data"
        }

        for f, p in files.items():
            data = self._load_data_from_module(enum_dir, f)
            content = content.replace(f"{{{{ {p} }}}}", html.escape(data or "No data available."))

        return content