# hunterNG/modules/report/assessment_report.py

import html
from pathlib import Path
from typing import Any, Dict, Optional
from rich.console import Console

class AssessmentReport:
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

    def _calculate_assessment_stats(self, assessment_dir: Path) -> Dict[str, int]:
        """Calculate vulnerability statistics from assessment data"""
        stats = {
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'total_vulns': 0
        }

        # Count vulnerabilities by type/severity
        candidate_files = list(assessment_dir.glob("*_candidates.txt"))
        
        for file_path in candidate_files:
            if file_path.exists() and file_path.stat().st_size > 0:
                try:
                    content = file_path.read_text()
                    vuln_count = len([line for line in content.splitlines() if line.strip() and line.startswith('[')])
                    
                    # Categorize by vulnerability type (this is a simplified approach)
                    filename = file_path.stem.lower()
                    if any(critical in filename for critical in ['sqli', 'cmdi', 'rce', 'xxe']):
                        stats['critical_count'] += vuln_count
                    elif any(high in filename for high in ['xss', 'ssrf', 'ssti', 'lfi', 'rfi']):
                        stats['high_count'] += vuln_count
                    elif any(medium in filename for medium in ['crlf', 'redirect', 'injection']):
                        stats['medium_count'] += vuln_count
                    else:
                        stats['low_count'] += vuln_count
                        
                except Exception:
                    continue

        stats['total_vulns'] = sum([stats['critical_count'], stats['high_count'], 
                                   stats['medium_count'], stats['low_count']])
        return stats

    def _generate_security_status_card(self, stats: Dict[str, int]) -> str:
        """Generate security status overview card"""
        total_vulns = stats['total_vulns']
        
        if total_vulns == 0:
            status_class = "success"
            status_icon = "fas fa-shield-alt"
            status_text = "Excellent"
            status_message = "No vulnerabilities detected by automated scanners"
            score_class = "score-excellent"
            score = "A"
        elif stats['critical_count'] > 0:
            status_class = "danger"
            status_icon = "fas fa-exclamation-triangle"
            status_text = "Critical Issues Found"
            status_message = f"{stats['critical_count']} critical vulnerabilities require immediate attention"
            score_class = "score-poor"
            score = "F"
        elif stats['high_count'] > 0:
            status_class = "warning"
            status_icon = "fas fa-exclamation-circle"
            status_text = "High Risk Issues"
            status_message = f"{stats['high_count']} high-priority vulnerabilities found"
            score_class = "score-fair"
            score = "C"
        else:
            status_class = "info"
            status_icon = "fas fa-info-circle"
            status_text = "Low Risk Issues"
            status_message = "Only low to medium risk issues detected"
            score_class = "score-good"
            score = "B"

        return f"""
        <div class="alert alert-{status_class} border-0 shadow">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h4 class="alert-heading mb-2">
                        <i class="{status_icon} me-2"></i>{status_text}
                    </h4>
                    <p class="mb-0">{status_message}</p>
                    <small class="text-muted">Total findings: {total_vulns}</small>
                </div>
                <div class="col-md-4 text-center">
                    <div class="security-score {score_class}">{score}</div>
                    <small class="text-muted">Security Score</small>
                </div>
            </div>
        </div>
        """

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
        self.console.print("[blue]Generating report for Assessment module...[/blue]")
        if 'assessment_results' not in self.global_state:
            return self._generate_placeholder_page("Assessment", "assessment_results")

        assessment_dir = Path(self.global_state['assessment_results'].get('output_dir', ''))
        if not assessment_dir.is_dir():
            self.console.print(f"[yellow]Warning: Assessment output directory not found: {assessment_dir}[/yellow]")
            return self._generate_placeholder_page("Assessment", "assessment_results")

        try:
            content_template = (self.template_dir / "assessment_content.html").read_text()
        except FileNotFoundError:
            self.console.print("[red]Error: assessment_content.html not found[/red]")
            return "<h3>Unable to load Assessment template.</h3>"

        # Calculate vulnerability statistics
        stats = self._calculate_assessment_stats(assessment_dir)
        
        # Generate security status card
        security_status_card = self._generate_security_status_card(stats)
        content_template = content_template.replace("{{ security_status_card }}", security_status_card)
        
        # Replace statistics
        for stat_name, stat_value in stats.items():
            content_template = content_template.replace(f"{{{{ {stat_name} }}}}", str(stat_value))

        # REAL-TIME FILE DETECTION - Always scan directory fresh
        candidate_files = []
        if assessment_dir.exists():
            # Scan for files that actually exist and have content
            for pattern_file in assessment_dir.glob("*_candidates.txt"):
                if pattern_file.exists() and pattern_file.stat().st_size > 0:
                    # Double-check file still exists and has content
                    try:
                        content = pattern_file.read_text().strip()
                        if content:  # Only include non-empty files
                            candidate_files.append(pattern_file)
                            self.console.print(f"[green]Found active file: {pattern_file.name}[/green]")
                        else:
                            self.console.print(f"[yellow]Skipping empty file: {pattern_file.name}[/yellow]")
                    except Exception as e:
                        self.console.print(f"[red]Error reading {pattern_file.name}: {e}[/red]")
        
        # Sort the found files
        candidate_files = sorted(candidate_files)
        
        self.console.print(f"[blue]Active candidate files found: {len(candidate_files)}[/blue]")
        for f in candidate_files:
            self.console.print(f"[blue]  - {f.name}[/blue]")

        if not candidate_files:
            tabs_html = ""
            contents_html = '''
            <div class="alert alert-info mt-3 border-0 shadow" role="alert">
                <h4 class="alert-heading">
                    <i class="fas fa-shield-alt me-2"></i>Excellent Security Posture!
                </h4>
                <p class="mb-0">No vulnerabilities were detected by our automated security scanners. This indicates a strong security configuration.</p>
                <hr>
                <p class="mb-0 small">
                    <i class="fas fa-info-circle me-1"></i>
                    Consider manual testing and code review for comprehensive security assessment.
                </p>
            </div>
            '''
        else:
            tabs_html_parts = []
            contents_html_parts = []
            is_first_tab = True

            # Enhanced title mapping with icons and better descriptions
            title_mapping = {
                "llm_candidates": ("Priority Targets", "High-Value URLs Selected by AI", "fas fa-bullseye", "primary"),
                "dalfox_xss_candidates": ("Dalfox XSS", "Cross-Site Scripting Vulnerabilities", "fas fa-code", "warning"),
                "sqli_candidates": ("SQL Injection", "SQL Injection Vulnerabilities", "fas fa-database", "danger"),
                "xss_candidates": ("XSS", "Cross-Site Scripting Findings", "fas fa-code", "warning"),
                "cmdi_candidates": ("Command Injection", "Command Injection Vulnerabilities", "fas fa-terminal", "danger"),
                "crlf_candidates": ("CRLF Injection", "CRLF Injection Findings", "fas fa-arrows-alt-v", "warning"),
                "injection_candidates": ("Other Injections", "Various Injection Vulnerabilities", "fas fa-syringe", "warning"),
                "lfi_candidates": ("LFI", "Local File Inclusion Vulnerabilities", "fas fa-file", "warning"),
                "redirect_candidates": ("Open Redirect", "Open Redirect Vulnerabilities", "fas fa-external-link-alt", "info"),
                "rfi_candidates": ("RFI", "Remote File Inclusion Vulnerabilities", "fas fa-cloud", "danger"),
                "ssrf_candidates": ("SSRF", "Server-Side Request Forgery", "fas fa-server", "danger"),
                "ssti_candidates": ("SSTI", "Server-Side Template Injection", "fas fa-code", "danger"),
                "xxe_candidates": ("XXE", "XML External Entity Vulnerabilities", "fas fa-file-code", "danger"),
                "cve_candidates": ("Known CVEs", "Known CVE Detections", "fas fa-bug", "warning")
            }

            # SORT FILES TO PUT LLM_CANDIDATES FIRST
            sorted_files = []
            llm_candidates_file = None
            other_files = []
            
            for path in candidate_files:
                if path.stem == "llm_candidates":
                    llm_candidates_file = path
                else:
                    other_files.append(path)
            
            # Put llm_candidates first, then others
            if llm_candidates_file:
                sorted_files.append(llm_candidates_file)
            sorted_files.extend(other_files)

            for path in sorted_files:
                filename_stem = path.stem
                vuln_id = f"assessment-{filename_stem}"

                # Get enhanced metadata from mapping
                default_tab_name = filename_stem.replace('_candidates', '').upper()
                default_content_title = f"Results for {default_tab_name}"
                default_icon = "fas fa-exclamation-triangle"
                default_severity = "secondary"
                
                tab_name, content_title, icon, severity = title_mapping.get(
                    filename_stem, 
                    (default_tab_name, default_content_title, default_icon, default_severity)
                )
                
                active_class = "active" if is_first_tab else ""
                show_class = "show active" if is_first_tab else ""

                # Count vulnerabilities in this file - REAL-TIME COUNT
                vuln_count = self._count_lines_in_file(path)
                badge_html = f'<span class="badge bg-{severity} ms-1">{vuln_count}</span>' if vuln_count > 0 else ''

                tabs_html_parts.append(
                    f'<li class="nav-item" role="presentation">'
                    f'<button class="nav-link {active_class}" id="{vuln_id}-tab" data-bs-toggle="tab" '
                    f'data-bs-target="#{vuln_id}-content" type="button" role="tab">'
                    f'<i class="{icon} me-2"></i>{tab_name}{badge_html}'
                    f'</button></li>'
                )

                # REAL-TIME DATA LOADING
                data = self._load_data_from_module(assessment_dir, filename_stem)
                escaped_data = html.escape(data or "No data available.")
                
                # Add severity indicator to content
                severity_badge = f'<span class="vulnerability-badge severity-{severity}"><i class="{icon} me-1"></i>{severity.upper()}</span>'
                
                # SPECIAL HANDLING FOR LLM_CANDIDATES - ADD DESCRIPTION
                if filename_stem == "llm_candidates":
                    description_html = '''
                    <div class="alert alert-primary border-0 mb-3">
                        <i class="fas fa-info-circle me-2"></i>
                        <strong>AI-Selected Priority Targets:</strong> These URLs were intelligently selected by our AI system based on their likelihood to contain vulnerabilities. They include URLs with multiple parameters, suspicious parameter names, and interesting paths that warrant immediate security testing.
                    </div>
                    '''
                else:
                    description_html = f'''
                    <div class="alert alert-{severity} border-0">
                        <i class="{icon} me-2"></i>
                        <strong>Found {vuln_count} potential issues</strong> - Review each finding carefully and verify manually.
                    </div>
                    '''
                
                contents_html_parts.append(
                    f'<div class="tab-pane fade {show_class}" id="{vuln_id}-content" role="tabpanel">'
                    f'<div class="d-flex justify-content-between align-items-center mb-3">'
                    f'<h2><i class="{icon} text-{severity} me-2"></i>{content_title}</h2>'
                    f'{severity_badge}'
                    f'</div>'
                    f'{description_html}'
                    f'<pre><code>{escaped_data}</code></pre>'
                    f'</div>'
                )
                is_first_tab = False

            tabs_html = "\n".join(tabs_html_parts)
            contents_html = "\n".join(contents_html_parts)
            
        final_content = content_template.replace("{{ assessment_tabs }}", tabs_html)
        final_content = final_content.replace("{{ assessment_contents }}", contents_html)

        return final_content