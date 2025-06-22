# hunterNG/modules/report/report_module.py

import html
from pathlib import Path
from typing import Any, Dict
from modules.base_module import BaseModule
from utils.file_utils import save_text
from .recon_report import ReconReport
from .enumeration_report import EnumerationReport
from .assessment_report import AssessmentReport

class ReportModule(BaseModule):
    def __init__(self, module_name: str, target: str, output_dir: Path, global_state: Dict[str, Any], verbose: bool = False):
        super().__init__(module_name, target, output_dir, global_state, verbose)
        self.template_dir = Path(__file__).parent / "templates"
        
        # Initialize report generators
        self.recon_report = ReconReport(self.template_dir, self.module_output_dir, self.global_state, self.console, self.verbose)
        self.enumeration_report = EnumerationReport(self.template_dir, self.module_output_dir, self.global_state, self.console, self.verbose)
        self.assessment_report = AssessmentReport(self.template_dir, self.module_output_dir, self.global_state, self.console, self.verbose)

    def run(self, **kwargs) -> Dict[str, Any]:
        super().run(**kwargs)

        try:
            base_template = (self.template_dir / "base.html").read_text()
        except FileNotFoundError:
            self.console.print(f"[red]Error: Could not find base.html at {self.template_dir}[/red]")
            return {}

        base_template = base_template.replace("{{ target }}", html.escape(self.target))

        pages = [
            ("recon", self.recon_report.generate()),
            ("enumeration", self.enumeration_report.generate()),
            ("assessment", self.assessment_report.generate()),
        ]
        
        for name, content in pages:
            self._render_and_save_page(base_template, name, content)

        report_path = self.module_output_dir / "recon.html"
        self.console.print(f"[green]HTML report generated: {report_path}[/green]")

        results = {"report_path": str(self.module_output_dir)}
        self._save_module_results(results)
        return results

    def _render_and_save_page(self, base_template: str, page_name: str, content: str):
        html_content = base_template.replace("{{ content }}", content)
        for tab in ["recon", "enumeration", "assessment"]:
            html_content = html_content.replace(f"{{{{ {tab}_active }}}}", "active" if tab == page_name else "")
        try:
            save_text(html_content, self.module_output_dir / f"{page_name}.html")
        except Exception as e:
            self.console.print(f"[red]Error while saving {page_name}.html: {e}[/red]")