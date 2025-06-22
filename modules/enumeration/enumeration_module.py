# hunterNG/modules/enumeration/enumeration_module.py

import re
from pathlib import Path
from typing import Any, Dict
from modules.base_module import BaseModule

class EnumerationModule(BaseModule):
    def __init__(self, module_name: str, 
                 target: str, 
                 output_dir: Path, 
                 global_state: Dict[str, Any], 
                 verbose: bool = False):
        super().__init__(module_name, target, output_dir, global_state, verbose)

    def run(self, **kwargs) -> Dict[str, Any]:
        super().run(**kwargs)
        
        focus_path = kwargs.get("focus_path", False)

        target_info = self.global_state.get('target_info', {})
        target_type = target_info.get('target_type', 'domain')

        results: Dict[str, Any] = {
            "target": self.target,
            "module_name": self.module_name,
            "output_dir": str(self.module_output_dir),
            "target_type": target_type,
            "focus_path": focus_path,
        }

        # Nmap scan
        self.console.print(f"[blue]Starting Nmap scan[/blue]")
        nmap_results = self._execute_command_task("nmap")
        self._save_task_results(nmap_results.stdout, "nmap")


        # Content discovery
        self.console.print(f"[blue]Starting Content discovery[/blue]")
        content_results = self._execute_command_task("content_discovery")
        self._save_task_results(content_results.stdout, "content_discovery")

        # Hidden parameters
        self.console.print(f"[blue]Finding hidden parameters[/blue]")
        hidden_param_results = self._execute_command_task("hidden_param")
        raw_output = hidden_param_results.stdout
        
        # 1. Loại bỏ các ký tự màu (ANSI escape codes)
        ansi_escape_pattern = re.compile(r'\x1b\[[0-9;]*m')
        output_no_color = ansi_escape_pattern.sub('', raw_output)
        
        # 2. Lọc bỏ các dòng "Processing chunks:" không cần thiết
        cleaned_lines = []
        for line in output_no_color.splitlines():
            if "Processing chunks:" not in line:
                cleaned_lines.append(line)
        
        # Nối các dòng đã làm sạch lại thành một chuỗi duy nhất
        cleaned_output = "\n".join(cleaned_lines)
        self._save_task_results(cleaned_output, "hidden_param")

        self._save_module_results(results)
        return results