# hunterNG/core/orchestrator.py

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from core.module_manager import ModuleManager
from core.config_manager import config
from core.target_handler import TargetHandler, TargetInfo
from utils.cli_utils import console
from utils.file_utils import load_json, save_json

class Orchestrator:
    def __init__(self, target: Optional[str], base_output_dir_name: Optional[str] = None, resume_path: Optional[str] = None):
        self.module_manager = ModuleManager()
        self.target_handler = TargetHandler()

        if self.module_manager.available_modules:
            console.print(f"[yellow]Available modules: {', '.join(self.module_manager.available_modules.keys())}[/yellow]")
        else:
            console.print("[yellow]No modules were found.[/yellow]")

        self.global_state: Dict[str, Any] = {}
        self.base_output_dir_name = base_output_dir_name or config.get('general.default_output_directory', 'hunter_output')
        self.resume_path = resume_path
        self.target: Optional[str] = None
        self.target_info: Optional[TargetInfo] = None

        if resume_path:
            self.output_dir = Path(resume_path).resolve()
            if not self.output_dir.is_dir():
                console.print(f"[red]Resume path '{self.output_dir}' is not a directory.[/red]")
                raise ValueError("Resume path must be a directory.")
            console.print(f"[yellow]Resuming from: {self.output_dir}[/yellow]")

            self._load_resume_state()

            if target is None:
                resume_target_from_state = self.global_state.get('target')
                if resume_target_from_state:
                    self.target = str(resume_target_from_state)
                    console.print(f"[yellow]Resuming target: {resume_target_from_state}[/yellow]")

                    if "target_info" in self.global_state:
                        self.target_info = self._restore_target_info(self.global_state['target_info'])
                    else:
                        self.target_info = self.target_handler.identify_target_type(self.target)
                else:
                    console.print(f"[red]Target not found in global_state.json from {self.output_dir / 'global_state.json'}[/red]")
                    raise ValueError("Target not found in resumed global_state and not provided via --target.")
            else:
                self.target = target
                self.target_info = self.target_handler.identify_target_type(target)
                console.print(f"[yellow]Using provided target: {self.target}[/yellow]")
                if self.global_state.get('target') != self.target:
                    console.print("[yellow]Overriding target in global state.[/yellow]")
                    self.global_state['target'] = self.target
        else:
            if target is None:
                console.print("[red]Target must be specified when not resuming.[/red]")
                raise ValueError("Target must be specified when not resuming.")
            
            self.target = target
            self.target_info = self.target_handler.identify_target_type(self.target)
            self._initialize_output_directory(self.target)
            self.global_state['target'] = self.target

        # Display target analysis
        self._display_target_analysis()
        
        # Enhance global state with target information
        self.global_state = self.target_handler.enhance_global_state(self.target_info, self.global_state)

    def _display_target_analysis(self):
        """Display target analysis results"""
        console.print(f"[blue]Target Analysis:[/blue]")
        console.print(f"  Original Input: [cyan]{self.target_info.original_input}[/cyan]")
        console.print(f"  Target Type: [green]{self.target_info.target_type.value.upper()}[/green]")
        
        if self.target_info.domain:
            console.print(f"  Domain: [cyan]{self.target_info.domain}[/cyan]")
        if self.target_info.subdomain:
            console.print(f"  Subdomain: [cyan]{self.target_info.subdomain}[/cyan]")
        if self.target_info.ip:
            console.print(f"  IP: [cyan]{self.target_info.ip}[/cyan]")
        if self.target_info.port:
            console.print(f"  Port: [cyan]{self.target_info.port}[/cyan]")
        if self.target_info.protocol:
            console.print(f"  Protocol: [cyan]{self.target_info.protocol}[/cyan]")
        if self.target_info.path:
            console.print(f"  Path: [cyan]{self.target_info.path}[/cyan]")

    def _restore_target_info(self, target_info_dict: Dict[str, Any]) -> TargetInfo:
        """Restore TargetInfo from dictionary"""
        from core.target_handler import TargetType
        
        return TargetInfo(
            original_input=target_info_dict.get('original_input', ''),
            target_type=TargetType(target_info_dict.get('target_type', 'domain')),
            domain=target_info_dict.get('domain'),
            subdomain=target_info_dict.get('subdomain'),
            ip=target_info_dict.get('ip'),
            port=target_info_dict.get('port'),
            protocol=target_info_dict.get('protocol'),
            path=target_info_dict.get('path'),
            base_url=target_info_dict.get('base_url')
        )

    def _initialize_output_directory(self, target: str) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        # Create safer filename from target
        safe_target = self._sanitize_target_for_filename(target)
        self.output_dir = Path(self.base_output_dir_name) / f"{safe_target}_{timestamp}"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        console.print(f"[yellow]Creating output directory: {self.output_dir}[/yellow]")

    def _sanitize_target_for_filename(self, target: str) -> str:
        """Sanitize target for use in filename"""
        # Remove protocol
        safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_').replace('.', '_')
        # Remove special characters
        safe_target = ''.join(c for c in safe_target if c.isalnum() or c in '_-')
        return safe_target[:50]  # Limit length

    def _load_resume_state(self):
        if not self.output_dir or not self.output_dir.is_dir():
            console.print("[red]No valid output directory found for resuming.[/red]")
            self.global_state = {}
            return
        
        global_state_file = self.output_dir / "global_state.json"
        if global_state_file.exists():
            try:
                loaded_data = load_json(global_state_file)
                if isinstance(loaded_data, dict):
                    self.global_state = loaded_data
                    console.print(f"[yellow]Global state loaded from {global_state_file}[/yellow]")
                else:
                    console.print("[red]Data from global_state.json is not a dictionary.[/red]")
                    self.global_state = {}
            except Exception as e:
                console.print(f"[red]Error loading global state: {e}[/red]")
                self.global_state = {}
        else:
            console.print("[yellow]No global state file found for resuming.[/yellow]")
            self.global_state = {}
        
    def _save_global_state(self) -> None:
        if not self.output_dir or not self.output_dir.is_dir():
            console.print("[red]No valid output directory found for saving global state.[/red]")
            return
        
        global_state_file = self.output_dir / "global_state.json"
        try:
            save_json(self.global_state, global_state_file)
        except Exception as e:
            console.print(f"[red]Error saving global state: {e}[/red]")

    def _prepare_module_kwargs(self, 
                               module_name: str, 
                               workflow_config: Dict[str, Any], 
                               focus_domain: bool,
                               focus_path: bool) -> Dict[str, Any]:
        kwargs = {}
        
        if module_name == "recon":
            kwargs['focus_domain'] = focus_domain
            kwargs['focus_path'] = focus_path
            kwargs['workflow_config'] = workflow_config.get('recon_config', {})

        elif module_name == "enumeration":
            kwargs['workflow_config'] = workflow_config.get('enumeration_config', {})
            
        elif module_name == "assessment":
            kwargs['workflow_config'] = workflow_config.get('assessment_config', {})
        
        return kwargs

    def run_pipeline(
        self,
        modules_order: Optional[list[str]] = None,
        focus_domain: bool = False,
        focus_path: bool = False,
        verbose: bool = False
    ) -> None:
        
        # Get workflow configuration for target type
        workflow_config = self.target_handler.get_workflow_config(self.target_info)

        for module_name in modules_order:
            if self.resume_path:
                if f"{module_name}_results" in self.global_state:
                    del self.global_state[f"{module_name}_results"]
                
            console.print("")
            console.rule(f"[blue]MODULE: {module_name.upper()}[/blue]")

            module_instance = self.module_manager.get_module_instance(
                module_name = module_name,
                target = self.target,
                output_dir = self.output_dir,
                global_state = self.global_state,
                verbose = verbose
            )

            try:
                # Prepare module-specific kwargs based on target type and workflow config
                run_kwargs = self._prepare_module_kwargs(module_name, workflow_config, focus_domain, focus_path)

                module_output = module_instance.run(**run_kwargs)
                if module_output is not None:
                    self.global_state[f"{module_name}_results"] = module_output
                    console.print("")
                    console.print(f"[blue]Module '{module_name}' completed successfully.[/blue]")
                else:
                    console.print(f"[red]Module '{module_name}' returned no output.[/red]")
            except Exception as e:
                console.print(f"[red]Error running module '{module_name}': {e}[/red]")
                import traceback
                console.print(traceback.format_exc())
            finally:
                self._save_global_state()
        
        console.print("")
        console.print("[blue]Pipeline execution completed.[/blue]")
        console.print(f"[blue]Global state saved to: {self.output_dir}[/blue]")