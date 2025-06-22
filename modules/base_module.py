# hunterNG/modules/base_module.py

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional, List
from core.config_manager import config
from utils.cli_utils import CommandResult, console, print_list, run_cmd
from utils.file_utils import save_json, load_json, save_text

class BaseModule(ABC):
    def __init__(self, 
                 module_name: str, 
                 target: str, 
                 output_dir: Path, 
                 global_state: Dict[str, Any],
                 verbose: bool = False):
        self.module_name = module_name
        self.target = target
        self.output_dir = output_dir
        self.global_state = global_state
        self.verbose = verbose

        self.module_output_dir = output_dir / self.module_name
        self.module_output_dir.mkdir(parents=True, exist_ok=True)
        self.module_config = config.get_section(self.module_name.lower()) or {}
        self.console = console

        self.task_results: Dict[str, CommandResult] = {}
        self._current_workflow_config: Dict[str, Any] = {}

    def _should_execute_task(self, workflow_key: str, config_task_name: str) -> bool:
        workflow_enabled = self._current_workflow_config.get(workflow_key, True)
        config_enabled = self._get_config_value(f"{config_task_name}.enabled", True)
        
        # Task runs only if BOTH workflow and config allow it
        should_run = workflow_enabled and config_enabled
        
        if not should_run:
            if not workflow_enabled:
                self.console.print(f"[dim]Skipping {config_task_name} (disabled in workflow)[/dim]")
            elif not config_enabled:
                self.console.print(f"[dim]Skipping {config_task_name} (disabled in config)[/dim]")
        
        return should_run

    def _set_workflow_config(self, workflow_config: Dict[str, Any]) -> None:
        self._current_workflow_config = workflow_config

    def _get_config_value(self, key_path: str, default_value: Any=None) -> Any:
        keys = key_path.split('.')
        value = self.module_config
        try:
            for key in keys:
                if isinstance(value, dict):
                    value = value.get(key, default_value)
                else:
                    return default_value
            return value
        except KeyError:
            return default_value
        
    def _save_module_results(self, data: Dict[str, Any], filename: str="results.json") -> Path:
        output_file = self.module_output_dir / filename
        try:
            save_json(data, output_file)
            return output_file
        except Exception as e:
            self.console.print(f"[red]Error saving results: {e}[/red]")
            return None

    def _load_module_results(self, filename: str="results.json") -> Optional[Dict[str, Any]]:
        input_file = self.module_output_dir / filename
        if input_file.exists():
            try:
                data = load_json(input_file)
                if isinstance(data, dict):
                    self.console.print(f"[blue]Results loaded from: {input_file}[/blue]")
                    return data
                else:
                    self.console.print("[red]Loaded data is not a dictionary.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error loading results: {e}[/red]")
        else:
            self.console.print(f"[yellow]Results file does not exist: {input_file}[/yellow]")
        return None

    def _build_command(self, task_config: Dict[str, Any]) -> str:
        """Override to handle multiple command formats based on target type"""
        # Get target info from global state
        target_info = self.global_state.get('target_info', {})
        target_type = target_info.get('target_type', 'domain')
        
        # Handle commands dict vs single command
        command_template = ""
        if "commands" in task_config:
            commands = task_config["commands"]
            command_template = commands.get(target_type)
            if not command_template:
                self.console.print(f"[red]No command found for target type: {target_type}[/red]")
                return ""
        elif "command" in task_config:
            command_template = task_config["command"]
        else:
            self.console.print(f"[red]No command template found in task config[/red]")
            return ""
        
        # Build replacements based on target info
        replacements = {
            'target': self.target,
            'domain': target_info.get('domain', ''),
            'subdomain': target_info.get('subdomain', ''),
            'ip': target_info.get('ip', ''),
            'port': str(target_info.get('port', '')),
            'protocol': target_info.get('protocol', ''),
            'base_url': target_info.get('base_url', ''),
        }
        
        # Only replace if value exists and is not empty
        for key, value in replacements.items():
            if value:
                command_template = command_template.replace(f"{{{key}}}", str(value))
        
        return command_template
        
    def _execute_command_task(self, task_name: str,
                             stdin_data: Optional[str] = None,
                             show_output: Optional[bool] = True) -> CommandResult:
        task_config = self._get_config_value(task_name)
        if not task_config:
            self.console.print(f"[red]Task '{task_name}' not found in module config.[/red]")
            return CommandResult(False, "", "Task not found", -1, task_name)
        
        try:
            command = self._build_command(task_config)
        except Exception as e:
            self.console.print(f"[red]Error building command for task '{task_name}': {e}[/red]")
            return CommandResult(False, "", str(e), -1, task_name)

        input_type = task_config.get("input_type", "target")
        if input_type == "stdin" and stdin_data is None:
            self.console.print(f"[red]No input data provided for task '{task_name}' with input type 'stdin'.[/red]")
            return CommandResult(False, "", "No input data provided", -1, task_name)
        
        result = run_cmd(
            command,
            input_data=stdin_data,
            cwd=self.module_output_dir,
            verbose=self.verbose
        )

        if result.success:
            # self.console.print(f"Executing task: {task_name}")
            if show_output:
                print_list(
                    # title=f"Output for task: {task_name}",
                    title=f"Output: ",
                    items=result.stdout.strip().splitlines(),
                    verbose=self.verbose
                )
            self.console.print(f"[dim]Executed in {result.execution_time:.2f} seconds[/dim]")
        else:
            self.console.print(f"[red]Task '{task_name}' failed.[/red]")
            self.console.print(f"[red]Error: {result.stderr}[/red]")

        return result

    def _execute_pipeline_tasks(self, tasks: List[str], 
                                pipeline_data: Optional[str] = None,
                                show_output: Optional[bool] = True) -> Dict[str, CommandResult]:
        results = {}
        current_input = pipeline_data

        for task_name in tasks:
            result = self._execute_command_task(
                task_name=task_name,
                stdin_data=current_input,
                show_output=show_output
            )
            results[task_name] = result

            if result.success:
                current_input = result.stdout
            else:
                self.console.print(f"[red]Task '{task_name}' failed. Stopping pipeline execution.[/red]")
                break
        
        return results
    
    def _save_task_results(self, data: str, filename: str) -> Path:
        output_file = self.module_output_dir / f"{filename}.txt"
        try:
            save_text(data, output_file)
            # self.console.print(f"Saved to: {output_file}")
            return output_file
        except Exception as e:
            self.console.print(f"[red]Error saving: {e}[/red]")
            return None

    def _load_task_results(self, filename: str, source_module_name: Optional[str] = None) -> Optional[str]:
        if source_module_name:
            input_file = self.output_dir / source_module_name / f"{filename}.txt"
        else:
            input_file = self.module_output_dir / f"{filename}.txt"
        if input_file.exists():
            try:
                data = input_file.read_text()
                return data
            except Exception as e:
                self.console.print(f"[red]Error loading task results: {e}[/red]")
        else:
            self.console.print(f"[yellow]Task results file does not exist: {input_file}[/yellow]")
        return None

    def _get_primary_scan_target(self) -> str:
        scan_targets = self.global_state.get("scan_targets", {})

        priority_order = ['urls', 'hosts', 'domains', 'ips']
        for key in priority_order:
            if scan_targets.get(key):
                self.target = scan_targets[key][0]
                break
        return self.target

    @abstractmethod
    def run(self, **kwargs) -> Dict[str, Any]:
        self.console.print("")
        self.console.print(f"[yellow]Running module: {self.module_name} on target: {self.target}[/yellow]")
        self.console.print("")

        workflow_config = kwargs.get("workflow_config", {})
        self._set_workflow_config(workflow_config)
        pass