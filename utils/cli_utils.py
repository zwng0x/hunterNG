# hunterNG/utils/cli_utils.py

from pathlib import Path
import shlex
import subprocess
import time
from typing import Any, Dict, Iterable, List, Optional, Union
from rich.console import Console
from core.config_manager import config

console = Console()

def banner() -> None:
    art = r"""
    __  __            __           
   / / / /_  ______  / /____  _____  _NG_
  / /_/ / / / / __ \/ __/ _ \/ ___/
 / __  / /_/ / / / / /_/  __/ /    
/_/ /_/\__,_/_/ /_/\__/\___/_/     
    Automated Pentest Framework
"""
    console.print(art, style="bold blue")

def print_list(title: Optional[str], 
               items: Iterable[Any], 
               verbose: Optional[bool]
               )-> None:
    show_sample_count = config.get("general.show_sample_count", 10)
    item_list = list(items)
    total = len(item_list)

    console.print(f"-> {title} ({total})")
    sample_items =  item_list if verbose else item_list[:show_sample_count]

    for item in sample_items:
        console.print(f"[dim]{str(item)}[/dim]")

    if not verbose and total > show_sample_count:
        console.print(f"[dim]... and {total - show_sample_count} more items[/dim]")

class CommandResult:
    def __init__(self, success: bool,
                 stdout: str,
                 stderr: str,
                 returncode: int,
                 command: str,
                 execution_time: float = 0):
        self.success = success
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.command = command
        self.execution_time = execution_time

    def __bool__(self) -> bool:
        return self.success
    
    def __str__(self) -> str:
        return self.stdout

def run_cmd(command: Union[str, List[str]],
            input_data: Optional[str] = None,
            timeout: int = 300,
            cwd: Optional[Path] = None,
            env: Optional[Dict[str, str]] = None,
            shell: Optional[bool] = True,
            capture_output: bool = True,
            text: bool = True,
            verbose: bool = False) -> CommandResult:
    """
    Execute a command with comprehensive options and error handling
    
    Args:
        command: Command string or list of command parts
        input_data: Data to pipe to stdin
        timeout: Command timeout in seconds
        cwd: Working directory
        env: Environment variables
        shell: Use shell execution
        capture_output: Capture stdout/stderr
        text: Return text instead of bytes
        verbose: Print debug information
    
    Returns:
        CommandResult object with execution details
    """
    start_time = time.time()
    try:
        # prepare command
        if isinstance(command, str):
            if shell:
                cmd = command
            else:
                cmd = shlex.split(command)
        else:
            cmd = command
        if verbose:
            console.print(f"[green]Executing: {cmd}[/green]")

        # execute command
        result = subprocess.run(
            cmd,
            input=input_data,
            timeout=timeout,
            cwd=cwd,
            env=env,
            shell=shell,
            capture_output=capture_output,
            text=text
        )

        execution_time = time.time() - start_time
        success = result.returncode == 0

        return CommandResult(
            success=success,
            stdout=result.stdout or "",
            stderr=result.stderr or "",
            returncode=result.returncode,
            command=str(cmd),
            execution_time=execution_time
        )
    except subprocess.TimeoutExpired as e:
        execution_time = time.time() - start_time
        console.print(f"[red]Timed out after {timeout} seconds[/red]")
        return CommandResult(
            success=False,
            stdout=e.stdout.decode() if e.stdout else "",
            stderr=e.stderr.decode() if e.stderr else str(e),
            returncode=-1,
            command=str(cmd),
            execution_time=execution_time
        )
    except subprocess.CalledProcessError as e:
        execution_time = time.time() - start_time
        console.print(f"[red]Command failed with return code {e.returncode}[/red]")
        return CommandResult(
            success=False,
            stdout=e.stdout.decode() if e.stdout else "",
            stderr=e.stderr.decode() if e.stderr else "",
            returncode=e.returncode,
            command=str(cmd),
            execution_time=execution_time
        )
    except Exception as e:
        execution_time = time.time() - start_time
        console.print(f"[red]Unexpected error: {str(e)}[/red]")
        return CommandResult(
            success=False,
            stdout="",
            stderr=str(e),
            returncode=-1,
            command=str(cmd),
            execution_time=execution_time
        )
