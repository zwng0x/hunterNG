# hunterNG/hunter.py

import argparse
import sys
from core.config_manager import config
from core.module_manager import ModuleManager
from core.orchestrator import Orchestrator
from core.target_handler import TargetHandler
from utils.cli_utils import banner, console

AVAILABLE_MODULE_CHOICES = list(ModuleManager().available_modules.keys())
DEFAULT_MODULES_ORDER = ["recon", "enumeration", "assessment", "report"]
VERSION = "0.1.0"

def parse_args():
    parser = argparse.ArgumentParser(description="HunterNG - Automated Pentest Framework", formatter_class=argparse.RawTextHelpFormatter)

    is_resuming = "--resume" in sys.argv

    parser.add_argument(
        "--version",
        action="version",
        version=f"HunterNG {VERSION}",
        help="Show the version of HunterNG"
    )
    parser.add_argument(
        "-t", "--target",
        required=not is_resuming,
        help="""Target to scan. Supports multiple formats:
  Domain:     example.com
  Subdomain:  api.example.com  
  URL:        https://example.com/path
  IPv4:       192.168.1.1
  IPv4+Port:  192.168.1.1:8080
  
If --resume is used, this argument is optional."""
    )
    parser.add_argument(
        "-l", "--local",
        action="store_true",
        default=False,
        help="For local scans.",
    )
    parser.add_argument(
        "-o", "--output",
        help=f"Output folder for results. Default: {config.get('general.default_output_directory', 'output')}"
    )
    parser.add_argument(
        "--focus-domain",
        action="store_true",
        help="Focus scan on the provided domain/subdomain without discovering other subdomains."
    )
    parser.add_argument(
        "--focus-path",
        action="store_true",
        help="Focus scan on the specific path provided in the URL target."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=None,
        help="Enable verbose output."
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Only analyze target and show recommended workflow, don't run scan."
    )

    pipeline_group = parser.add_argument_group("Pipeline Configuration")
    pipeline_group.add_argument(
        "--pipeline",
        nargs="+",
        help="Custom pipeline to use. This overrides --only and --skip options."
    )
    pipeline_group.add_argument(
        "--only",
        nargs="+",
        choices=AVAILABLE_MODULE_CHOICES,
        help="Only run the specified modules."
    )
    pipeline_group.add_argument(
        "--skip",
        nargs="+",
        choices=AVAILABLE_MODULE_CHOICES,
        help="Skip the specified modules."
    )
    pipeline_group.add_argument(
        "--resume",
        metavar="DIR",
        help="Path to a previous output directory to resume from. If specified, --target is not required."
    )

    args = parser.parse_args()
    
    if args.target is None and not is_resuming:
        parser.error("The --target argument is required unless using --resume.")
    
    if args.verbose is None:
        args.verbose = bool(config.get("general.verbose", False))
    if args.verbose is not None:
        config._config["general"]["verbose"] = args.verbose

    return args

def analyze_target_only(target: str):

    target_handler = TargetHandler()
    target_info = target_handler.identify_target_type(target)
    workflow_config = target_handler.get_workflow_config(target_info)
    
    console.print("\n[blue]═══ TARGET ANALYSIS ═══[/blue]")
    console.print(f"Original Input: [cyan]{target_info.original_input}[/cyan]")
    console.print(f"Target Type: [green]{target_info.target_type.value.upper()}[/green]")
    
    if target_info.domain:
        console.print(f"Domain: [cyan]{target_info.domain}[/cyan]")
    if target_info.subdomain:
        console.print(f"Subdomain: [cyan]{target_info.subdomain}[/cyan]")
    if target_info.ip:
        console.print(f"IP Address: [cyan]{target_info.ip}[/cyan]")
    if target_info.port:
        console.print(f"Port: [cyan]{target_info.port}[/cyan]")
    if target_info.protocol:
        console.print(f"Protocol: [cyan]{target_info.protocol}[/cyan]")
    if target_info.path:
        console.print(f"Path: [cyan]{target_info.path}[/cyan]")
    
    console.print(f"\n[blue]═══ RECOMMENDED WORKFLOW ═══[/blue]")
    
    console.print(f"\n[blue]RECON CONFIGURATION[/blue]")
    recon_config = workflow_config.get('recon_config', {})
    for task, enabled in recon_config.items():
        status = "[green]✓[/green]" if enabled else "[red]✗[/red]"
        console.print(f"  {status} {task}")

    console.print(f"\n[blue]ENUMERATION CONFIGURATION[/blue]")
    enum_config = workflow_config.get('enumeration_config', {})
    for task, enabled in enum_config.items():
        status = "[green]✓[/green]" if enabled else "[red]✗[/red]"
        console.print(f"  {status} {task}")

    console.print(f"\n[blue]ASSESSMENT CONFIGURATION[/blue]")
    assess_config = workflow_config.get('assessment_config', {})
    for task, enabled in assess_config.items():
        status = "[green]✓[/green]" if enabled else "[red]✗[/red]"
        console.print(f"  {status} {task}")
    
    # Generate scan targets
    global_state = {"target": target}
    enhanced_state = target_handler.enhance_global_state(target_info, global_state)
    scan_targets = enhanced_state.get('scan_targets', {})
    
    console.print(f"\n[bold blue]═══ SCAN TARGETS ═══[/bold blue]")
    for target_type, targets in scan_targets.items():
        if targets:
            console.print(f"[yellow]{target_type.upper()}:[/yellow]")
            for t in targets:
                console.print(f"  • {t}")

def main():
    banner()
    args = parse_args()

    if args.analyze:
        if not args.target:
            console.print("[red]--target is required for analysis mode[/red]")
            sys.exit(1)
        analyze_target_only(args.target)
        return

    modules_order = DEFAULT_MODULES_ORDER

    if args.pipeline:
        invalid_pipeline_modules = [m for m in args.pipeline if m not in AVAILABLE_MODULE_CHOICES]
        if invalid_pipeline_modules:
            console.print(f"[red]Invalid modules in pipeline: {', '.join(invalid_pipeline_modules)}[/red]")
            console.print(f"[red]Available modules are: {', '.join(AVAILABLE_MODULE_CHOICES)}[/red]")
            exit(1)
        modules_order = args.pipeline
        console.print(f"[yellow]Using custom pipeline: {', '.join(modules_order)}[/yellow]")
        
    elif args.only:
        valid_only_modules = []
        invalid_only_modules = []
        for m_only in args.only:
            if m_only in AVAILABLE_MODULE_CHOICES:
                valid_only_modules.append(m_only)
            else:
                invalid_only_modules.append(m_only)
        
        if invalid_only_modules:
            console.print(f"[red]Invalid modules in --only: {', '.join(invalid_only_modules)}[/red]")
            console.print(f"[red]Available modules are: {', '.join(AVAILABLE_MODULE_CHOICES)}[/red]")
            exit(1)

        modules_order = [m for m in DEFAULT_MODULES_ORDER if m in valid_only_modules]
        if all(m in modules_order for m in args.only):
            modules_order = [m for m in args.only if m in modules_order]

        console.print(f"[yellow]Only running specified modules: {', '.join(modules_order)}[/yellow]")

    elif args.skip:
        actual_skipped_modules = []
        invalid_skipped_modules = []
        for m_skip in args.skip:
            if m_skip in AVAILABLE_MODULE_CHOICES:
                actual_skipped_modules.append(m_skip)
            else:
                invalid_skipped_modules.append(m_skip)

        if invalid_skipped_modules:
            console.print(f"[red]Invalid modules in --skip: {', '.join(invalid_skipped_modules)}[/red]")
        
        modules_order = [m for m in DEFAULT_MODULES_ORDER if m not in actual_skipped_modules]
        if actual_skipped_modules:
            console.print(f"[yellow]Skipping modules: {', '.join(actual_skipped_modules)}[/yellow]")

        if not modules_order:
            console.print("[red]No modules to run after skipping.[/red]")
            exit(1)
        console.print(f"[yellow]Running modules: {', '.join(modules_order)}[/yellow]")
    else:
        modules_order = DEFAULT_MODULES_ORDER

    try:
        orchestrator = Orchestrator(
            target=args.target,
            base_output_dir_name=args.output,
            resume_path=args.resume
        )
        
        orchestrator.run_pipeline(
            modules_order=modules_order,
            focus_domain=args.focus_domain,
            focus_path=args.focus_path,
            verbose=args.verbose
        )
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()