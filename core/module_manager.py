# hunterNG/core/module_manager.py

import importlib
import pkgutil
import inspect
from pathlib import Path
from typing import Any, Optional, Type, Dict
from modules.base_module import BaseModule
from utils.cli_utils import console

class ModuleManager:
    def __init__(self, modules_package_name: str = "modules"):
        self.modules_package_name = modules_package_name
        self.available_modules: Dict[str, Type[BaseModule]] = {}
        self._load_modules()

    def _load_modules(self) -> None:
        try:
            package = importlib.import_module(self.modules_package_name)
        except ImportError as e:
            raise ImportError(f"Could not import package '{self.modules_package_name}': {e}")
        
        for _, sub_module_name, is_pkg in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
            if not is_pkg:
                continue
            
            try:
                module_file_name = f"{sub_module_name.split('.')[-1]}_module"
                actual_module_to_import = f"{sub_module_name}.{module_file_name}"

                try:
                    module_impl = importlib.import_module(actual_module_to_import)
                except ImportError:
                    continue

                for name, obj in inspect.getmembers(module_impl):
                    if inspect.isclass(obj) and issubclass(obj, BaseModule) and obj is not BaseModule:
                        module_key = name.replace("Module", "").lower()
                        if module_key:
                            self.available_modules[module_key] = obj
            except ImportError as e:
                pass
            except Exception as e:
                pass

    def get_module_instance(self, 
                            module_name: str, 
                            target: str, 
                            output_dir: Path, 
                            global_state: Dict[str, Any],
                            verbose: bool
                            ) -> Optional[BaseModule]:
        module_class = self.available_modules.get(module_name.lower())
        if module_class:
            try:
                return module_class(module_name = module_name.lower(), 
                                    target = target, 
                                    output_dir = output_dir, 
                                    global_state = global_state,
                                    verbose = verbose)
            except Exception as e:
                console.print(f"[red]Error initializing module '{module_name}': {e}[/red]")
                return None
        return None