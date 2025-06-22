# hunterNG/core/config_manager.py

from typing import Dict, Any
import yaml
from pathlib import Path

CONFIG_FILE = Path(__file__).parent.parent / "config" / "default_config.yaml"

class ConfigManager:
    _config: Dict[str, Any] = {}
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ConfigManager, cls).__new__(cls, *args, **kwargs)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self) -> None:
        if not CONFIG_FILE.exists():
            raise FileNotFoundError(f"Configuration file not found: {CONFIG_FILE}")
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as file:
                self._config = yaml.safe_load(file)
                if self._config is None:
                    self._config = {}
                    raise ValueError("Configuration file is empty or invalid.")

        except Exception as e:
            raise RuntimeError("Error loading configuration file") from e
        
    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split('.')
        value = self._config
        try:
            for k in keys:
                if isinstance(value, dict):
                    value = value[k]
                else:
                    return default
            return value
        except KeyError:
            return default
        
    def get_section(self, section: str) -> Dict[str, Any]:
        if section not in self._config:
            raise KeyError(f"Section '{section}' not found in configuration.")
        return self._config[section]

config = ConfigManager()