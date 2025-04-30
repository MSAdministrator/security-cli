import os

from pathlib import Path, PurePath
from typing import Dict, List, Optional


import yaml

from attr import asdict, define, field
from cattrs import structure
from jinja2 import Environment, FileSystemLoader


@define
class Source:
    name: str = field()
    apikey: str = field(default="")
    template: str = field(default="")


@define
class Enrich:
    ipaddress: List[Source] = field(factory=list)
    domain: List[Source] = field(factory=list)
    url: List[Source] = field(factory=list)
    email: List[Source] = field(factory=list)


@define
class Actions:
    enrich: Enrich = field(default=Enrich)


@define
class Config:
    actions: Actions = field(default=Actions)


class ConfigManager:

    _config: Config = None
    _config_path: str = None
    _env_prefix: str = "ENRICHMENT_MCP"
    _jinja2_env: Environment

    def load(self, path: Optional[str] = "./config.yaml") -> Config:
        self._jinja2_env = Environment(
            loader=FileSystemLoader(
                self.get_abs_path("./src/security_cli/data/templates")
            )
        )
        self.load_from_file(path=path)
        self.load_from_env()
        self._load_templates()
        return self._config

    def get(self) -> Dict[str, str]:
        if not self._config:
            self.load()
        return asdict(self._config)

    def load_from_file(self, path: Optional[str] = ".") -> Config:
        if not self._config_path:
            self._config_path = path
            # we reset our config if a new path is loaded
            self._config = None
        if not self._config:
            self._config = structure(
                self.load_config_yaml(path=self._config_path), Config
            )
        return self._config

    def load_from_env(self) -> Config:
        if not self._config:
            self.load_from_file()
        for enrichment_type in ["ipaddress", "domain", "url", "email"]:
            if getattr(self._config.actions.enrich, enrichment_type):
                for source in getattr(self._config.actions.enrich, enrichment_type):
                    env = f"{self._env_prefix}_{source.name}_key".upper()
                    if os.environ.get(env):
                        source.apikey = os.environ.get(env)
        return self._config

    def _load_templates(self) -> None:
        for enrichment_type in ["ipaddress", "domain", "url", "email"]:
            if getattr(self._config.actions.enrich, enrichment_type):
                for source in getattr(self._config.actions.enrich, enrichment_type):
                    if self._jinja2_env.get_template(source.template):
                        source.template = self._jinja2_env.get_template(source.template)

    def find_config(self, path: str = ".", pattern="*.yaml") -> str:
        """Attempts to find the MCP server config containing settings and data sources.

        Args:
            path (str): A path to the config yaml file.
            pattern (str, optional): Pattern used to find yaml config files. Defaults to *.yaml.

        Returns:
            str: A full qualified path string
        """
        result = []
        path = PurePath(self.get_abs_path(path))
        for p in Path(path).rglob(pattern):
            result.append(p.resolve())
        return result[0] if len(result) > 0 else ""

    def get_abs_path(self, value) -> str:
        """Formats and returns the absolute path for a path value

        Args:
            value (str): A path string in many different accepted formats

        Returns:
            str: The absolute path of the provided string
        """
        return os.path.abspath(os.path.expanduser(os.path.expandvars(value)))

    def load_config_yaml(self, path: str) -> Dict:
        if not os.path.exists(self.get_abs_path(path)):
            path = self.find_config(path)
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f.read())
