import logging
import os
from dataclasses import asdict, dataclass, field
from dataclasses import fields as dc_fields
from pathlib import Path
from typing import Self, Dict, Any

import yaml
from dotenv import load_dotenv

logger = logging.getLogger('bountyforge')


# @dataclass
# class BountyForge(object):
#     host: str = "0.0.0.0"
#     port: int = 5000
#     workers: int = 1
#     threads: int = 1
#     timeout: int = 120
#     project_version: str = "0.0.8"

#     def __post_init__(self):
#         if isinstance(self.port, str):
#             self.port = int(self.port)

#         if isinstance(self.workers, str):
#             self.workers = int(self.workers)

#         if isinstance(self.threads, str):
#             self.threads = int(self.threads)

#         if isinstance(self.timeout, str):
#             self.timeout = int(self.timeout)


@dataclass
class BaseApp(object):
    host: str = "127.0.0.1"
    port: int = 5000  # check for port conflict
    workers: int = 1
    session_secret_key: str = "default_secret_key"
    session_lifetime: int = 3  # in hours
    auth_user: str = "admin"
    auth_pass: str = "admin"  # H8Ny+t2F(7MB
    is_debug: bool = True

    def __post_init__(self):
        if isinstance(self.port, str):
            self.port = int(self.port)

        if isinstance(self.workers, str):
            self.workers = int(self.workers)

        if isinstance(self.session_lifetime, str):
            self.session_lifetime = int(self.session_lifetime)


@dataclass
class BackendBountyForge(BaseApp):
    celery_broker_url: str = "redis://redis:6379/0"
    mongo_url: str = "mongodb://mongo:27017"
    frontend_host: str = "localhost"
    threads: int = 1
    timeout: int = 120
    rate_limit: int = "20"
    project_version: str = "0.0.9"

    def __post_init__(self):
        super().__post_init__()

        if isinstance(self.port, str):
            self.port = int(self.port)

        if isinstance(self.workers, str):
            self.workers = int(self.workers)

        if isinstance(self.threads, str):
            self.threads = int(self.threads)

        if isinstance(self.timeout, str):
            self.timeout = int(self.timeout)

        if isinstance(self.rate_limit, str):
            self.rate_limit = int(self.rate_limit)


@dataclass
class FrontendBountyForge(BaseApp):
    session_secret: str = "default_secret_key"
    port: int = 8080
    backend_host: str = "localhost"

    def __post_init__(self):
        super().__post_init__()


@dataclass
class ScannerSettings(object):
    """
    Configuration for scanner modules.

    This includes settings for individual scanning modules.
    """
    nmap: Dict[str, Any] = field(default_factory=lambda: {
        "scan_type": "default",  # Options: "default", "aggressive", "full"
        "additional_flags": []
    })
    subfinder: Dict[str, Any] = field(default_factory=lambda: {
        "additional_flags": []
    })
    subdomain_bruteforce: Dict[str, Any] = field(default_factory=lambda: {
        "wordlist": "subdomains-small.txt",
        "additional_flags": []
    })
    httpx: Dict[str, Any] = field(default_factory=lambda: {
        "mode": "recon",   # Options: "recon", "live"
        "additional_flags": []
    })

    nuclei: Dict[str, Any] = field(default_factory=lambda: {
        "mode": "full",   # Options: "full", "fast"
        "additional_flags": []
    })

    def __post_init__(self):
        pass


@dataclass
class LoggingConfig(object):
    level: int = logging.INFO
    file_path: str | None = None
    syslog_enabled: bool = False

    def __post_init__(self):
        log_levels = logging.getLevelNamesMapping()

        if isinstance(self.level, int):
            if self.level not in [val for key, val in log_levels.items()]:
                self.level = logging.INFO

        if isinstance(self.level, str):
            self.level = log_levels.get(self.level, logging.INFO)


@dataclass
class Config(object):
    """
    Generalized Config class
    """
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    backend: BackendBountyForge = field(default_factory=BackendBountyForge)
    frontend: FrontendBountyForge = field(default_factory=FrontendBountyForge)
    # app: BountyForge = field(default_factory=BountyForge)
    scanners: ScannerSettings = field(default_factory=ScannerSettings)

    def __post_init__(self):
        attrs = [(field.name, field.type) for field in dc_fields(self)]
        for attr_name, attr_type in attrs:
            if isinstance(getattr(self, attr_name), dict):
                setattr(self, attr_name, attr_type(**getattr(self, attr_name)))

    @classmethod
    def load(cls, cfg_path: str | os.PathLike | None = "config.yaml") -> Self:
        """
        Load config from config file
            or from environment variables
        """
        if cfg_path and Path(cfg_path).exists():
            return cls._load_config_file(cfg_path)
        else:
            return cls._load_env_configs()

    @classmethod
    def _load_config_file(cls, cfg_path: str | os.PathLike) -> Self:
        """
        Loads config from yaml file
        """
        config = {}
        with open(cfg_path) as path:
            yaml_conf = path.read()
            config = yaml.safe_load(yaml_conf)
        return cls(**config)

    @classmethod
    def _load_env_configs(cls) -> Self:
        """
        Loads config from environment variables
            sets default values if any var found
        """
        if Path(".env").exists:
            load_dotenv()

        env_items = dict(os.environ.items())

        config = asdict(cls())
        cfg_fields = [x.name for x in dc_fields(cls)]
        env_vars = filter(
            lambda x: x.split("__")[0].lower() in cfg_fields,
            env_items.keys()
        )
        for env_var in env_vars:
            vars = env_var.lower().split("__")
            cfg_instance = config
            while vars:
                var = vars.pop(0)
                if var in cfg_instance:
                    if isinstance(cfg_instance[var], dict):
                        cfg_instance = cfg_instance[var]
                    else:
                        cfg_instance[var] = env_items[env_var]
        return cls(**config)

    def save(self, cfg_path: str | os.PathLike | None = "config.yaml") -> None:
        """
        Save config to yaml file
        """
        with open(cfg_path, "w", encoding="utf-8") as path:
            yaml.dump(
                asdict(self),
                path,
                default_flow_style=False,
                allow_unicode=True
            )


# Cached if imported
settings = Config.load()
