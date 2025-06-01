import datetime
import logging
import json
from typing import Any, Dict, List

from celery import Celery
from pymongo import MongoClient
import redis

from bountyforge.config import settings
from bountyforge.core import module_manager
from bountyforge.core.module_base import ScanType, TargetType

logger = logging.getLogger(__name__)

celery = Celery(
    "bountyforge",
    broker=settings.backend.celery_broker_url,
)

mongo = MongoClient(settings.backend.mongo_url)
db = mongo.get_default_database()

redis_client = redis.Redis.from_url(settings.backend.celery_broker_url)


def merge_tool_opts(tool: str, options: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get settings for a specific tool by merging
        from default and run-specific configurations
    """
    default_cfg = getattr(settings.scanners, tool, {}) or {}
    run_cfg = options.get(tool, {}) or {}
    cfg: Dict[str, Any] = {}

    flags = run_cfg.get("additional_flags")
    if flags is None:
        flags = default_cfg.get("additional_flags")
    cfg["additional_flags"] = flags

    # tool-specific options
    if tool == "ffuf" or tool.startswith("ffuf_"):
        cfg["dns_wordlist"] = run_cfg.get("dns_wordlist")\
            or default_cfg.get("dns_wordlist")
        cfg["directories_wordlist"] = run_cfg.get("directories_wordlist")\
            or default_cfg.get("directories_wordlist")
    if tool == "nmap":
        mode = run_cfg.get("mode") or default_cfg.get("mode")
        cfg["mode"] = mode
    if tool == "httpx":
        mode = run_cfg.get("mode") or default_cfg.get("mode")
        exclude = run_cfg.get("exclude") or default_cfg.get("exclude")
        cfg["mode"] = mode
        cfg["exclude"] = exclude
    if tool == "nuclei":
        mode = run_cfg.get("mode") or default_cfg.get("mode")
        templates = run_cfg.get("templates_dir")\
            or default_cfg.get("templates_dir")
        cfg["mode"] = mode
        cfg["templates_dir"] = templates

    return cfg


class ScanPipeline:
    """
    ScanPipeline orchestrates a series of scanning tools
    """
    ORDER = [
        "subfinder",
        "ffuf_subdomainbruteforce",
        "nmap",
        "httpx",
        "ffuf_directorybruteforce",
        "nuclei"
    ]

    def __init__(
        self,
        targets: List[str],
        tools: List[str],
        options: Dict[str, Any],
        channel: str = None,
        rate_limit: int = 20,
        timeout: int = 10,
    ):
        self.initial_targets = targets
        self.targets = targets
        self.tools = set(tools)
        self.options = options
        self.results: Dict[str, Any] = {}
        self.channel = channel
        self.rate_limit = rate_limit
        self.timeout = timeout

    def run(self) -> Dict[str, Any]:
        if "subfinder" in self.tools:
            logger.info("[1] subfinder")
            cfg = merge_tool_opts("subfinder", self.options)
            mod = module_manager.get_module("subfinder")(
                target=self.targets,
                target_type=TargetType.MULTIPLE,
                scan_type=cfg.get("mode"),
                additional_flags=cfg.get("additional_flags"),
                rate_limit=self.rate_limit
            )
            res = mod.run()
            self.results["subfinder"] = res
            hosts = [r["host"] for r in res.get("parsed", [])]
            self.targets = list(set(self.targets + hosts))
            redis_client.publish(
                self.channel,
                json.dumps(res.get("result", []))
            )
            logger.info(f"raw results: {res}")

        if "ffuf_subdomainbruteforce" in self.tools:
            logger.info("[2] ffuf_subdomainbruteforce")
            cfg = merge_tool_opts("ffuf", self.options)
            mod = module_manager.get_module("ffuf")(
                target=self.targets,
                target_type=TargetType.MULTIPLE,
                scan_type=ScanType.SUBDOMAIN,
                wordlist="/app/wordlists/"+cfg.get("dns_wordlist"),
                additional_flags=cfg.get("additional_flags"),
                rate_limit=self.rate_limit
            )
            res = mod.run()
            self.results["ffuf_subdomainbruteforce"] = res
            hosts = [r["host"] for r in res.get("parsed", [])]
            self.targets = list(set(self.targets + hosts))
            redis_client.publish(
                self.channel,
                json.dumps(res.get("result", []))
            )
            logger.info(f"raw results: {res}")

        if "nmap" in self.tools:
            logger.info("[3] nmap")
            cfg = merge_tool_opts("nmap", self.options)
            mod = module_manager.get_module("nmap")(
                target=self.targets,
                target_type=TargetType.MULTIPLE,
                scan_type=ScanType(cfg.get("mode")),
                additional_flags=cfg.get("additional_flags"),
                rate_limit=self.rate_limit
            )
            res = mod.run()
            self.results["nmap"] = res
            ports: List[str] = []
            for entry in res.get("parsed", []):
                h = entry.get("host") or entry.get("ip")
                port_num = entry.get("port", "").split('/')[0]
                ports.append(f"{h}:{port_num}")
            self.targets = ports
            redis_client.publish(
                self.channel,
                json.dumps(res.get("result", []))
            )
            logger.info(f"raw results: {res}")

        if "httpx" in self.tools:
            logger.info("[4] httpx")
            cfg = merge_tool_opts("httpx", self.options)
            mod = module_manager.get_module("httpx")(
                target=self.targets,
                target_type=TargetType.MULTIPLE,
                scan_type=ScanType(cfg.get("mode")),
                additional_flags=cfg.get("additional_flags"),
                exclude=cfg.get("exclude") or [],
                rate_limit=self.rate_limit
            )
            res = mod.run()
            self.results["httpx"] = res
            urls = [
                r["url"] for r in res.get("parsed", [])
                if r.get("status", 0) < 400
            ]
            self.targets = urls
            redis_client.publish(
                self.channel,
                json.dumps(res.get("result", []))
            )
            logger.info(f"raw results: {res}")

        if "ffuf_directorybruteforce" in self.tools:
            logger.info("[5] ffuf_directorybruteforce")
            cfg = merge_tool_opts("ffuf", self.options)
            mod = module_manager.get_module("ffuf")(
                target=self.targets,
                target_type=TargetType.MULTIPLE,
                scan_type=ScanType.DEFAULT,
                wordlist="/app/wordlists/"+cfg.get("directories_wordlist"),
                additional_flags=cfg.get("additional_flags"),
                rate_limit=self.rate_limit
            )
            res = mod.run()
            self.results["ffuf_directorybruteforce"] = res
            self.targets += [r.get("url") for r in res.get("parsed", [])]
            redis_client.publish(
                self.channel, json.dumps(res.get("result", []))
            )
            logger.info(f"raw results: {res}")
            logger.info(
                f"Targets after ffuf_directorybruteforce: {self.targets}"
            )

        if "nuclei" in self.tools:
            logger.info("[6] nuclei")
            cfg = merge_tool_opts("nuclei", self.options)
            self.targets += [
                    "http://192.168.2.130"
            ]
            mod = module_manager.get_module("nuclei")(
                target=self.targets,
                target_type=TargetType.MULTIPLE,
                scan_type=ScanType(cfg.get("mode")),
                templates_dir=cfg.get("templates_dir"),
                additional_flags=cfg.get("additional_flags"),
                rate_limit=self.rate_limit
            )
            res = mod.run()
            self.results["nuclei"] = res
            redis_client.publish(
                self.channel,
                json.dumps(res.get("result", []))
            )
            logger.info(f"raw results: {res}")

        return self.results


@celery.task(bind=True)
def run_scan_task(self, request: Dict[str, Any], settings_curr):
    """
    Run a scan task in background using Celery
    """
    targets = request.get("target", [])
    tools = request.get("tools", [])

    logger.info(f"Starting scan task {self.request.id} for targets: {targets}")
    logger.debug(f"Run options: {settings_curr}")

    channel = f"scan:{self.request.id}"
    db.scan_jobs.update_one(
        {"job_id": self.request.id},
        {"$set": {"status": "running"}}
    )
    redis_client.publish(
        channel,
        json.dumps(
            {
                "event": "started",
                "job_id": self.request.id
            }
        )
    )

    backend = settings_curr.get("backend", {})
    pipeline = ScanPipeline(
        targets, tools, settings_curr.get("scanners", []),
        channel, backend.get("rate_limit", 20), backend.get("timeout", 10)
    )
    try:
        results = pipeline.run()
        status = "finished"
    except Exception as e:
        logger.exception(f"Pipeline failed: {e}")
        results = {"error": str(e)}
        status = "error" if settings.backend.abort_on_error\
            else "finished_with_errors"

    record = {
        "job_id": self.request.id,
        "timestamp": datetime.datetime.now(),
        "results": results,
        "status": status
    }
    db.scan_results.insert_one(record)
    db.scan_jobs.update_one(
        {
            "job_id": self.request.id
        },
        {
            "$set": {
                "status": status
            }
        }
    )
    redis_client.publish(
        channel,
        json.dumps(
            {
                "event": status,
                "job_id": self.request.id
            }
        )
    )

    return {
        "job_id": self.request.id,
        "status": status,
        "results_count": len(results)
    }
