# # import datetime, json, logging
# import logging
# from typing import List, Dict, Any
# from pymongo import MongoClient
# # import redis

# from bountyforge.core.module_manager import module_manager
# from bountyforge.core.module_base import TargetType, ScanType
# from bountyforge.config import settings

# logger = logging.getLogger(__name__)


# class ScanPipeline:
#     def __init__(
#         self,
#         job_id: str,
#         initial_targets: List[str],
#         exclude: List[str],
#         requested_tools: List[str],
#         publish_fn,
#         save_result_fn
#     ):
#         self.job_id = job_id
#         self.targets = initial_targets
#         self.exclude = exclude
#         self.requested = set(requested_tools)
#         self.publish = publish_fn
#         self.save = save_result_fn

#     def run(self) -> int:
#         total_parsed = 0

#         # 1) Поддомены
#         if "subfinder" in self.requested:
#             self.targets = self._run_module("subfinder", self.targets)
#         if "subdomain_bruteforce" in self.requested:
#             self.targets = self._run_module(
#                 "subdomain_bruteforce",
#                 self.targets
#             )

#         # 2) Фильтрация живых хостов
#         if "httpx" in self.requested:
#             # временно установим режим live
#             live = self._run_module(
#                 "httpx",
#                 self.targets,
#                 extra={"mode": "live"}
#             )
#             self.targets = [
#                 r["url"] for r in live
#                 if r.get("status") and r["status"] < 400
#             ]

#         # 3) Nmap: собираем открытые порты
#         if "nmap" in self.requested:
#             nmap_parsed = self._run_module("nmap", self.targets)
#             # превращаем в список host:port
#             port_targets = []
#             for entry in nmap_parsed:
#                 host = entry.get("host") \
#                     or entry.get("ip") \
#                     or entry.get("target")
#                 port = entry["port"]
#                 port_targets.append(f"{host}:{port.split('/')[0]}")
#             self.targets = port_targets

#         # 4) HTTPX recon по host:port → получаем URL
#         if "httpx" in self.requested:
#             recon = self._run_module(
#                 "httpx",
#                 self.targets,
#                 extra={"mode": "recon"}
#             )
#             self.targets = [
#                 r["url"] for r in recon
#                 if r.get("status") and r["status"] < 400
#             ]

#         # 5) Ffuf
#         if "ffuf" in self.requested:
#             paths = self._run_module("ffuf", self.targets)
#             total_parsed += len(paths)

#         # 6) Nuclei
#         if "nuclei" in self.requested:
#             total_parsed += len(self._run_module("nuclei", self.targets))

#         return total_parsed

#     def _run_module(
#         self, tool: str, targets: List[str],
#         extra: Dict[str, Any] = None
#     ) -> List[Dict[str, Any]]:
#         """
#         Запускает единичное модульное сканирование:
#         - инициализирует класс из module_manager
#         - запускает .run()
#         - публикует raw и parsed
#         - сохраняет в Mongo
#         - возвращает parsed (list of dict)
#         """
#         ModuleClass = module_manager.get_module(tool)
#         if not ModuleClass:
#             logger.warning(f"No module '{tool}'")
#             return []

#         # Собираем kwargs из настроек
#         cfg = getattr(settings.scanners, tool, {})
#         scan_type = ScanType((extra or cfg).get(
#             "mode",
#             cfg.get("mode", "default")
#         ))
#         flags = (extra or cfg).get(
#             "additional_flags",
#             cfg.get("additional_flags", [])
#         )
#         wordlist = (extra or cfg).get(
#             "wordlist",
#             cfg.get("wordlist", None)
#         )
#         templates = (extra or cfg).get(
#             "templates_dir",
#             cfg.get("templates_dir", None)
#         )

#         init_kwargs = {
#             "target":        targets,
#             "target_type":   TargetType.MULTIPLE,
#             "scan_type":     scan_type,
#             "additional_flags": flags,
#             "exclude":       self.exclude
#         }
#         if tool == "ffuf" and wordlist:
#             init_kwargs["wordlist"] = wordlist
#         if tool == "nuclei" and templates:
#             init_kwargs["templates_dir"] = templates

#         mod = ModuleClass(**init_kwargs)
#         logger.info(f"[Pipeline:{tool}] Running on {len(targets)} targets")

#         res = mod.run()
#         raw = res.get("result", [])
#         parsed = res.get("parsed", [])

#         # Publish to SSE
#         self.publish(tool, raw, parsed)

#         # Save to Mongo
#         self.save(tool, raw, parsed, self.job_id)

#         return parsed
