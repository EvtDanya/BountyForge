from typing import Any, Dict, List, Union
from bountyforge.core import Module, ScanType, TargetType
import os
import re


class NucleiModule(Module):
    """
    Nuclei scanner module.
    Uses `nuclei` CLI to scan targets with given templates.
    """
    templates_dir: str = "./nuclei-templates"

    def __init__(
        self,
        target: Union[str, List[str]],
        target_type: TargetType = TargetType.SINGLE,
        templates_dir: str = "",
        scan_type: ScanType = ScanType.DEFAULT,
        additional_flags: List[str] = None
    ) -> None:
        """
        :param target: Single target string or list of targets.
        :param target_type: SINGLE / MULTIPLE / FILE.
        :param templates_dir: Path to nuclei templates directory.
        :param scan_type: One of ScanType.
        :param additional_flags: Extra CLI flags.
        """
        super().__init__(
            scan_type=scan_type,
            target=target,
            target_type=target_type,
            additional_flags=additional_flags
        )
        self.templates_dir = templates_dir
        self.binary_name = "nuclei"

    def _build_command(self, target_str: str) -> List[str]:
        """
        Construct the nuclei command based on target and configuration.
        """
        cmd = super()._build_base_command()

        if self.target_type == TargetType.SINGLE:
            cmd += ["-u", target_str]
        else:
            cmd += ["-l", target_str]

        if self.templates_dir:
            cmd += ["-t", self.templates_dir]

        match self.scan_type:
            case ScanType.AGGRESSIVE:
                # increase rate-limit for aggressive mode
                cmd += ["-rate-limit", "200"]
            case ScanType.FULL:
                # run all templates
                cmd += ["-all"]
            case ScanType.RECON:
                # recon mode: output extra metadata
                cmd += ["-json"]
            case _:
                pass

        if self.additional_flags:
            cmd += self.additional_flags

        return cmd

    def _post_run(
        self, target_str: str,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Parse nuclei JSON output (if any) or return raw output.
        """
        output = result.get("output", "")
        # if JSON mode, try to parse each line as JSON
        if self.scan_type == ScanType.RECON and output:
            try:
                import json
                parsed = [
                    json.loads(line) for line
                    in output.splitlines()
                    if line.strip()
                ]
                return {"results": parsed}
            except Exception:
                # fallback to raw
                return {"output": output}
        return result

    @staticmethod
    def _parse_version(output: str) -> str:
        # nuclei -version output: "Current Version: 2.8.3"
        match = re.search(r'Current Version: (\d+\.\d+\.\d+)', output)
        return match.group(1) if match else "unknown"

    @classmethod
    def check_availability(cls) -> bool:
        """
        Check if nuclei is installed and available in PATH
        Returns True if nuclei --version executes successfully
        :return: _description_
        :rtype: bool
        """
        version = cls.get_version()
        return {
            "available": version is not None,
            "version": version
        }

    def _validate_templates(self):
        """
        Validate PATH for templates
        """
        if not os.Path(self.template_dir).exists():
            raise Exception("Invalid template directory")

    def update_templates(self) -> None:
        """
        Update the nuclei templates to the latest version.
        """
        if not os.path.exists(self.templates_dir):
            os.makedirs(self.templates_dir)

        cmd = ["nuclei", "-update-templates"]
        self._execute_command(cmd, cwd=self.templates_dir)

    def update_nuclei(self) -> None:
        """
        Update the nuclei binary to the latest version.
        """
        cmd = ["nuclei", "-update"]
        self._execute_command(cmd)
