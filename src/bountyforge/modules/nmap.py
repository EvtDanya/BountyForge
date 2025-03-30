import subprocess
import logging
from typing import Dict, Any

from bountyforge.core.module_base import Module

logger = logging.getLogger(__name__)


class NmapModule(Module):
    """
    Module for running an Nmap scan.

    Configuration:
        scan_type: Type of scanning (e.g., 'aggressive' or 'default')
    """

    def __init__(self, scan_type: str = "default"):
        self.scan_type = scan_type

    def execute(self, target: str) -> Dict[str, Any]:
        """
        Execute the Nmap scan for the given target.

        :param target: The target address or domain.
        :return: A dictionary containing the scan output.
        """
        logger.info(f"Running Nmap (type: {self.scan_type}) for target: {target}")
        try:
            # Example call to nmap; parameters may be adjusted based on scan_type.
            command = ["nmap", "-Pn", target]
            if self.scan_type == "aggressive":
                command.append("-A")
            process = subprocess.run(command, capture_output=True, text=True, check=True)
            result = {"output": process.stdout}
            logger.info("Nmap scan completed successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing Nmap: {e}")
            result = {"error": str(e)}
        return result
