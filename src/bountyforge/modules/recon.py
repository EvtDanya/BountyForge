import subprocess
import abc


class ReconAbstractModule(abc.ABC):
    """
    Abstract class for recon submodules
    """
    def __init__(self):
        pass


class ReconModule:
    def __init__(self, target: str):
        self.target = target

    def run_subprocess(self, cmd: list[str]) -> list[str]:
        """
        ["subfinder", "-d", self.target, "-silent"]
        Run specified command

        :param cmd: _description_
        :type cmd: list[str]
        :return: _description_
        :rtype: list[str]
        """
        result = subprocess.run(
            cmd, capture_output=True, text=True
        )
        return result.stdout.splitlines()

    def filter_subdomains(self, subdomains: list[str]) -> list[str]:
        """_summary_

        :param subdomains: _description_
        :type subdomains: list[str]
        :return: _description_
        :rtype: list[str]
        """
        live_subdomains = []
        return live_subdomains
