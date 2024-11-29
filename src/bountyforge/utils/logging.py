import logging
import logging.handlers
import pathlib
import platform
import sys

from ..config import settings


def config_syslog(logger: logging.Logger):
    """
    Configure syslog logger handler

    :param logger: logger instance to configure
    :type logger: Logger
    """
    class HostnameFilter(logging.Filter):
        hostname = platform.node()

        def filter(self, record):
            record.hostname = HostnameFilter.hostname
            return True

    sh = logging.handlers.SysLogHandler(address='/dev/log')
    sh.addFilter(HostnameFilter())
    sh.setLevel(settings.logging.level)
    sf = logging.Formatter(
        ('%(asctime)s %(hostname)s %(name)s[%(process)d]: '
         '%(levelname)s: %(message)s')
    )
    sh.setFormatter(sf)
    logger.addHandler(sh)


def config_file_log(logger: logging.Logger) -> None:
    """
    Configure file logger handler

    :param logger: logger instance to configure
    :type logger: Logger
    """
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # File handler
    file_path = pathlib.Path(settings.logging.file_path)

    if not file_path.parent.is_dir:
        file_path.parent.mkdir()

    fh = logging.handlers.RotatingFileHandler(file_path, 'a', 2097152, 10)
    fh.setFormatter(formatter)
    fh.setLevel(settings.logging.level)
    logger.addHandler(fh)


def init_logging(logger: logging.Logger):
    """
    Initialize logging for the app

    :param logger: logger instance to configure
    :type logger: Logger
    """
    stdout_handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    stdout_handler.setFormatter(formatter)
    logger.addHandler(stdout_handler)

    if settings.logging.syslog_enabled:
        config_syslog(logger)

    if settings.logging.file_path is not None:
        config_file_log(logger)

    logger.setLevel(settings.logging.level)
