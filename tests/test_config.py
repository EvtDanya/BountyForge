from dataclasses import asdict
from honeypot.config import Config


def test_config_load():
    conf_obj = Config.load()

    assert asdict(conf_obj) == {
        'logging': {
            'level': 20,
            'file_path': None,
            'syslog_enabled': False
        },
        'app': {
            'host': '127.0.0.1',
            'port': 8888
        }
    }
