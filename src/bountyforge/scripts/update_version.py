'''
update_version.py

Updates app version according version in toml file
'''


import toml
import re
import os

current_script_path = os.path.abspath(__file__)

if __name__ == "__main__":

    with open('pyproject.toml') as f:
        config = toml.load(f)

    config_path = f"{current_script_path}/../config.py"
    with open(config_path) as f:
        content = f.read()

    updated_content = re.sub(
        r'project_version:\sstr\s=\s.+',
        f'project_version: str = "{config["tool"]["poetry"]["version"]}"',
        content
    )

    with open(config_path, 'w') as f:
        f.write(updated_content)

    print(config["tool"]["poetry"]["version"])
