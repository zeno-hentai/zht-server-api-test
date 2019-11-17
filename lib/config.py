import os
from pathlib import Path

import yaml
from typing import NamedTuple

from typeguard import typechecked


@typechecked
class ZHTTestConfigFile(NamedTuple):
    baseUrl: str
    masterKey: str

    def url(self, path):
        return f"{self.baseUrl}{path}"


def get_env():
    return os.environ.get("ZHT_ENV") or "default"


def load_config(env):
    data = yaml.load(open(config_root / f'{env}.yaml'), Loader=yaml.Loader)
    return ZHTTestConfigFile(**data)


config_root = Path(os.path.dirname(__file__), '..', "config")
__all__ = ['zht_config', 'ZHTTestConfigFile']

zht_config = load_config(get_env())
