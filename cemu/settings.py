import configparser
from typing import Any, Optional

import cemu.const

from cemu.log import dbg


class Settings:
    def __init__(self, *args, **kwargs):
        self.__config: Optional[configparser.ConfigParser] = None
        self.__config_filename = cemu.const.CONFIG_FILEPATH

        if not self.__config_filename.is_file():
            self.__create_default_config_file()
            dbg("Settings file created")

        self.load()
        return

    def set(self, section: str, key: str, value: Any) -> None:
        """
        Store a setting
        """
        assert self.__config
        if not self.__config.has_section(section):
            self.__config.add_section(section)

        self.__config.set(section, key, value)
        return

    def get(self, section: str, key: str, default=None) -> Any:
        """
        Retrieve a setting
        """
        assert self.__config
        return self.__config.get(section, key, fallback=default)

    def getint(self, section: str, key: str, default=0) -> int:
        """
        Retrieve an integer setting
        """
        assert self.__config
        return self.__config.getint(section, key, fallback=default)

    def getboolean(self, section: str, key: str, default=False) -> bool:
        """
        Retrieve a boolean setting
        """
        assert self.__config
        return self.__config.getboolean(section, key, fallback=default)

    def save(self) -> None:
        """
        Save the settings to disk
        """
        assert self.__config
        with open(self.__config_filename, "w") as fd:
            self.__config.write(fd)
        dbg(f"Settings saved to '{self.__config_filename}'")
        return

    def load(self) -> None:
        """
        Load the config
        """
        if self.__config is not None:
            del self.__config

        self.__config = configparser.ConfigParser()
        self.__config.read(self.__config_filename)
        dbg(f"Settings loaded from '{self.__config_filename}'")
        return

    def __create_default_config_file(self) -> None:
        """
        Deploy a new config file as ~/.cemu.ini
        """
        with self.__config_filename.open("w") as cfg:
            cfg.write(cemu.const.TEMPLATE_CONFIG.open().read())
        return

    def __contains__(self, key: str) -> bool:
        """
        Check if a config key exists
        """
        assert self.__config
        return key in self.__config
