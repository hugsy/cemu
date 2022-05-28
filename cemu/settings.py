import configparser
from typing import Any

import cemu.const


class Settings:

    def __init__(self, *args, **kwargs):
        self.__config_filename = cemu.const.CONFIG_FILEPATH

        if not self.__config_filename.is_file():
            self.__create_default_config_file()

        self.__config = configparser.ConfigParser()
        self.__config.read(self.__config_filename)
        return

    def set(self, section: str, key: str, value: Any) -> None:
        """
        Store a setting
        """
        if not self.__config.has_section(section):
            self.__config.add_section(section)

        self.__config.set(section, key, value)
        return

    def get(self, section: str, key: str, default=None) -> Any:
        """
        Retrieve a setting
        """
        return self.__config.get(section, key, fallback=default)

    def getint(self, section: str, key: str, default=0) -> int:
        """
        Retrieve an integer setting
        """
        return self.__config.getint(section, key, fallback=default)

    def getboolean(self, section: str, key: str, default=False) -> bool:
        """
        Retrieve a boolean setting
        """
        return self.__config.getboolean(section, key, fallback=default)

    def save(self) -> None:
        """
        Save the settings to disk
        """
        with open(self.__config_filename, "w") as fd:
            self.__config.write(fd)
        return

    def __create_default_config_file(self) -> None:
        """
        Deploy a new config file as ~/.cemu.ini
        """
        with self.__config_filename.open('w') as cfg:
            cfg.write(cemu.const.TEMPLATE_CONFIG.open().read())
        return

    def __contains__(self, key: str) -> bool:
        """
        Check if a config key exists
        """
        return key in self.__config
