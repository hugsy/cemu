import os
import configparser

from typing import Any


import cemu.const



class Settings:


    def __init__(self, *args, **kwargs):
        self.__config_filename = cemu.const.CONFIG_FILEPATH

        if not os.access(self.__config_filename, os.R_OK):
            self.__create_default_config_file()

        self.__config = configparser.ConfigParser()
        self.__config.read(self.__config_filename)
        return


    def set(self, section, key, value) -> None:
        """
        Store a setting
        """
        if not self.__config.has_section(section):
            self.__config.add_section(section)

        self.__config.set(section, key, value)
        return


    def get(self, section, key, default=None) -> Any:
        """
        Retrieve a setting
        """
        return self.__config.get(section, key, fallback=default)


    def getint(self, section, key, default=0) -> int:
        """
        Retrieve an integer setting
        """
        return self.__config.getint(section, key, fallback=default)


    def getboolean(self, section, key, default=False) -> bool:
        """
        Retrieve a boolean setting
        """
        return self.__config.getboolean(section, key, fallback=default)


    def save(self) -> None:
        """
        Save the settings to disk
        """
        self.__config.write(self.__config_filename)
        return


    def __create_default_config_file(self) -> None:
        """
        Deploy a new config file as ~/.cemu.ini
        """
        with open(self.__config_filename, 'w') as configfile:
            configfile.write(open(cemu.const.TEMPLATE_CONFIG, "r").read())
        return

