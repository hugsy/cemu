from dataclasses import dataclass
from typing import Union


@dataclass
class OperatingSystem:
    name: str

    def __str__(self):
        return self.name

    def __fspath__(self):
        return str(self).lower()

    def __eq__(self, __value: Union[str, "OperatingSystem"]) -> bool:
        if isinstance(__value, str):
            return str(self).lower() == __value.lower()

        if isinstance(__value, OperatingSystem):
            return self.name == __value.name

        raise ValueError


Linux = OperatingSystem("Linux")
Windows = OperatingSystem("Windows")
