
import abc
import enum

# from cemu.arch.arm import AARCH64, ARM
# from cemu.arch.mips import MIPS, MIPS64
# from cemu.arch.ppc import PowerPC
# from cemu.arch.sparc import SPARC, SPARC64
# from cemu.arch.x86 import X86, X86_32, X86_64
from cemu.const import SYSCALLS_PATH


class Endianness(enum.Enum):
    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __int__(self) -> int:
        return self.value


class Syntax(enum.Enum):
    INTEL = 1
    ATT = 2

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __int__(self) -> int:
        return self.value


class Architecture(object):
    """Generic metaclass for the architectures."""
    __metaclass__ = abc.ABCMeta

    endianness = Endianness.LITTLE_ENDIAN
    syntax = Syntax.INTEL
    __syscalls = None

    @abc.abstractproperty
    def name(self):
        pass

    @abc.abstractproperty
    def registers(self):
        pass

    @abc.abstractproperty
    def instruction_length(self):
        pass

    @abc.abstractproperty
    def flag(self):
        pass

    @abc.abstractproperty
    def pc(self):
        pass

    @abc.abstractproperty
    def sp(self):
        pass

    @abc.abstractproperty
    def ptrsize(self):
        pass

    @abc.abstractproperty
    def regsize(self):
        pass

    @abc.abstractproperty
    def syscall_filename(self) -> str:
        pass

    def __str__(self):
        return f"{self.name} (Ptrsize={self.ptrsize}, Endian={self.endianness}, Syntax={self.syntax})"

    syscall_base = 0

    @property
    def syscalls(self):
        if not self.__syscalls:
            fpath = SYSCALLS_PATH / self.syscall_filename
            self.__syscalls = {}

            with fpath.open('r') as fd:
                for row in fd.readlines():
                    row = [x.strip() for x in row.strip().split(',')]
                    syscall_number = int(row[0])
                    syscall_name = row[1].lower()
                    self.__syscalls[syscall_name] = self.syscall_base + \
                        syscall_number

        return self.__syscalls

    def __eq__(self, x):
        if not isinstance(x, Architecture):
            return False
        return self.name == x.name and self.endianness == x.endianness and self.syntax == x.syntax


Architectures: dict[str, list[Architecture]] = {}


def load_architectures() -> None:
    """Instanciate all the architecture objects
    """
    global Architectures

    if len(Architectures) > 0:
        return

    Architectures["x86"] = [x86.X86(), x86.X86_32(), x86.X86_64(), x86.X86(
        syntax=Syntax.ATT), x86.X86_32(syntax=Syntax.ATT), x86.X86_64(syntax=Syntax.ATT)]
    Architectures["arm"] = [arm.ARM(), arm.ARM(thumb=True), arm.AARCH64()]
    Architectures["mips"] = [mips.MIPS(), mips.MIPS(endian=Endianness.BIG_ENDIAN),
                             mips.MIPS64(), mips.MIPS64(endian=Endianness.BIG_ENDIAN)]
    Architectures["sparc"] = [sparc.SPARC(), sparc.SPARC64()]
    return


def is_x86_16(a: Architecture):
    return a.name == "Intel 8086 16bit"


def is_x86_32(a: Architecture):
    return a.name == "Intel i386 32bit"


def is_x86_64(a: Architecture):
    return a.name == "Intel i386 64bit"


def is_x86(a: Architecture):
    return is_x86_16(a) or is_x86_32(a) or is_x86_64(a)


def is_arm(a: Architecture):
    return a.name in ("ARM THUMB mode", "ARM Native mode")


def is_arm_thumb(a: Architecture):
    return a.name == "ARM THUMB mode"


def is_aarch64(a: Architecture):
    return a.name == "ARM AARCH64"


def is_mips(a: Architecture):
    return a.name == "MIPS 32bits"


def is_mips64(a: Architecture):
    return a.name == "MIPS 64bits"


def is_sparc(a: Architecture):
    return a.name == "SPARC 32bits"


def is_sparc64(a: Architecture):
    return a.name == "SPARC 64bits"


def is_ppc(a: Architecture):
    return a.name == "PowerPC 32bits"


def get_all_architecture_names():
    archs = []
    for abi in Architectures:
        for arch in Architectures[abi]:
            archs.append(arch.__class__.__name__.lower())
    return archs


def get_architecture_by_name(name):
    for abi in Architectures:
        for arch in Architectures[abi]:
            if arch.__class__.__name__.lower() == name.lower():
                return arch
    raise KeyError("Cannot find architecture '{}'".format(name))
