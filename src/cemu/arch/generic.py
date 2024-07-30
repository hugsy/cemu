from cemu.arch import Architecture


class Generic(Architecture):
    pc = "PC"
    sp = "SP"
    flag = ""
    registers = []

    def __init__(self, *args, **kwargs):
        return

    @property
    def ptrsize(self):
        return 4

    @property
    def syscall_filename(self):
        raise ValueError("This architecture cannot be used")

    @property
    def name(self):
        return "Generic Architecture"
