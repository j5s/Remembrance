from collections import defaultdict
from ctypes import FormatError
from ctypes.wintypes import ULONG

from .native import Kernel32
from .native.ntstatus import NTSTATUS_CODES


class NativeException(Exception):
    ...


class WinAPIException(NativeException, OSError):
    def __init__(self, code: int = Kernel32.GetLastError(), message: str = None):
        if not message:
            message = FormatError(code).strip()

        super().__init__(None, message, None, code)


class NTStatusException(NativeException):
    STATUS_CODES = defaultdict(list)

    def __init__(self, code: int, message: str = None):
        code = ULONG(code).value

        if not message:
            message = f"{self.STATUS_CODES[code][0]}."

        super().__init__(f"[NTSTATUS {code:#x}] {message}")

    @classmethod
    def register_code(cls, code: int, name: str, description: str):
        cls.STATUS_CODES[code].append(description)


# Register NTSTATUS codes
for parameters in NTSTATUS_CODES:
    NTStatusException.register_code(*parameters)


class ProcessException(Exception):
    ...


class ProcessHandleException(ProcessException):
    ...


class ProcessNotFoundException(ProcessException):
    ...


class ModuleNotFoundException(ProcessException):
    ...


class ThreadException(Exception):
    ...


class ThreadHandleException(ThreadException):
    ...


class ThreadNotFoundException(ThreadException):
    ...
