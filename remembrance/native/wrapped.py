from . import Kernel32
from ..exception import WinAPIException


class Handle:
    __handle: int

    @property
    def native(self) -> int:
        """
        Get the native handle value.
        """
        return self.__handle

    @property
    def open(self) -> bool:
        """
        If the handle is open.
        """
        return self.__handle is not None

    def __init__(self, native_handle: int):
        self.__handle = native_handle

    def close(self):
        """
        Close the handle.
        """
        if not Kernel32.CloseHandle(self.__handle):
            raise WinAPIException

        # noinspection PyTypeChecker
        self.__handle = None

    def __str__(self) -> str:
        handle = f"{self.__handle:#x}" if self.open else None
        return f"Handle(handle={handle}, open={self.open})"

    def __repr__(self) -> str:
        return self.__str__()
