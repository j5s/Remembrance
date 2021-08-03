import ctypes
import functools
from ctypes.wintypes import ULONG
from typing import Callable

from remembrance.exception import NTStatusException, ThreadHandleException, WinAPIException
from remembrance.native import Kernel32, NTDLL
from remembrance.native.enum import ThreadAccessRights
from remembrance.native.structure import THREAD_BASIC_INFORMATION
from remembrance.native.wrapped import Handle


def _ensure_handle_status(ensure_open: bool):
    def decorator(function: Callable):
        @functools.wraps(function)
        def wrapper(cls: "Thread", *args, **kwargs):
            if cls.__getattribute__('_Thread__handle').open ^ ensure_open:
                if ensure_open:
                    raise ThreadHandleException("The thread has not been opened yet.")
                else:
                    raise ThreadHandleException("The thread has already been opened.")

            return function(cls, *args, **kwargs)

        return wrapper

    return decorator


class Thread:
    __id: int
    __handle: Handle

    @property
    @_ensure_handle_status(ensure_open=True)
    def handle(self) -> Handle:
        """
        The thread handle.
        """
        return self.__handle

    @property
    def id(self) -> int:
        """
        The thread id.
        """
        return self.__id

    @property
    def base_address(self) -> int:
        """
        The thread base address.
        """
        return self.__query_basic_information().TebBaseAddress

    @property
    def priority(self) -> int:
        """
        The thread priority.
        """
        return self.__query_basic_information().Priority

    # noinspection PyTypeChecker
    def __init__(self, thread_id: int, handle: Handle = Handle(None)):
        self.__id = thread_id
        self.__handle = handle

    def __query_basic_information(self):
        thread_info = THREAD_BASIC_INFORMATION()
        _useless = ULONG()
        status = NTDLL.NtQueryInformationThread(self.handle.native, 0x0, ctypes.pointer(thread_info),
                                                ctypes.sizeof(thread_info), ctypes.pointer(_useless))
        if status != 0x0:
            raise NTStatusException(status)

        return thread_info

    @_ensure_handle_status(ensure_open=False)
    def open(self, access_rights: ThreadAccessRights):
        """
        Open the thread with the desired access rights.
        :param access_rights: the desired access rights
        """
        native_handle = Kernel32.OpenThread(access_rights, False, self.__id)
        if native_handle is None:
            raise WinAPIException

        self.__handle = Handle(native_handle)

    def close(self):
        """
        Close the previously opened thread.
        """
        self.handle.close()

    def terminate(self, exit_code: int):
        """
        Terminate the process.
        :param exit_code: the process exit code
        """
        if not Kernel32.TerminateThread(self.handle.native, exit_code):
            raise WinAPIException

    def suspend(self):
        """
        Suspend the thread.
        """
        if Kernel32.SuspendThread(self.handle.native) == -1:
            raise WinAPIException

    def resume(self):
        """
        Resume the thread.
        """
        if Kernel32.ResumeThread(self.handle.native) == -1:
            raise WinAPIException

    def __str__(self) -> str:
        return f"Thread(id={self.__id}, handle={self.__handle})"

    def __repr__(self) -> str:
        return self.__str__()
