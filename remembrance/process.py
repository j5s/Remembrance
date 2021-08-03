import ctypes
import functools
from ctypes.wintypes import DWORD, MAX_PATH
from typing import Callable, List, Tuple

from .exception import ModuleNotFoundException, NTStatusException, ProcessHandleException, ProcessNotFoundException, \
    ThreadNotFoundException, WinAPIException
from .native import Kernel32, NTDLL, PSAPI
from .native.constant import INVALID_HANDLE_VALUE
from .native.enum import ProcessAccessRights, SnapshotFlags, ThreadCreationFlags
from .native.structure import MODULEENTRY32A, PROCESSENTRY32A, THREADENTRY32
from .native.wrapped import Handle
from .thread import Thread


def _ensure_handle_status(ensure_open: bool):
    def decorator(function: Callable):
        @functools.wraps(function)
        def wrapper(cls: "Process", *args, **kwargs):
            if cls.__getattribute__('_Process__handle').open ^ ensure_open:
                if ensure_open:
                    raise ProcessHandleException("The process has not been opened yet.")
                else:
                    raise ProcessHandleException("The process has already been opened.")

            return function(cls, *args, **kwargs)

        return wrapper

    return decorator


class Module:
    __parent: "Process"
    __base_address: int
    __size: int
    __name: str

    @property
    def parent(self) -> "Process":
        """
        The module parent process object.
        """
        return self.__parent

    @property
    def base_address(self) -> int:
        """
        The module base address.
        """
        return self.__base_address

    @property
    def size(self) -> int:
        """
        The module image size.
        """
        return self.__size

    @property
    def name(self) -> str:
        """
        The module image filename.
        """
        return self.__name

    @property
    def path(self) -> str:
        """
        The module image file path.
        """
        path = ctypes.create_string_buffer(MAX_PATH)
        size = PSAPI.GetModuleFileNameExA(self.__parent.handle.native, self.__base_address, ctypes.byref(path),
                                          MAX_PATH)
        if size is None:
            raise WinAPIException

        return path.raw[:size].decode('utf-8')

    def __init__(self, parent: "Process", base_address: int, size: int, name: str):
        self.__parent = parent
        self.__base_address = base_address
        self.__size = size
        self.__name = name

    @staticmethod
    def create_from_native_structure(parent: "Process", native_structure: MODULEENTRY32A) -> "Module":
        return Module(parent, int.from_bytes(native_structure.modBaseAddr, byteorder='little'),
                      native_structure.modBaseSize, native_structure.szModule.decode('utf-8'))

    def eject(self, wait_ejection: bool = True):
        """
        Eject the module from the process.
        :param wait_ejection: if the method has to wait for the FreeLibrary thread to end (optional)
        """
        # noinspection PyProtectedMember
        freelibrary_address = Kernel32.GetProcAddress(Kernel32._handle, b'FreeLibrary')
        self.__parent.create_thread(freelibrary_address, param=self.__base_address, wait_for_end=wait_ejection)

    def __str__(self) -> str:
        return f"Module(parent={self.__parent}, base_address={self.__base_address:#x}, size={self.__size}, " \
               f"name=\"{self.__name}\", path=\"{self.path}\")"

    def __repr__(self) -> str:
        return self.__str__()


class Process:
    __process_id: int

    # noinspection PyTypeChecker
    __handle: Handle = Handle(None)

    @property
    def id(self) -> int:
        """
        The process ID.
        """
        return self.__process_id

    @property
    @_ensure_handle_status(ensure_open=True)
    def handle(self) -> Handle:
        """
        The process handle wrapper object.
        """
        return self.__handle

    @property
    def filename(self) -> str:
        """
        Get the process image name.
        """
        name = ctypes.create_string_buffer(MAX_PATH)
        size = DWORD(MAX_PATH)

        if not Kernel32.QueryFullProcessImageNameA(self.handle.native, 0x0, ctypes.pointer(name), ctypes.pointer(size)):
            raise WinAPIException

        return name.raw[:size.value].decode('utf-8')

    @property
    def modules(self) -> List:
        """
        Get a list of the modules loaded by the process.
        """
        entry = MODULEENTRY32A()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32A)

        snapshot = Kernel32.CreateToolhelp32Snapshot(
                SnapshotFlags.TH32CS_SNAPMODULE | SnapshotFlags.TH32CS_SNAPMODULE32, self.__process_id)
        if snapshot == INVALID_HANDLE_VALUE:
            raise WinAPIException

        if not Kernel32.Module32First(snapshot, ctypes.pointer(entry)):
            Kernel32.CloseHandle(snapshot)
            raise WinAPIException

        modules = []
        while Kernel32.Module32Next(snapshot, ctypes.pointer(entry)):
            modules.append(Module.create_from_native_structure(self, entry))

        Kernel32.CloseHandle(snapshot)

        return modules

    @property
    def threads(self) -> List[Thread]:
        """
        Get a list of all the process threads.
        """
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)

        snapshot = Kernel32.CreateToolhelp32Snapshot(SnapshotFlags.TH32CS_SNAPTHREAD, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            raise WinAPIException

        if not Kernel32.Thread32First(snapshot, ctypes.pointer(entry)):
            Kernel32.CloseHandle(snapshot)
            raise WinAPIException

        threads = []
        while Kernel32.Thread32Next(snapshot, ctypes.pointer(entry)):
            if entry.th32OwnerProcessID == self.__process_id:
                threads.append(Thread(entry.th32ThreadID))

        Kernel32.CloseHandle(snapshot)

        return threads

    def __init__(self, process_id: int):
        self.__process_id = process_id

    def module(self, name: str, case_insensitive: bool = True) -> Module:
        """
        Get a module by its name.
        :param name: the module name
        :param case_insensitive: if the name is case-insensitive
        :return: the module object
        """
        if case_insensitive:
            name = name.casefold()

        modules = self.modules
        module_names = [module.name.casefold() if case_insensitive else module.name for module in modules]

        if name not in module_names:
            raise ModuleNotFoundException

        return modules[module_names.index(name)]

    def thread(self, thread_id: int) -> Thread:
        """
        Get a thread by its thread id.
        :param thread_id: the thread id
        :return: the thread object
        """
        threads = self.threads
        thread_ids = [thread.id for thread in threads]

        if thread_id not in thread_ids:
            raise ThreadNotFoundException

        return threads[thread_ids.index(thread_id)]

    @staticmethod
    def by_name(name: str, case_insensitive: bool = True, multiple: bool = False) -> List["Process"] or "Process":
        """
        Get a process (or a list of processes) by its (or their) name(s).
        :param name: the process name
        :param case_insensitive: if the name is case-insensitive
        :param multiple: if a list of results if allowed
        :return: the process object(s)
        """
        if case_insensitive:
            name = name.casefold()

        entry = PROCESSENTRY32A()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32A)

        snapshot = Kernel32.CreateToolhelp32Snapshot(SnapshotFlags.TH32CS_SNAPPROCESS, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            raise WinAPIException

        if not Kernel32.Process32First(snapshot, ctypes.pointer(entry)):
            Kernel32.CloseHandle(snapshot)
            raise WinAPIException

        process_ids = []
        while Kernel32.Process32Next(snapshot, ctypes.pointer(entry)):
            executable_filename = entry.szExeFile.decode('utf-8')

            if (executable_filename.casefold() if case_insensitive else executable_filename) == name:
                process_ids.append(entry.th32ProcessID)

        Kernel32.CloseHandle(snapshot)

        if not process_ids:
            raise ProcessNotFoundException

        if not multiple:
            return Process(process_ids[0])

        return [Process(process_id) for process_id in process_ids]

    @staticmethod
    def all() -> List["Process"]:
        """
        Get a list of all processes running on the machine.
        :return: the list of processes
        """
        entry = PROCESSENTRY32A()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32A)

        snapshot = Kernel32.CreateToolhelp32Snapshot(SnapshotFlags.TH32CS_SNAPPROCESS, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            raise WinAPIException

        if not Kernel32.Process32First(snapshot, ctypes.pointer(entry)):
            Kernel32.CloseHandle(snapshot)
            raise WinAPIException

        process_ids = []
        while Kernel32.Process32Next(snapshot, ctypes.pointer(entry)):
            process_ids.append(Process(entry.th32ProcessID))

        Kernel32.CloseHandle(snapshot)

        return process_ids

    @_ensure_handle_status(ensure_open=False)
    def open(self, access_rights: ProcessAccessRights):
        """
        Open the process with the desired access rights.
        :param access_rights: the desired access rights
        """
        native_handle = Kernel32.OpenProcess(access_rights, False, self.__process_id)
        if native_handle is None:
            raise WinAPIException

        self.__handle = Handle(native_handle)

    def close(self):
        """
        Close the previously opened process.
        """
        self.handle.close()

    def terminate(self, exit_code: int):
        """
        Terminate the process.
        :param exit_code: the process exit code
        """
        status = NTDLL.NtTerminateProcess(self.handle.native, exit_code)
        if status != 0x0:
            raise NTStatusException(status)

    def suspend(self):
        """
        Suspend the process.
        (It uses NtSuspendProcess, for further information consult the MSDN posts)
        """
        status = NTDLL.NtSuspendProcess(self.handle.native)
        if status != 0x0:
            raise NTStatusException(status)

    def resume(self):
        """
        Resume the process.
        (It uses NtSuspendProcess, for further information consult the MSDN posts)
        """
        status = NTDLL.NtResumeProcess(self.handle.native)
        if status != 0x0:
            raise NTStatusException(status)

    def create_thread(self, address: int, param: int = None, security_attributes: int = None, stack_size: int = 0,
                      creation_flags: ThreadCreationFlags = ThreadCreationFlags.CREATE_NORMAL,
                      wait_for_end: bool = False) -> Tuple[int, int] or None:
        """
        Create a thread in the process context.
        :param address: the address to the code to execute
        :param param: the parameter(s) to pass to the thread (optional)
        :param security_attributes: the thread security attributes (optional)
        :param stack_size: the thread maximum stack size (optional)
        :param creation_flags: the thread creation flags (optional)
        :param wait_for_end: if the method has to wait for the thread to exit (it does not return anything if true)
        :return: the thread object
        """
        thread_id = DWORD()
        thread_handle = Kernel32.CreateRemoteThread(self.handle.native, security_attributes, stack_size,
                                                    address, param, creation_flags, ctypes.pointer(thread_id))
        if thread_handle is None:
            raise WinAPIException

        if wait_for_end:
            Kernel32.WaitForSingleObjectEx(thread_handle, -1, True)
            return

        return Thread(thread_id.value, thread_handle)

    def __str__(self) -> str:
        return f"Process(id={self.__process_id}, handle={self.__handle})"

    def __repr__(self) -> str:
        return self.__str__()
