from abc import ABC, abstractmethod

from remembrance.native import Kernel32
from remembrance.native.enum import MemoryProtection


# noinspection PyUnresolvedReferences
class DLLInjectionMethod(ABC):
    _memory: "Memory"

    def __init__(self, memory: "Memory"):
        self._memory = memory

    @abstractmethod
    def execute(self, *args, **kwargs):
        ...


class LoadLibraryMethod(DLLInjectionMethod):
    def execute(self, path: str, wait_for_exit: bool = False):
        """
        Inject the provided DLL into the process using the LoadLibrary WINAPI.
        :param path: the path to the DLL file.
        :param wait_for_exit: if the method has to wait for the DLL to exit (it won't return anything if true)
        :return: the path memory area and the thread object
        """

        path_area = self._memory.allocate(len(path) + 1, MemoryProtection.PAGE_READWRITE)
        path_area.write(path.encode('utf-8') + b'\x00')

        # noinspection PyProtectedMember
        loadlibrary_address = Kernel32.GetProcAddress(Kernel32._handle, b'LoadLibraryA')
        thread = self._memory.process.create_thread(loadlibrary_address, param=path_area.base_address,
                                                    wait_for_end=wait_for_exit)

        if not wait_for_exit:
            return path_area, thread

        path_area.free()
