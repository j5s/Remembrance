from abc import ABC, abstractmethod

from remembrance.native.enum import MemoryProtection


# noinspection PyUnresolvedReferences
class ShellcodeInjectionMethod(ABC):
    _memory: "Memory"

    def __init__(self, memory: "Memory"):
        self._memory = memory

    @abstractmethod
    def execute(self, *args, **kwargs):
        ...


class CreateRemoteThreadMethod(ShellcodeInjectionMethod):
    def execute(self, shellcode: bytes, wait_for_exit: bool = False):
        """
        Inject the provided shellcode into the process using the CreateRemoteThread WINAPI.
        :param shellcode: the shellcode to execute
        :param wait_for_exit: if the method has to wait for the DLL to exit (it won't return anything if true)
        :return: the path memory area and the thread object
        """

        shellcode_area = self._memory.allocate(len(shellcode), MemoryProtection.PAGE_EXECUTE_READWRITE)
        shellcode_area.write(shellcode)

        # noinspection PyProtectedMember
        thread = self._memory.process.create_thread(shellcode_area.base_address, wait_for_end=wait_for_exit)

        if not wait_for_exit:
            return shellcode_area, thread

        shellcode_area.free()
