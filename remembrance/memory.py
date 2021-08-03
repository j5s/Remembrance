import ctypes
from typing import Tuple, Type

from .exception import WinAPIException
from .injection.dll import DLLInjectionMethod
from .injection.shellcode import ShellcodeInjectionMethod
from .native import Kernel32, SIZE_T
from .native.enum import MemoryAllocation, MemoryFreeing, MemoryProtection
from .process import Process


class MemoryArea:
    __parent: "Memory"
    __base_address: int
    __size: int

    @property
    def parent(self) -> "Memory":
        """
        The memory area parent.
        """
        return self.__parent

    @property
    def base_address(self) -> int:
        """
        The memory area base address.
        """
        return self.__base_address

    @property
    def size(self) -> int:
        """
        The memory area size in bytes.
        """
        return self.__size

    def __init__(self, parent: "Memory", base_address: int, size: int):
        self.__parent = parent
        self.__base_address = base_address
        self.__size = size

    def read(self, byte_width: int, offset: int = 0) -> bytes:
        """
        Read some data from the memory area.
        :param byte_width: how many bytes to read
        :param offset: the offset from the base address (optional)
        :return: the read data
        """
        return self.__parent.basic_read(self.__base_address + offset, byte_width)

    def write(self, data: bytes, offset: int = 0):
        """
        Write some data to the memory area.
        :param data: the data to write
        :param offset: the offset from the base address (optional)
        """
        self.__parent.basic_write(self.__base_address + offset, data)

    def free(self, *args, **kwargs):
        """
        Free the memory area.
        NOTE: For more arguments, consult the Memory.basic_free documentation.
        """
        self.__parent.basic_free(self.__base_address, self.__size, *args, **kwargs)

    def __str__(self) -> str:
        return f"MemoryArea(parent={self.__parent}, base_address={self.__base_address:#x}, size={self.__size})"

    def __repr__(self) -> str:
        return self.__str__()


class Memory:
    __process: Process

    @property
    def process(self) -> Process:
        return self.__process

    def __init__(self, process: Process):
        self.__process = process

    def basic_read(self, address: int, byte_width: int,
                   return_read_count: bool = False) -> Tuple[int, bytes] or bytes:
        """
        Read some data from the process memory.
        :param address: the address to read from
        :param byte_width: how many bytes to read
        :param return_read_count: if the count of how many bytes have been read must be returned
        :return: the read buffer
        """
        buffer = ctypes.create_string_buffer(byte_width)
        count = SIZE_T()

        if not Kernel32.ReadProcessMemory(self.__process.handle.native, address,
                                          ctypes.byref(buffer), byte_width, ctypes.pointer(count)):
            raise WinAPIException

        if return_read_count:
            return count.value, buffer.raw
        return buffer.raw

    def basic_write(self, address: int, data: bytes, return_written_count: bool = False) -> int or None:
        """
        Write some data to the process memory.
        :param address: the address to write to
        :param data: the data to write
        :param return_written_count: if the count of how many bytes have been written must be returned
        """

        count = SIZE_T()
        if not Kernel32.WriteProcessMemory(self.__process.handle.native, address, data, len(data),
                                           ctypes.pointer(count)):
            raise WinAPIException

        if return_written_count:
            return count.value

    def basic_allocate(self, size: int, protection: MemoryProtection, address: int = None,
                       allocation_type: MemoryAllocation = MemoryAllocation.MEM_COMMIT) -> int:
        """
        Allocate a memory area in the process memory namespace.
        NOTE: This is just a wrapper for the native method. Use Memory.allocate to get a more user-friendly approach.
        :param size: the size of the area
        :param protection: the area protection
        :param address: the address to allocate at (optional)
        :param allocation_type: the area allocation type (optional, not recommended to change)
        :return: the memory area address
        """
        address = Kernel32.VirtualAllocEx(self.__process.handle.native, address, size, allocation_type, protection)
        if address is None:
            raise WinAPIException

        return address

    def basic_free(self, address: int, size: int, free_type: MemoryFreeing = MemoryFreeing.MEM_DECOMMIT):
        """
        Free a previously allocated memory area in the process memory namespace.
        :param address: the memory area address
        :param size: the memory area size
        :param free_type: the area freeing type (optional, not recommended to change)
        """
        if not Kernel32.VirtualFreeEx(self.__process.handle.native, address, size, free_type):
            raise WinAPIException

    def allocate(self, size: int, protection: MemoryProtection, *args, **kwargs) -> MemoryArea:
        """
        Allocate a memory area in the process memory namespace.
        NOTE: For more parameters consult the Memory.basic_allocate documentation.
        :param size: the size of the area
        :param protection: the area protection
        :return: the memory area address
        """
        return MemoryArea(self, self.basic_allocate(size, protection, *args, **kwargs), size)

    def inject_dll(self, method: Type[DLLInjectionMethod], *args, **kwargs):
        """
        Inject a DLL via the provided method.
        NOTE: For parameters, consult the chosen injection method documentation.
        :param method: the injection method to use
        """
        return method(self).execute(*args, **kwargs)

    def inject_shellcode(self, method: Type[ShellcodeInjectionMethod], *args, **kwargs):
        """
        Inject a shellcode via the provided method.
        NOTE: For parameters, consult the chosen injection method documentation.
        :param method: the injection method to use
        """
        return method(self).execute(*args, **kwargs)

    def __str__(self) -> str:
        return f"Memory(process={self.__process})"

    def __repr__(self) -> str:
        return self.__str__()
