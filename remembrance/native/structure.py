from .constant import MAX_MODULE_NAME32
from .types import *


class PROCESSENTRY32A(ctypes.Structure):
    _fields_ = [('dwSize', DWORD),
                ('cntUsage', DWORD),
                ('th32ProcessID', DWORD),
                ('th32DefaultHeapID', ULONG_PTR),
                ('th32ModuleID', DWORD),
                ('cntThreads', DWORD),
                ('th32ParentProcessID', DWORD),
                ('pcPriClassBase', LONG),
                ('dwFlags', DWORD),
                ('szExeFile', CHAR * MAX_PATH)]


LPPROCESSENTRY32A = ctypes.POINTER(PROCESSENTRY32A)


class MODULEENTRY32A(ctypes.Structure):
    _fields_ = [('dwSize', DWORD),
                ('th32ModuleID', DWORD),
                ('th32ProcessID', DWORD),
                ('GlblcntUsage', DWORD),
                ('ProccntUsage', DWORD),
                ('modBaseAddr', PBYTE),
                ('modBaseSize', DWORD),
                ('hModule', HMODULE),
                ('szModule', CHAR * MAX_MODULE_NAME32),
                ('szExePath', CHAR * MAX_PATH)]


LPMODULEENTRY32A = ctypes.POINTER(MODULEENTRY32A)


# noinspection PyPep8Naming
class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('nLength', DWORD),
                ('lpSecurityDescriptor', LPVOID),
                ('bInheritHandle', BOOL)]


LPSECURITY_ATTRIBUTES = ctypes.POINTER(SECURITY_ATTRIBUTES)


class THREADENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', DWORD),
                ('cntUsage', DWORD),
                ('th32ThreadID', DWORD),
                ('th32OwnerProcessID', DWORD),
                ('tpBasePri', LONG),
                ('tpDeltaPri', LONG),
                ('dwFlags', DWORD)]


LPTHREADENTRY32 = ctypes.POINTER(THREADENTRY32)


class CLIENT_ID(ctypes.Structure):
    _fields_ = [('UniqueProcess', LPVOID),
                ('UniqueThread', LPVOID)]


class THREAD_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [('ExitStatus', NTSTATUS),
                ('TebBaseAddress', LPVOID),
                ('ClientId', CLIENT_ID),
                ('AffinityMask', KAFFINITY),
                ('Priority', KPRIORITY),
                ('BasePriority', KPRIORITY)]
