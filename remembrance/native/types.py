import ctypes
from ctypes.wintypes import *

if ctypes.sizeof(ctypes.c_void_p) == 8:
    ULONG_PTR = ctypes.c_ulonglong
else:
    ULONG_PTR = ctypes.c_ulong

NTSTATUS = ULONG
SIZE_T = ULONG
PSIZE_T = ctypes.POINTER(SIZE_T)
FARPROC = LPCVOID
KAFFINITY = ULONG_PTR
KPRIORITY = DWORD
THREADINFOCLASS = DWORD
