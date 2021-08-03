import ctypes
from ctypes.wintypes import *

from remembrance.native.structure import LPMODULEENTRY32A, LPPROCESSENTRY32A, LPSECURITY_ATTRIBUTES, LPTHREADENTRY32
from remembrance.native.types import FARPROC, NTSTATUS, PSIZE_T, SIZE_T, THREADINFOCLASS

Kernel32 = ctypes.windll.Kernel32
NTDLL = ctypes.windll.NTDLL
PSAPI = ctypes.windll.psapi

"""
    DWORD GetLastError();
"""
Kernel32.GetLastError.argtypes = []
Kernel32.GetLastError.restype = DWORD

"""
    BOOL CloseHandle(
        HANDLE hObject
    );
"""
Kernel32.CloseHandle.argtypes = [HANDLE]
Kernel32.CloseHandle.restype = BOOL

"""
    HANDLE OpenProcess(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwProcessId
    );
"""
Kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
Kernel32.OpenProcess.restype = HANDLE

"""
    HANDLE CreateToolhelp32Snapshot(
        DWORD dwFlags,
        DWORD th32ProcessID
    );
"""
Kernel32.CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
Kernel32.CreateToolhelp32Snapshot.restype = HANDLE

"""
    BOOL Process32First(
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe
    );
"""
Kernel32.Process32First.argtypes = [HANDLE, LPPROCESSENTRY32A]
Kernel32.Process32First.restype = BOOL

"""
    BOOL Process32Next(
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe
    );
"""
Kernel32.Process32Next.argtypes = [HANDLE, LPPROCESSENTRY32A]
Kernel32.Process32Next.restype = BOOL

"""
    BOOL ReadProcessMemory(
        HANDLE  hProcess,
        LPCVOID lpBaseAddress,
        LPVOID  lpBuffer,
        SIZE_T  nSize,
        SIZE_T  *lpNumberOfBytesRead
    );
"""
Kernel32.ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, SIZE_T, PSIZE_T]
Kernel32.ReadProcessMemory.restype = BOOL

"""
    BOOL WriteProcessMemory(
        HANDLE  hProcess,
        LPVOID  lpBaseAddress,
        LPCVOID lpBuffer,
        SIZE_T  nSize,
        SIZE_T  *lpNumberOfBytesWritten
    );
"""
Kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, SIZE_T, PSIZE_T]
Kernel32.WriteProcessMemory.restype = BOOL

"""
    LPVOID VirtualAllocEx(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flAllocationType,
        DWORD  flProtect
    );
"""
Kernel32.VirtualAllocEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD]
Kernel32.VirtualAllocEx.restype = LPVOID

"""
    BOOL VirtualFreeEx(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  dwFreeType
    );
"""
Kernel32.VirtualFreeEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD]
Kernel32.VirtualFreeEx.restype = BOOL

"""
    BOOL QueryFullProcessImageNameA(
        HANDLE hProcess,
        DWORD  dwFlags,
        LPSTR  lpExeName,
        PDWORD lpdwSize
    );
"""
Kernel32.QueryFullProcessImageNameA.argtypes = [HANDLE, DWORD, LPVOID, PDWORD]
Kernel32.QueryFullProcessImageNameA.restype = BOOL

"""
    BOOL Module32First(
        HANDLE          hSnapshot,
        LPMODULEENTRY32 lpme
    );
"""
Kernel32.Module32First.argtypes = [HANDLE, LPMODULEENTRY32A]
Kernel32.Module32First.restype = BOOL

"""
    BOOL Module32Next(
        HANDLE           hSnapshot,
        LPMODULEENTRY32  lpme
    );
"""
Kernel32.Module32Next.argtypes = [HANDLE, LPMODULEENTRY32A]
Kernel32.Module32Next.restype = BOOL

"""
    BOOL Thread32First(
        HANDLE          hSnapshot,
        LPTHREADENTRY32 lpte
    );
"""
Kernel32.Thread32First.argtypes = [HANDLE, LPTHREADENTRY32]
Kernel32.Thread32First.restype = BOOL

"""
    BOOL Thread32Next(
        HANDLE          hSnapshot,
        LPTHREADENTRY32 lpte
    );
"""
Kernel32.Thread32Next.argtypes = [HANDLE, LPTHREADENTRY32]
Kernel32.Thread32Next.restype = BOOL

"""
    HANDLE CreateRemoteThread(
        HANDLE                 hProcess,
        LPSECURITY_ATTRIBUTES  lpThreadAttributes,
        SIZE_T                 dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID                 lpParameter,
        DWORD                  dwCreationFlags,
        LPDWORD                lpThreadId
    );
"""
Kernel32.CreateRemoteThread.argtypes = [HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPCVOID, LPVOID, DWORD, LPDWORD]
Kernel32.CreateRemoteThread.restype = HANDLE

"""
    FARPROC GetProcAddress(
        HMODULE hModule,
        LPCSTR  lpProcName
    );
"""
Kernel32.GetProcAddress.argtypes = [HMODULE, LPCSTR]
Kernel32.GetProcAddress.restype = FARPROC

"""
    DWORD WaitForSingleObjectEx(
        HANDLE hHandle,
        DWORD  dwMilliseconds,
        BOOL   bAlertable
    );
"""
Kernel32.WaitForSingleObjectEx.argtypes = [HANDLE, DWORD, BOOL]
Kernel32.WaitForSingleObjectEx.restype = DWORD

"""
    HANDLE OpenThread(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwThreadId
    );
"""
Kernel32.OpenThread.argtypes = [DWORD, BOOL, DWORD]
Kernel32.OpenThread.restype = HANDLE

"""
    BOOL TerminateThread(
        HANDLE hThread,
        DWORD  dwExitCode
    );
"""
Kernel32.TerminateThread.argtypes = [HANDLE, DWORD]
Kernel32.TerminateThread.restype = BOOL

"""
    DWORD SuspendThread(
        HANDLE hThread
    );
"""
Kernel32.SuspendThread.argtypes = [HANDLE]
Kernel32.SuspendThread.restype = DWORD

"""
    DWORD ResumeThread(
        HANDLE hThread
    );
"""
Kernel32.ResumeThread.argtypes = [HANDLE]
Kernel32.ResumeThread.restype = DWORD

"""
    DWORD GetModuleFileNameExA(
        HANDLE  hProcess,
        HMODULE hModule,
        LPSTR   lpFilename,
        DWORD   nSize
    );
"""
PSAPI.GetModuleFileNameExA.argtypes = [HANDLE, HMODULE, LPVOID, DWORD]
PSAPI.GetModuleFileNameExA.restype = DWORD

"""
    NTSTATUS NtSuspendProcess(
        HANDLE hProcessHandle
    );
"""
NTDLL.NtSuspendProcess.argtypes = [HANDLE]
NTDLL.NtSuspendProcess.restype = NTSTATUS

"""
    NTSTATUS NtResumeProcess(
        HANDLE hProcessHandle
    );
"""
NTDLL.NtResumeProcess.argtypes = [HANDLE]
NTDLL.NtResumeProcess.restype = NTSTATUS

"""
    NTSTATUS NtTerminateProcess(
        HANDLE hProcessHandle,
        NTSTATUS ntExitStatus
    );
"""
NTDLL.NtResumeProcess.argtypes = [HANDLE]
NTDLL.NtResumeProcess.restype = NTSTATUS

"""
    __kernel_entry NTSTATUS NtQueryInformationThread(
        HANDLE          ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID           ThreadInformation,
        ULONG           ThreadInformationLength,
        PULONG          ReturnLength
    );
"""
NTDLL.NtQueryInformationThread.argtypes = [HANDLE, THREADINFOCLASS, LPVOID, ULONG, PULONG]
NTDLL.NtQueryInformationThread.restype = NTSTATUS
