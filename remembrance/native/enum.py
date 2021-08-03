import enum


class ProcessAccessRights(enum.IntEnum):
    DELETE = 0x00010000
    SYNCHRONIZE = 0x00100000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000

    PROCESS_CREATE_PROCESS = 0x0080
    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_DUP_HANDLE = 0x0040
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_SET_INFORMATION = 0x0200
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_SUSPEND_RESUME = 0x0800
    PROCESS_TERMINATE = 0x0001
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020

    PROCESS_ALL_ACCESS = (
            PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION |
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME |
            PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE)


class SnapshotFlags(enum.IntEnum):
    TH32CS_INHERIT = 0x80000000
    TH32CS_SNAPHEAPLIST = 0x00000001
    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
    TH32CS_SNAPPROCESS = 0x00000002
    TH32CS_SNAPTHREAD = 0x00000004

    TH32CS_SNAPALL = TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD


class MemoryProtection(enum.IntEnum):
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_TARGETS_INVALID = 0x40000000
    PAGE_TARGETS_NO_UPDATE = 0x40000000


class MemoryAllocation(enum.IntEnum):
    MEM_COMMIT = 0x00001000
    MEM_RESERVE = 0x00002000
    MEM_RESET = 0x00080000
    MEM_RESET_UNDO = 0x1000000

    MEM_LARGE_PAGES = 0x20000000
    MEM_PHYSICAL = 0x00400000
    MEM_TOP_DOWN = 0x00100000


class MemoryFreeing(enum.IntEnum):
    MEM_DECOMMIT = 0x00004000
    MEM_RELEASE = 0x00008000

    MEM_COALESCE_PLACEHOLDERS = 0x00000001
    MEM_PRESERVE_PLACEHOLDER = 0x00000002


class ThreadCreationFlags(enum.IntEnum):
    CREATE_NORMAL = 0
    CREATE_SUSPENDED = 0x00000004
    STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000


class ThreadAccessRights(enum.IntEnum):
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    SYNCHRONIZE = 0x00100000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000

    THREAD_DIRECT_IMPERSONATION = 0x0200
    THREAD_GET_CONTEXT = 0x0008
    THREAD_IMPERSONATE = 0x0100
    THREAD_QUERY_INFORMATION = 0x0040
    THREAD_QUERY_LIMITED_INFORMATION = 0x0800
    THREAD_SET_CONTEXT = 0x0010
    THREAD_SET_INFORMATION = 0x0020
    THREAD_SET_LIMITED_INFORMATION = 0x0400
    THREAD_SET_THREAD_TOKEN = 0x0080
    THREAD_SUSPEND_RESUME = 0x0002
    THREAD_TERMINATE = 0x0001

    THREAD_ALL_ACCESS = (THREAD_DIRECT_IMPERSONATION | THREAD_GET_CONTEXT | THREAD_IMPERSONATE |
                         THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_CONTEXT |
                         THREAD_SET_INFORMATION | THREAD_SET_LIMITED_INFORMATION | THREAD_SET_THREAD_TOKEN |
                         THREAD_SUSPEND_RESUME | THREAD_TERMINATE)
