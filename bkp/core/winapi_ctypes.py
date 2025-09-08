# core/winapi_ctypes.py
import ctypes
from ctypes import wintypes
import json

# Carregar DLLs
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

# Definir tipos
HANDLE = wintypes.HANDLE
LPVOID = wintypes.LPVOID
DWORD = wintypes.DWORD
WORD = wintypes.WORD
BYTE = wintypes.BYTE
BOOL = wintypes.BOOL
ULONG = wintypes.ULONG
PVOID = ctypes.c_void_p  # Corrigido: usar c_void_p em vez de wintypes.PVOID

# Estruturas
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", wintypes.LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", DWORD),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
    ]

# Definir funções
CreateProcessW = kernel32.CreateProcessW
CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.LPVOID,
    wintypes.LPVOID,
    BOOL,
    DWORD,
    wintypes.LPVOID,
    wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]
CreateProcessW.restype = BOOL

ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = [HANDLE]
ResumeThread.restype = DWORD

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [HANDLE]
CloseHandle.restype = BOOL

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = BOOL

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = BOOL

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [HANDLE, LPVOID, ctypes.c_size_t, DWORD, DWORD]
VirtualAllocEx.restype = LPVOID

VirtualFreeEx = kernel32.VirtualFreeEx
VirtualFreeEx.argtypes = [HANDLE, LPVOID, ctypes.c_size_t, DWORD]
VirtualFreeEx.restype = BOOL

GetThreadContext = kernel32.GetThreadContext
GetThreadContext.argtypes = [HANDLE, ctypes.POINTER(CONTEXT)]
GetThreadContext.restype = BOOL

SetThreadContext = kernel32.SetThreadContext
SetThreadContext.argtypes = [HANDLE, ctypes.POINTER(CONTEXT)]
SetThreadContext.restype = BOOL

GetLastError = kernel32.GetLastError
GetLastError.argtypes = []
GetLastError.restype = DWORD

# Funções NtDll
NtUnmapViewOfSection = ntdll.NtUnmapViewOfSection
NtUnmapViewOfSection.argtypes = [HANDLE, PVOID]
NtUnmapViewOfSection.restype = ULONG

# Constantes
CREATE_SUSPENDED = 0x00000004
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
CONTEXT_FULL = 0x00010007
MEM_RELEASE = 0x8000

# STATUS_SUCCESS
STATUS_SUCCESS = 0x00000000

# Variável global para armazenar informações do processo suspenso
_suspended_process = None

def create_suspended_process(path):
    global _suspended_process
    
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()
    
    # Converter caminho para wide string
    wide_path = ctypes.c_wchar_p(path)
    
    success = CreateProcessW(
        wide_path,
        None,
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi)
    )
    
    if not success:
        error_code = GetLastError()
        print(f"[CTypes] Falha ao criar processo suspenso. Código de erro: {error_code}")
        return False
    
    # Armazenar informações do processo globalmente
    _suspended_process = pi
    print(f"[CTypes] Processo suspenso criado com sucesso → PID: {pi.dwProcessId}")
    return True

def resume_process():
    global _suspended_process
    
    if _suspended_process is None or _suspended_process.hThread is None:
        print("[CTypes] Nenhum processo suspenso para retomar")
        return False
    
    result = ResumeThread(_suspended_process.hThread)
    
    if result == 0xFFFFFFFF:
        error_code = GetLastError()
        print(f"[CTypes] Falha ao retomar processo. Código de erro: {error_code}")
        return False
    
    # Fechar handles
    CloseHandle(_suspended_process.hProcess)
    CloseHandle(_suspended_process.hThread)
    
    # Resetar estrutura
    _suspended_process = None
    
    print("[CTypes] Processo retomado com sucesso")
    return True

def read_process_memory(address, size):
    global _suspended_process
    
    if _suspended_process is None or _suspended_process.hProcess is None:
        print("[CTypes] Nenhum processo aberto")
        return None
    
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    
    success = ReadProcessMemory(
        _suspended_process.hProcess,
        address,
        buffer,
        size,
        ctypes.byref(bytes_read)
    )
    
    if not success or bytes_read.value != size:
        error_code = GetLastError()
        print(f"[CTypes] Falha ao ler memória. Código de erro: {error_code}")
        return None
    
    return buffer.raw

def write_process_memory(address, data):
    global _suspended_process
    
    if _suspended_process is None or _suspended_process.hProcess is None:
        print("[CTypes] Nenhum processo aberto")
        return False
    
    if isinstance(data, str):
        data = data.encode()
    
    buffer = ctypes.create_string_buffer(data)
    bytes_written = ctypes.c_size_t(0)
    
    success = WriteProcessMemory(
        _suspended_process.hProcess,
        address,
        buffer,
        len(data),
        ctypes.byref(bytes_written)
    )
    
    if not success or bytes_written.value != len(data):
        error_code = GetLastError()
        print(f"[CTypes] Falha ao escrever memória. Código de erro: {error_code}")
        return False
    
    return True

def virtual_alloc_ex(size, address=0):
    global _suspended_process
    
    if _suspended_process is None or _suspended_process.hProcess is None:
        print("[CTypes] Nenhum processo aberto")
        return 0
    
    alloc_address = VirtualAllocEx(
        _suspended_process.hProcess,
        address,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )
    
    if not alloc_address:
        error_code = GetLastError()
        print(f"[CTypes] Falha ao alocar memória. Código de erro: {error_code}")
        return 0
    
    return alloc_address

def virtual_free_ex(address, size=0):
    global _suspended_process
    
    if _suspended_process is None or _suspended_process.hProcess is None:
        print("[CTypes] Nenhum processo aberto")
        return False
    
    success = VirtualFreeEx(
        _suspended_process.hProcess,
        address,
        size,
        MEM_RELEASE
    )
    
    if not success:
        error_code = GetLastError()
        print(f"[CTypes] Falha ao liberar memória. Código de erro: {error_code}")
        return False
    
    return True

def get_thread_context():
    global _suspended_process
    
    if _suspended_process is None or _suspended_process.hThread is None:
        print("[CTypes] Nenhum thread suspenso")
        return None
    
    context = CONTEXT()
    context.ContextFlags = CONTEXT_FULL
    
    success = GetThreadContext(_suspended_process.hThread, ctypes.byref(context))
    
    if not success:
        error_code = GetLastError()
        print(f"[CTypes] Falha ao obter contexto. Código de erro: {error_code}")
        return None
    
    return {
        'Eax': context.Eax,
        'Ebx': context.Ebx,
        'Ecx': context.Ecx,
        'Edx': context.Edx,
        'Esi': context.Esi,
        'Edi': context.Edi,
        'Ebp': context.Ebp,
        'Esp': context.Esp,
        'Eip': context.Eip,
        'SegCs': context.SegCs,
        'SegDs': context.SegDs,
        'SegEs': context.SegEs,
        'SegFs': context.SegFs,
        'SegGs': context.SegGs,
        'SegSs': context.SegSs,
        'EFlags': context.EFlags
    }

def set_thread_context(context_dict):
    global _suspended_process
    
    if _suspended_process is None or _suspended_process.hThread is None:
        print("[CTypes] Nenhum thread suspenso")
        return False
    
    context = CONTEXT()
    context.ContextFlags = CONTEXT_FULL
    context.Eax = context_dict.get('Eax', 0)
    context.Ebx = context_dict.get('Ebx', 0)
    context.Ecx = context_dict.get('Ecx', 0)
    context.Edx = context_dict.get('Edx', 0)
    context.Esi = context_dict.get('Esi', 0)
    context.Edi = context_dict.get('Edi', 0)
    context.Ebp = context_dict.get('Ebp', 0)
    context.Esp = context_dict.get('Esp', 0)
    context.Eip = context_dict.get('Eip', 0)
    context.SegCs = context_dict.get('SegCs', 0)
    context.SegDs = context_dict.get('SegDs', 0)
    context.SegEs = context_dict.get('SegEs', 0)
    context.SegFs = context_dict.get('SegFs', 0)
    context.SegGs = context_dict.get('SegGs', 0)
    context.SegSs = context_dict.get('SegSs', 0)
    context.EFlags = context_dict.get('EFlags', 0)
    
    success = SetThreadContext(_suspended_process.hThread, ctypes.byref(context))
    
    if not success:
        error_code = GetLastError()
        print(f"[CTypes] Falha ao definir contexto. Código de erro: {error_code}")
        return False
    
    return True

def get_process_handle():
    global _suspended_process
    if _suspended_process is None:
        return 0
    return _suspended_process.hProcess

def get_thread_handle():
    global _suspended_process
    if _suspended_process is None:
        return 0
    return _suspended_process.hThread

def nt_unmap_view_of_section(process_handle, base_address):
    result = NtUnmapViewOfSection(process_handle, base_address)
    return result == STATUS_SUCCESS