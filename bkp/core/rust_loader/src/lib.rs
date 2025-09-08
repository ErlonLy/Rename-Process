// core/rust_loader/src/lib.rs
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Read;
use std::os::raw::c_char;
use serde_json::json;

// Estruturas para cabeçalhos PE
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub BaseOfData: u32,
    pub ImageBase: u32,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u32,
    pub SizeOfStackCommit: u32,
    pub SizeOfHeapReserve: u32,
    pub SizeOfHeapCommit: u32,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IMAGE_NT_HEADERS32 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub VirtualSize: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

#[no_mangle]
pub extern "C" fn parse_pe(path: *const c_char) -> *const c_char {
    let result = parse_pe_internal(path);
    
    match result {
        Ok(json_str) => {
            let c_string = CString::new(json_str).unwrap_or_else(|_| {
                CString::new("{\"error\": \"Failed to create CString\"}").unwrap()
            });
            c_string.into_raw()
        }
        Err(err_msg) => {
            let error_json = json!({
                "error": err_msg
            });
            let c_string = CString::new(error_json.to_string()).unwrap_or_else(|_| {
                CString::new("{\"error\": \"Unknown error\"}").unwrap()
            });
            c_string.into_raw()
        }
    }
}

fn parse_pe_internal(path: *const c_char) -> Result<String, String> {
    // Converte ponteiro C para Rust string
    let c_str = unsafe { CStr::from_ptr(path) };
    let filename = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return Err("Invalid path encoding".to_string()),
    };

    // Abre o arquivo
    let mut file = match File::open(filename) {
        Ok(f) => f,
        Err(e) => return Err(format!("Error opening file: {}", e)),
    };

    // Lê o conteúdo do arquivo
    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        return Err(format!("Error reading file: {}", e));
    }

    // Parse do PE
    match parse_pe_data(&buffer) {
        Ok(pe_info) => {
            let json_info = json!({
                "success": true,
                "image_base": pe_info.image_base,
                "entry_point": pe_info.entry_point,
                "size_of_image": pe_info.size_of_image,
                "section_count": pe_info.sections.len(),
                "is_64bit": pe_info.is_64bit,
                "message": format!("PE parsed successfully: {} sections", pe_info.sections.len())
            });
            Ok(json_info.to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Debug)]
struct PEInfo {
    image_base: u64,
    entry_point: u32,
    size_of_image: u32,
    sections: Vec<SectionInfo>,
    is_64bit: bool,
}

#[derive(Debug)]
struct SectionInfo {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    characteristics: u32,
}

fn parse_pe_data(data: &[u8]) -> Result<PEInfo, &'static str> {
    if data.len() < 64 {
        return Err("File too small to be a valid PE");
    }

    // Parse DOS header
    let dos_header: IMAGE_DOS_HEADER = unsafe {
        if data[0] != b'M' || data[1] != b'Z' {
            return Err("MZ signature not found");
        }
        std::ptr::read(data.as_ptr() as *const IMAGE_DOS_HEADER)
    };

    // Verifica se é um PE válido
    let nt_headers_offset = dos_header.e_lfanew as usize;
    if nt_headers_offset + 4 >= data.len() {
        return Err("Invalid NT headers offset");
    }

    if data[nt_headers_offset] != b'P'
        || data[nt_headers_offset + 1] != b'E'
        || data[nt_headers_offset + 2] != 0
        || data[nt_headers_offset + 3] != 0
    {
        return Err("PE signature not found");
    }

    // Determina se é 32 ou 64 bits
    let magic = u16::from_le_bytes([data[nt_headers_offset + 24], data[nt_headers_offset + 25]]);
    let is_64bit = magic == 0x20b;

    let (image_base, entry_point, size_of_image) = if is_64bit {
        let nt_headers: IMAGE_NT_HEADERS64 = unsafe {
            std::ptr::read(data.as_ptr().offset(nt_headers_offset as isize) as *const IMAGE_NT_HEADERS64)
        };
        (
            nt_headers.OptionalHeader.ImageBase,
            nt_headers.OptionalHeader.AddressOfEntryPoint,
            nt_headers.OptionalHeader.SizeOfImage
        )
    } else {
        let nt_headers: IMAGE_NT_HEADERS32 = unsafe {
            std::ptr::read(data.as_ptr().offset(nt_headers_offset as isize) as *const IMAGE_NT_HEADERS32)
        };
        (
            nt_headers.OptionalHeader.ImageBase as u64,
            nt_headers.OptionalHeader.AddressOfEntryPoint,
            nt_headers.OptionalHeader.SizeOfImage
        )
    };

    // Parse sections
    let num_sections = unsafe {
        std::ptr::read(data.as_ptr().offset(nt_headers_offset as isize + 4 + 20) as *const u16)
    } as usize;

    let sections_offset = nt_headers_offset + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>() + 
        if is_64bit {
            std::mem::size_of::<IMAGE_OPTIONAL_HEADER64>()
        } else {
            std::mem::size_of::<IMAGE_OPTIONAL_HEADER32>()
        };
    
    let mut sections = Vec::new();
    
    for i in 0..num_sections {
        let section_offset = sections_offset + i * std::mem::size_of::<IMAGE_SECTION_HEADER>();
        if section_offset + std::mem::size_of::<IMAGE_SECTION_HEADER>() > data.len() {
            return Err("Section beyond file boundary");
        }
        
        let section_header: IMAGE_SECTION_HEADER = unsafe {
            std::ptr::read(data.as_ptr().offset(section_offset as isize) as *const IMAGE_SECTION_HEADER)
        };
        
        let name = String::from_utf8_lossy(&section_header.Name)
            .trim_end_matches('\0')
            .to_string();
        
        sections.push(SectionInfo {
            name,
            virtual_address: section_header.VirtualAddress,
            virtual_size: section_header.VirtualSize,
            raw_size: section_header.SizeOfRawData,
            characteristics: section_header.Characteristics,
        });
    }

    Ok(PEInfo {
        image_base,
        entry_point,
        size_of_image,
        sections,
        is_64bit,
    })
}

#[no_mangle]
pub extern "C" fn free_str(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}