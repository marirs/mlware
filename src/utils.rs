use crate::Result;
use maplit::hashmap;
use std::{io::Read, path::Path};

/// Loads a file and returns the buffer
pub fn load_file<P: AsRef<Path>>(file_name: P) -> Vec<u8> {
    let mut file = std::fs::File::open(file_name).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    data
}

pub fn align(value: &u64, align_on: &u64) -> u64 {
    if align_on > &0u64 && value % align_on > 0 {
        value + (align_on - (value % align_on))
    } else {
        *value
    }
}

pub fn hashing_transform(n_features: u32, data: &[Vec<(&[u8], f64)>]) -> Result<Vec<f64>> {
    let mut indices = vec![];
    let mut indptr = vec![0];
    let mut values = vec![];
    let mut size = 0;
    let error_margin = f64::EPSILON;

    for x in data {
        for (f, v) in x {
            if (v - 0.0_f64).abs() < error_margin {
                continue;
            }
            let h = murmur3::murmur3_32(&mut std::io::Cursor::new(f), 0)? as i32;
            if h == -2147483648 {
                indices.push((2147483647 - (n_features - 1)) as u32 % n_features);
            } else {
                indices.push((h as i32).abs() as u32 % n_features);
            }
            let value = v * (((if h >= 0 { 1 } else { 0 }) * 2 - 1) as f64);
            values.push(value);
            size += 1;
        }
        indptr.push(size);
    }
    let mut res = vec![0.0; n_features as usize];
    if let Some(i) = indptr.windows(2).next() {
        for ii in i[0]..i[1] {
            res[indices[ii] as usize] += values[ii];
        }
    }
    Ok(res)
}

pub fn hasher_bytes(width: u32, data: &[u8]) -> Result<Vec<f64>> {
    hashing_transform(width, &vec![vec![(data, 1.0)]])
}

pub fn hasher_bytes_vec(width: u32, data: &Vec<&[u8]>) -> Result<Vec<f64>> {
    hashing_transform(width, &vec![data.iter().map(|s| (*s, 1.0)).collect()])
}

pub fn hasher_bytes_u32_pairs(width: u32, data: &[(&[u8], u32)]) -> Result<Vec<f64>> {
    hashing_transform(
        width,
        &[data.iter().map(|(s, i)| (*s, *i as f64)).collect()],
    )
}

pub fn hasher_bytes_f64_pairs(width: u32, data: &Vec<(&[u8], f64)>) -> Result<Vec<f64>> {
    hashing_transform(width, &[data.iter().map(|(s, i)| (*s, *i)).collect()])
}

/// Calculates the entropy for the given buffer
pub fn entropy(data: &[u8]) -> f64 {
    let mut frequencies = vec![0; 256];
    for x in data {
        frequencies[*x as usize] += 1;
    }
    let mut entropy = 0.0;
    for p in frequencies {
        if p > 0 {
            let freq = p as f64 / data.len() as f64;
            entropy += freq * f64::log2(freq);
        }
    }
    -entropy
}

pub fn machine_to_string(p: u16) -> String {
    match p {
        0x0000 => "UNKNOWN".to_string(),
        0x01d3 => "AM33".to_string(),
        0x8664 => "AMD64".to_string(),
        0x01c0 => "ARM".to_string(),
        0x01c4 => "ARMNT".to_string(),
        0xaa64 => "ARM64".to_string(),
        0x0ebc => "EBC".to_string(),
        0x014c => "I386".to_string(),
        0x0200 => "IA64".to_string(),
        0x9041 => "M32R".to_string(),
        0x0266 => "MIPS16".to_string(),
        0x0366 => "MIPSFPU".to_string(),
        0x0466 => "MIPSFPU16".to_string(),
        0x01f0 => "POWERPC".to_string(),
        0x01f1 => "POWERPCFP".to_string(),
        0x0166 => "R4000".to_string(),
        0x5032 => "RISCV32".to_string(),
        0x5064 => "RISCV64".to_string(),
        0x5128 => "RISCV128".to_string(),
        0x01a2 => "SH3".to_string(),
        0x01a3 => "SH3DSP".to_string(),
        0x01a6 => "SH4".to_string(),
        0x01a8 => "SH5".to_string(),
        0x01c2 => "THUMB".to_string(),
        0x0169 => "WCEMIPSV2".to_string(),
        _ => "INVALID".to_string(),
    }
}

pub fn file_characteristics_to_strings(p: u16) -> Vec<String> {
    let mut res = vec![];
    let characteristics = hashmap! {
        0x0001 => "RELOCS_STRIPPED".to_string(),
        0x0002 => "EXECUTABLE_IMAGE".to_string(),
        0x0004 => "LINE_NUMS_STRIPPED".to_string(),
        0x0008 => "LOCAL_SYMS_STRIPPED".to_string(),
        0x0010 => "AGGRESSIVE_WS_TRIM".to_string(),
        0x0020 => "LARGE_ADDRESS_AWARE".to_string(),
        0x0080 => "BYTES_REVERSED_LO".to_string(),
        0x0100 => "CHARA_32BIT_MACHINE".to_string(),
        0x0200 => "DEBUG_STRIPPED".to_string(),
        0x0400 => "REMOVABLE_RUN_FROM_SWAP".to_string(),
        0x0800 => "NET_RUN_FROM_SWAP".to_string(),
        0x1000 => "SYSTEM".to_string(),
        0x2000 => "DLL".to_string(),
        0x3000 => "UP_SYSTEM_ONLY".to_string(),
        0x8000 => "BYTES_REVERSED_HI".to_string()
    };
    for (i, s) in characteristics {
        if i & p != 0 {
            res.push(s.clone());
        }
    }
    if res.is_empty() {
        res.push("INVALID".to_string());
    }
    res
}

pub fn subsystem_to_string(p: u16) -> String {
    match p {
        0 => "UNKNOWN".to_string(),
        1 => "NATIVE".to_string(),
        2 => "WINDOWS_GUI".to_string(),
        3 => "WINDOWS_CUI".to_string(),
        5 => "OS2_CUI".to_string(),
        7 => "POSIX_CUI".to_string(),
        8 => "NATIVE_WINDOWS".to_string(),
        9 => "WINDOWS_CE_GUI".to_string(),
        10 => "EFI_APPLICATION".to_string(),
        11 => "EFI_BOOT_SERVICE_DRIVER".to_string(),
        12 => "EFI_RUNTIME_DRIVER".to_string(),
        13 => "EFI_ROM".to_string(),
        14 => "XBOX".to_string(),
        16 => "WINDOWS_BOOT_APPLICATION".to_string(),
        _ => "INVALID".to_string(),
    }
}

pub fn dll_characteristics_to_strings(p: u16) -> Vec<String> {
    let mut res = vec![];
    let characteristics = hashmap! {
        0x0020 => "HIGH_ENTROPY_VA".to_string(),
        0x0040 => "DYNAMIC_BASE".to_string(),
        0x0080 => "FORCE_INTEGRITY".to_string(),
        0x0100 => "NX_COMPAT".to_string(),
        0x0200 => "NO_ISOLATION".to_string(),
        0x0400 => "NO_SEH".to_string(),
        0x0800 => "NO_BIND".to_string(),
        0x1000 => "APPCONTAINER".to_string(),
        0x2000 => "WDM_DRIVER".to_string(),
        0x3000 => "GUARD_CF".to_string(),
        0x8000 => "TERMINAL_SERVER_AWARE".to_string()
    };
    for (i, s) in characteristics {
        if i & p != 0 {
            res.push(s.clone());
        }
    }
    if res.is_empty() {
        res.push("INVALID".to_string());
    }
    res
}

pub fn magic_to_string(p: u16) -> String {
    match p {
        0x010b => "PE32".to_string(),
        0x020b => "PE32_PLUS".to_string(),
        _ => "INVALID".to_string(),
    }
}

pub fn section_characteristics_to_strings(p: u32) -> Vec<String> {
    let mut res = vec![];
    let characteristics = hashmap! {
        0x00000008 => "TYPE_NO_PAD".to_string(),
        0x00000020 => "CNT_CODE".to_string(),
        0x00000040 => "CNT_INITIALIZED_DATA".to_string(),
        0x00000080 => "CNT_UNINITIALIZED_DATA".to_string(),
        0x00000100 => "LNK_OTHER".to_string(),
        0x00000200 => "LNK_INFO".to_string(),
        0x00000800 => "LNK_REMOVE".to_string(),
        0x00001000 => "LNK_COMDAT".to_string(),
        0x00008000 => "GPREL".to_string(),
        0x00010000 => "MEM_PURGEABLE".to_string(),
        0x00020000 => "MEM_16BIT".to_string(),
        0x00040000 => "MEM_LOCKED".to_string(),
        0x00080000 => "MEM_PRELOAD".to_string(),
        0x00100000 => "ALIGN_1BYTES".to_string(),
        0x00200000 => "ALIGN_2BYTES".to_string(),
        0x00300000 => "ALIGN_4BYTES".to_string(),
        0x00400000 => "ALIGN_8BYTES".to_string(),
        0x00500000 => "ALIGN_16BYTES".to_string(),
        0x00600000 => "ALIGN_32BYTES".to_string(),
        0x00700000 => "ALIGN_64BYTES".to_string(),
        0x00800000 => "ALIGN_128BYTES".to_string(),
        0x00900000 => "ALIGN_256BYTES".to_string(),
        0x00a00000 => "ALIGN_512BYTES".to_string(),
        0x00b00000 => "ALIGN_1024BYTES".to_string(),
        0x00c00000 => "ALIGN_2048BYTES".to_string(),
        0x00d00000 => "ALIGN_4096BYTES".to_string(),
        0x00e00000 => "ALIGN_8192BYTES".to_string(),
        0x01000000 => "LNK_NRELOC_OVFL".to_string(),
        0x02000000 => "MEM_DISCARDABLE".to_string(),
        0x04000000 => "MEM_NOT_CACHED".to_string(),
        0x08000000 => "MEM_NOT_PAGED".to_string(),
        0x10000000 => "MEM_SHARED".to_string(),
        0x20000000 => "MEM_EXECUTE".to_string(),
        0x40000000 => "MEM_READ".to_string(),
        0x80000000 => "MEM_WRITE".to_string()
    };
    for (i, s) in characteristics {
        if i & p != 0 {
            res.push(s.clone());
        }
    }
    if res.is_empty() {
        res.push("INVALID".to_string());
    }
    res
}
