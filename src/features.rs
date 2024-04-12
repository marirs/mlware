use crate::{
    utils::{
        align, dll_characteristics_to_strings, entropy, file_characteristics_to_strings,
        hasher_bytes, hasher_bytes_f64_pairs, hasher_bytes_u32_pairs, hasher_bytes_vec,
        machine_to_string, magic_to_string, section_characteristics_to_strings,
        subsystem_to_string,
    },
    Result,
};
use maplit::hashmap;
use pelite::{
    image::{
        IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER32, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_WRITE,
    },
    pe32::Pe as Pe32,
    pe64::Pe as Pe64,
    PeFile,
};
use regex::bytes::Regex;
use std::{collections::HashMap, mem::size_of, str::from_utf8};

#[derive(Debug)]
pub enum Feature {
    ByteHistogram(ByteHistogramFeature),
    ByteEntropyHistogram(ByteEntropyHistogramFeature),
    StringExtractor(StringExtractorFeature),
    GeneralFileInfo(GeneralFileInfoFeature),
    HeaderFileInfo(HeaderFileInfoFeature),
    SectionInfo(SectionInfoFeature),
    ImportsInfo(ImportsInfoFeature),
    ExportsInfo(ExportsInfoFeature),
    DataDirectory(DataDirectoryFeature),
}

impl Feature {
    pub fn feature_vector(&self, bytes: &[u8], pe: &Option<PeFile>) -> Result<Vec<f64>> {
        match self {
            Feature::ByteHistogram(b) => b.process_raw_features(&b.raw_features(bytes)?),
            Feature::ByteEntropyHistogram(b) => b.process_raw_features(&b.raw_features(bytes)?),
            Feature::StringExtractor(b) => b.process_raw_features(&b.raw_features(bytes)?),
            Feature::GeneralFileInfo(b) => b.process_raw_features(&b.raw_features(bytes, pe)?),
            Feature::HeaderFileInfo(b) => b.process_raw_features(&b.raw_features(bytes, pe)?),
            Feature::SectionInfo(b) => b.process_raw_features(&b.raw_features(bytes, pe)?),
            Feature::ImportsInfo(b) => b.process_raw_features(&b.raw_features(bytes, pe)?),
            Feature::ExportsInfo(b) => b.process_raw_features(&b.raw_features(bytes, pe)?),
            Feature::DataDirectory(b) => b.process_raw_features(&b.raw_features(bytes, pe)?),
        }
    }

    pub fn dim(&self) -> u32 {
        match self {
            Feature::ByteHistogram(b) => b.dim,
            Feature::ByteEntropyHistogram(b) => b.dim,
            Feature::StringExtractor(b) => b.dim,
            Feature::GeneralFileInfo(b) => b.dim,
            Feature::HeaderFileInfo(b) => b.dim,
            Feature::SectionInfo(b) => b.dim,
            Feature::ImportsInfo(b) => b.dim,
            Feature::ExportsInfo(b) => b.dim,
            Feature::DataDirectory(b) => b.dim,
        }
    }
}

#[derive(Debug)]
pub struct PeFeaturesExtractor {
    dim: u32,
    features: Vec<Feature>,
}

impl PeFeaturesExtractor {
    pub fn new() -> Result<PeFeaturesExtractor> {
        let mut res = PeFeaturesExtractor {
            dim: 0,
            features: vec![
                Feature::ByteHistogram(ByteHistogramFeature::new()),
                Feature::ByteEntropyHistogram(ByteEntropyHistogramFeature::new()),
                Feature::StringExtractor(StringExtractorFeature::new()?),
                Feature::GeneralFileInfo(GeneralFileInfoFeature::new()),
                Feature::HeaderFileInfo(HeaderFileInfoFeature::new()),
                Feature::SectionInfo(SectionInfoFeature::new()),
                Feature::ImportsInfo(ImportsInfoFeature::new()),
                Feature::ExportsInfo(ExportsInfoFeature::new()),
                Feature::DataDirectory(DataDirectoryFeature::new()),
            ],
        };
        res.dim = res
            .features
            .iter()
            .map(|s| s.dim())
            .collect::<Vec<u32>>()
            .iter()
            .sum();
        Ok(res)
    }

    pub fn feature_vector(&self, bytes: &[u8]) -> Result<Vec<f64>> {
        let mut res = vec![];
        let pe = match PeFile::from_bytes(bytes) {
            Ok(s) => Some(s),
            _ => None,
        };
        for f in &self.features {
            res.extend(f.feature_vector(bytes, &pe)?);
        }
        Ok(res)
    }
}

#[derive(Debug)]
pub struct ByteHistogramFeature {
    _name: String,
    dim: u32,
}

impl ByteHistogramFeature {
    pub fn new() -> ByteHistogramFeature {
        ByteHistogramFeature {
            _name: String::from("histogram"),
            dim: 256,
        }
    }

    pub fn raw_features(&self, bytes: &[u8]) -> Result<Vec<u32>> {
        let mut res = vec![0; 256];
        for b in bytes {
            res[*b as usize] += 1;
        }
        Ok(res)
    }

    pub fn process_raw_features(&self, raw_obj: &[u32]) -> Result<Vec<f64>> {
        let sum: u32 = raw_obj.iter().sum();
        let normalized: Vec<f64> = raw_obj.iter().map(|m| *m as f64 / sum as f64).collect();
        Ok(normalized)
    }
}

#[derive(Debug)]
pub struct ByteEntropyHistogramFeature {
    _name: String,
    dim: u32,
    window: usize,
    step: usize,
}

impl ByteEntropyHistogramFeature {
    fn entropy_bin_counts(&self, block: &[u8]) -> (u32, Vec<usize>) {
        let mut c = vec![0; 16];
        for b in block {
            c[(b >> 4) as usize] += 1;
        }
        let p: Vec<f32> = c.iter().map(|cc| *cc as f32 / self.window as f32).collect();
        let mut h = 0.0;
        for (i, cc) in c.iter().enumerate() {
            if cc != &0 {
                h += -p[i] * f32::log2(p[i]);
            }
        }
        let mut hbin = (h * 4.0) as u32;
        if hbin == 16 {
            hbin = 15;
        }
        (hbin, c)
    }

    pub fn new() -> ByteEntropyHistogramFeature {
        ByteEntropyHistogramFeature {
            _name: String::from("byteentropy"),
            dim: 256,
            window: 2048,
            step: 1024,
        }
    }

    pub fn raw_features(&self, bytes: &[u8]) -> Result<Vec<u32>> {
        let mut res: Vec<u32> = vec![0; 256];
        let mut i = 0;
        while i + self.window < bytes.len() {
            let block = &bytes[i..i + self.window];
            let (hbin, c) = self.entropy_bin_counts(block);
            for (i, h) in c.iter().enumerate() {
                res[(hbin * 16 + i as u32) as usize] += *h as u32;
            }
            i += self.step;
        }
        Ok(res)
    }

    pub fn process_raw_features(&self, raw_obj: &[u32]) -> Result<Vec<f64>> {
        let sum: u32 = raw_obj.iter().sum();
        let normalized: Vec<f64> = raw_obj.iter().map(|m| *m as f64 / sum as f64).collect();
        Ok(normalized)
    }
}

#[derive(Debug)]
pub struct StringExtractorFeature {
    _name: String,
    dim: u32,
    allstrings: Regex,
    paths: Regex,
    urls: Regex,
    registry: Regex,
    mz: Regex,
}

impl StringExtractorFeature {
    pub fn new() -> Result<StringExtractorFeature> {
        Ok(StringExtractorFeature {
            _name: "strings".to_string(),
            dim: 1 + 1 + 1 + 96 + 1 + 1 + 1 + 1 + 1,
            allstrings: Regex::new(r"(?-u)[\x20-\x7f]{5,}")?,
            paths: Regex::new(r"(?i)c:\\")?,
            urls: Regex::new(r"(?i)https?://")?,
            registry: Regex::new(r"HKEY_")?,
            mz: Regex::new(r"MZ")?,
        })
    }
    pub fn raw_features(&self, bytes: &[u8]) -> Result<HashMap<String, Vec<f64>>> {
        let mut string_lengths = vec![];
        let mut as_shifted_string = vec![];
        let mut c = vec![0.0; 96];
        let mut allstrings_len = 0;
        for f in self.allstrings.find_iter(bytes) {
            string_lengths.push(f.as_bytes().len());
            for b in f.as_bytes() {
                as_shifted_string.push(b - 0x20);
                c[*b as usize - 0x20] += 1.0;
            }
            allstrings_len += 1;
        }
        let avlength = string_lengths.iter().sum::<usize>() as f64 / string_lengths.len() as f64;
        let csum: f64 = c.iter().sum();
        let p: Vec<f64> = c.iter().map(|cc| *cc / csum).collect();
        let h: f64 = p
            .iter()
            .map(|pp| -pp * f64::log2(*pp))
            .collect::<Vec<f64>>()
            .iter()
            .sum();
        let res = hashmap! {
            "numstrings".to_string() => vec!(allstrings_len as f64),
            "avlength".to_string() => vec!(avlength),
            "printabledist".to_string() => c,
            "printables".to_string() => vec![csum as f64],
            "entropy".to_string() => vec![h as f64],
            "paths".to_string() => vec![self.paths.find_iter(bytes).count() as f64],
            "urls".to_string() => vec![self.urls.find_iter(bytes).count() as f64],
            "registry".to_string() => vec![self.registry.find_iter(bytes).count() as f64],
            "MZ".to_string() => vec![self.mz.find_iter(bytes).count() as f64]
        };
        Ok(res)
    }

    pub fn process_raw_features(&self, raw_obj: &HashMap<String, Vec<f64>>) -> Result<Vec<f64>> {
        let mut res = vec![];
        let mut hist_divisor = raw_obj["printables"][0];
        if hist_divisor == 0.0 {
            hist_divisor = 1.0;
        }
        res.extend(&raw_obj["numstrings"]);
        res.extend(&raw_obj["avlength"]);
        res.extend(&raw_obj["printables"]);
        res.extend(raw_obj["printabledist"].iter().map(|pp| pp / hist_divisor));
        res.extend(&raw_obj["entropy"]);
        res.extend(&raw_obj["paths"]);
        res.extend(&raw_obj["urls"]);
        res.extend(&raw_obj["registry"]);
        res.extend(&raw_obj["MZ"]);
        Ok(res)
    }
}

#[derive(Debug)]
pub struct HeaderFileInfoFeature {
    _name: String,
    dim: u32,
}

impl HeaderFileInfoFeature {
    pub fn new() -> HeaderFileInfoFeature {
        HeaderFileInfoFeature {
            _name: String::from("header"),
            dim: 62,
        }
    }

    pub fn raw_features(
        &self,
        _bytes: &[u8],
        pe: &Option<PeFile>,
    ) -> Result<HashMap<String, HashMap<String, Vec<f64>>>> {
        let res = match pe {
            None => hashmap! {
                "coff".to_string() => hashmap!{
                    "timestamp".to_string() => vec![0.0],
                    "machine".to_string() => vec![0.0; 10],
                    "characteristics".to_string() => vec![0.0; 10],
                },
                "optional".to_string() => hashmap!{
                    "subsystem".to_string() => vec![0.0; 10],
                    "dll_characteristics".to_string() => vec![0.0; 10],
                    "magic".to_string() => vec![0.0; 10],
                    "major_image_version".to_string() => vec![0.0],
                    "minor_image_version".to_string() => vec![0.0],
                    "major_linker_version".to_string() => vec![0.0],
                    "minor_linker_version".to_string() => vec![0.0],
                    "major_operating_system_version".to_string() => vec![0.0],
                    "minor_operating_system_version".to_string() => vec![0.0],
                    "major_subsystem_version".to_string() => vec![0.0],
                    "minor_subsystem_version".to_string() => vec![0.0],
                    "sizeof_code".to_string() => vec![0.0],
                    "sizeof_headers".to_string() => vec![0.0],
                    "sizeof_heap_commit".to_string() => vec![0.0]
                }
            },
            Some(PeFile::T32(pe)) => {
                let characteristics =
                    file_characteristics_to_strings(pe.file_header().Characteristics);
                let characteristics_bytes = characteristics.iter().map(|s| s.as_bytes()).collect();
                let dll_characteristics =
                    dll_characteristics_to_strings(pe.optional_header().DllCharacteristics);
                let dll_characteristics_bytes =
                    dll_characteristics.iter().map(|s| s.as_bytes()).collect();
                hashmap! {
                    "coff".to_string() => hashmap!{
                        "timestamp".to_string() => vec![pe.file_header().TimeDateStamp as f64],
                        "machine".to_string() => hasher_bytes(10, machine_to_string(pe.file_header().Machine).as_bytes())?,
                        "characteristics".to_string() => hasher_bytes_vec(10, &characteristics_bytes)?
                    },
                    "optional".to_string() => hashmap!{
                        "subsystem".to_string() => hasher_bytes(10, subsystem_to_string(pe.optional_header().Subsystem).as_bytes())?,
                        "dll_characteristics".to_string() => hasher_bytes_vec(10, &dll_characteristics_bytes)?,
                        "magic".to_string() => hasher_bytes(10, magic_to_string(pe.optional_header().Magic).as_bytes())?,
                        "major_image_version".to_string() => vec![pe.optional_header().ImageVersion.Major as f64],
                        "minor_image_version".to_string() => vec![pe.optional_header().ImageVersion.Minor as f64],
                        "major_linker_version".to_string() => vec![pe.optional_header().LinkerVersion.Major as f64],
                        "minor_linker_version".to_string() => vec![pe.optional_header().LinkerVersion.Minor as f64],
                        "major_operating_system_version".to_string() => vec![pe.optional_header().OperatingSystemVersion.Major as f64],
                        "minor_operating_system_version".to_string() => vec![pe.optional_header().OperatingSystemVersion.Minor as f64],
                        "major_subsystem_version".to_string() => vec![pe.optional_header().SubsystemVersion.Major as f64],
                        "minor_subsystem_version".to_string() => vec![pe.optional_header().SubsystemVersion.Minor as f64],
                        "sizeof_code".to_string() => vec![pe.optional_header().SizeOfCode as f64],
                        "sizeof_headers".to_string() => vec![pe.optional_header().SizeOfHeaders as f64],
                        "sizeof_heap_commit".to_string() => vec![pe.optional_header().SizeOfHeapCommit as f64]
                    }
                }
            }
            Some(PeFile::T64(pe)) => {
                let characteristics =
                    file_characteristics_to_strings(pe.file_header().Characteristics);
                let characteristics_bytes = characteristics.iter().map(|s| s.as_bytes()).collect();
                let dll_characteristics =
                    dll_characteristics_to_strings(pe.optional_header().DllCharacteristics);
                let dll_characteristics_bytes =
                    dll_characteristics.iter().map(|s| s.as_bytes()).collect();
                hashmap! {
                    "coff".to_string() => hashmap!{
                        "timestamp".to_string() => vec![pe.file_header().TimeDateStamp as f64],
                        "machine".to_string() => hasher_bytes(10, machine_to_string(pe.file_header().Machine).as_bytes())?,
                        "characteristics".to_string() => hasher_bytes_vec(10, &characteristics_bytes)?
                    },
                    "optional".to_string() => hashmap!{
                        "subsystem".to_string() => hasher_bytes(10, subsystem_to_string(pe.optional_header().Subsystem).as_bytes())?,
                        "dll_characteristics".to_string() => hasher_bytes_vec(10, &dll_characteristics_bytes)?,
                        "magic".to_string() => hasher_bytes(10, magic_to_string(pe.optional_header().Magic).as_bytes())?,
                        "major_image_version".to_string() => vec![pe.optional_header().ImageVersion.Major as f64],
                        "minor_image_version".to_string() => vec![pe.optional_header().ImageVersion.Minor as f64],
                        "major_linker_version".to_string() => vec![pe.optional_header().LinkerVersion.Major as f64],
                        "minor_linker_version".to_string() => vec![pe.optional_header().LinkerVersion.Minor as f64],
                        "major_operating_system_version".to_string() => vec![pe.optional_header().OperatingSystemVersion.Major as f64],
                        "minor_operating_system_version".to_string() => vec![pe.optional_header().OperatingSystemVersion.Minor as f64],
                        "major_subsystem_version".to_string() => vec![pe.optional_header().SubsystemVersion.Major as f64],
                        "minor_subsystem_version".to_string() => vec![pe.optional_header().SubsystemVersion.Minor as f64],
                        "sizeof_code".to_string() => vec![pe.optional_header().SizeOfCode as f64],
                        "sizeof_headers".to_string() => vec![pe.optional_header().SizeOfHeaders as f64],
                        "sizeof_heap_commit".to_string() => vec![pe.optional_header().SizeOfHeapCommit as f64]
                    }
                }
            }
        };
        Ok(res)
    }

    pub fn process_raw_features(
        &self,
        raw_obj: &HashMap<String, HashMap<String, Vec<f64>>>,
    ) -> Result<Vec<f64>> {
        let mut res = vec![];
        res.extend(raw_obj["coff"]["timestamp"].clone());
        res.extend(raw_obj["coff"]["machine"].clone());
        res.extend(raw_obj["coff"]["characteristics"].clone());
        res.extend(raw_obj["optional"]["subsystem"].clone());
        res.extend(raw_obj["optional"]["dll_characteristics"].clone());
        res.extend(raw_obj["optional"]["magic"].clone());
        res.extend(raw_obj["optional"]["major_image_version"].clone());
        res.extend(raw_obj["optional"]["minor_image_version"].clone());
        res.extend(raw_obj["optional"]["major_linker_version"].clone());
        res.extend(raw_obj["optional"]["minor_linker_version"].clone());
        res.extend(raw_obj["optional"]["major_operating_system_version"].clone());
        res.extend(raw_obj["optional"]["minor_operating_system_version"].clone());
        res.extend(raw_obj["optional"]["major_subsystem_version"].clone());
        res.extend(raw_obj["optional"]["minor_subsystem_version"].clone());
        res.extend(raw_obj["optional"]["sizeof_code"].clone());
        res.extend(raw_obj["optional"]["sizeof_headers"].clone());
        res.extend(raw_obj["optional"]["sizeof_heap_commit"].clone());
        Ok(res)
    }
}

#[derive(Debug)]
pub struct GeneralFileInfoFeature {
    _name: String,
    dim: u32,
}

impl GeneralFileInfoFeature {
    fn get_pe32_virtual_size(&self, pe: &pelite::pe32::PeFile) -> usize {
        let mut res = 0;
        res += pe.dos_header().e_lfanew as usize;
        res += size_of::<IMAGE_FILE_HEADER>();
        res += size_of::<IMAGE_OPTIONAL_HEADER32>();
        for s in pe.section_headers() {
            res = res.max(s.virtual_range().end as usize);
        }
        res = align(
            &(res as u64),
            &(pe.optional_header().SectionAlignment as u64),
        ) as usize;
        res
    }

    fn get_pe64_virtual_size(&self, pe: &pelite::pe64::PeFile) -> usize {
        let mut res = 0;
        res += pe.dos_header().e_lfanew as usize;
        res += size_of::<IMAGE_FILE_HEADER>();
        res += size_of::<IMAGE_OPTIONAL_HEADER32>();
        for s in pe.section_headers() {
            res = res.max(s.virtual_range().end as usize);
        }
        res = align(
            &(res as u64),
            &(pe.optional_header().SectionAlignment as u64),
        ) as usize;
        res
    }

    fn get_pe32_imports_count(&self, pe: &pelite::pe32::PeFile) -> Result<usize> {
        let mut res = 0;
        if let Ok(imp) = pe.imports() {
            for desc in imp {
                if let Ok(iat) = desc.iat() {
                    if let Ok(int) = desc.int() {
                        for (_va, _) in Iterator::zip(iat, int) {
                            res += 1;
                        }
                    }
                }
            }
        }
        Ok(res)
    }

    fn get_pe64_imports_count(&self, pe: &pelite::pe64::PeFile) -> Result<usize> {
        let mut res = 0;
        if let Ok(imp) = pe.imports() {
            for desc in imp {
                if let Ok(iat) = desc.iat() {
                    if let Ok(int) = desc.int() {
                        for (_va, _) in Iterator::zip(iat, int) {
                            res += 1;
                        }
                    }
                }
            }
        }
        Ok(res)
    }

    pub fn new() -> GeneralFileInfoFeature {
        GeneralFileInfoFeature {
            _name: String::from("general"),
            dim: 10,
        }
    }

    pub fn raw_features(
        &self,
        bytes: &[u8],
        pe: &Option<PeFile>,
    ) -> Result<HashMap<String, Vec<f64>>> {
        let res = match pe {
            None => hashmap! {
                "size".to_string() => vec![bytes.len() as f64],
                "vsize".to_string() => vec![0.0],
                "has_debug".to_string() => vec![0.0],
                "exports".to_string() => vec![0.0],
                "imports".to_string() => vec![0.0],
                "has_relocations".to_string() => vec![0.0],
                "has_resources".to_string() => vec![0.0],
                "has_signature".to_string() => vec![0.0],
                "has_tls".to_string() => vec![0.0],
                "symbols".to_string() => vec![0.0]
            },
            Some(PeFile::T32(pe)) => hashmap! {
                "size".to_string() => vec![bytes.len() as f64],
                "vsize".to_string() => vec![self.get_pe32_virtual_size(pe) as f64],
                "has_debug".to_string() => vec![if pe.debug().is_ok() {1.0} else {0.0}],
                "exports".to_string() => {
                    match pe.exports(){
                        Err(pelite::Error::Null) => vec![0.0],
                        Ok(p) => {
                            if let Ok(by) = p.by(){
                                vec![by.iter().count() as f64]
                            }else{
                                vec![0.0_f64]
                            }
                        },
                        Err(e) => return Err(crate::error::Error::PeLite(e))
                    }
                },
                "imports".to_string() => vec![self.get_pe32_imports_count(pe)? as f64],
                "has_relocations".to_string() => vec![if pe.base_relocs().is_ok() {1.0} else {0.0}],
                "has_resources".to_string() => vec![if pe.resources().is_ok() {1.0} else {0.0}],
                "has_signature".to_string() => vec![if pe.security().is_ok() {1.0} else {0.0}],
                "has_tls".to_string() => vec![if pe.tls().is_ok() {1.0} else {0.0}],
                "symbols".to_string() => vec![pe.file_header().NumberOfSymbols as f64]
            },
            Some(PeFile::T64(pe)) => hashmap! {
                "size".to_string() => vec![bytes.len() as f64],
                "vsize".to_string() => vec![self.get_pe64_virtual_size(pe) as f64],
                "has_debug".to_string() => vec![if pe.debug().is_ok() {1.0} else {0.0}],
                "exports".to_string() => {
                    match pe.exports(){
                        Err(pelite::Error::Null) => vec![0.0],
                        Ok(p) => {
                            if let Ok(by) = p.by(){
                                vec![by.iter().count() as f64]
                            }else{
                                vec![0.0_f64]
                            }
                        },
                        Err(e) => return Err(crate::error::Error::PeLite(e))
                    }
                },
                "imports".to_string() => vec![self.get_pe64_imports_count(pe)? as f64],
                "has_relocations".to_string() => vec![if pe.base_relocs().is_ok() {1.0} else {0.0}],
                "has_resources".to_string() => vec![if pe.resources().is_ok() {1.0} else {0.0}],
                "has_signature".to_string() => vec![if pe.security().is_ok() {1.0} else {0.0}],
                "has_tls".to_string() => vec![if pe.tls().is_ok() {1.0} else {0.0}],
                "symbols".to_string() => vec![pe.file_header().NumberOfSymbols as f64]
            },
        };
        Ok(res)
    }

    pub fn process_raw_features(&self, raw_obj: &HashMap<String, Vec<f64>>) -> Result<Vec<f64>> {
        let mut res = vec![];
        res.extend(raw_obj["size"].clone());
        res.extend(raw_obj["vsize"].clone());
        res.extend(raw_obj["has_debug"].clone());
        res.extend(raw_obj["exports"].clone());
        res.extend(raw_obj["imports"].clone());
        res.extend(raw_obj["has_relocations"].clone());
        res.extend(raw_obj["has_resources"].clone());
        res.extend(raw_obj["has_signature"].clone());
        res.extend(raw_obj["has_tls"].clone());
        res.extend(raw_obj["symbols"].clone());
        Ok(res)
    }
}

//section info
#[derive(Debug)]
pub struct SectionInfoFeature {
    _name: String,
    dim: u32,
}

impl SectionInfoFeature {
    pub fn new() -> SectionInfoFeature {
        SectionInfoFeature {
            _name: String::from("section"),
            dim: 5 + 50 + 50 + 50 + 50 + 50,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn raw_features(
        &self,
        bytes: &[u8],
        pe: &Option<PeFile>,
    ) -> Result<HashMap<String, Vec<HashMap<String, Vec<f64>>>>> {
        let res = match pe {
            None => hashmap! {
                "entry".to_string() => vec![hashmap!{
                    "name".to_string() => hasher_bytes(50, b"")?,
                    "characteristics".to_string() => vec![0.0; 50]
                }],
                "sections".to_string() => vec![hashmap!{
                    "sections_len".to_string() => vec![0.0],
                    "nonzero_sections_len".to_string() => vec![0.0],
                    "empty_named_sections_len".to_string() => vec![0.0],
                    "rx_sections_len".to_string() => vec![0.0],
                    "w_sections_len".to_string() => vec![0.0],
                    "section_sizes".to_string() => hasher_bytes_u32_pairs(50, &[])?,
                    "section_entropies".to_string() => hasher_bytes_f64_pairs(50, &[])?,
                    "section_vsizes".to_string() => hasher_bytes_u32_pairs(50, &[])?
                }]
            },
            Some(PeFile::T32(pe)) => {
                let entry_point_address = pe.optional_header().AddressOfEntryPoint;
                let mut res = hashmap! {
                    "entry".to_string() => vec![],
                    "sections".to_string() => vec![]
                };
                let mut sizes = vec![];
                let mut entropies = vec![];
                let mut vsizes = vec![];
                let mut non_zero_sections_len = 0;
                let mut empty_named_sections_len = 0;
                let mut rx_sections_len = 0;
                let mut w_sections_len = 0;
                for s in pe.section_headers() {
                    if s.VirtualAddress <= entry_point_address
                        && entry_point_address < s.VirtualAddress + s.VirtualSize
                    {
                        if let Some(ss) = res.get_mut("entry") {
                            let section_characteristics =
                                section_characteristics_to_strings(s.Characteristics);
                            let section_characteristics_bytes = section_characteristics
                                .iter()
                                .map(|s| s.as_bytes())
                                .collect();
                            ss.push(hashmap!{
                                "name".to_string() => hasher_bytes(50, from_utf8(&s.Name)?.trim_matches(char::from(0)).as_bytes())?,
                                "characteristics".to_string() => hasher_bytes_vec(50, &section_characteristics_bytes)?,
                            });
                        }
                    }
                    if s.SizeOfRawData != 0 {
                        non_zero_sections_len += 1;
                    }
                    if s.Name[0] == 0 {
                        empty_named_sections_len += 1;
                    }
                    if s.Characteristics & IMAGE_SCN_MEM_READ != 0
                        && s.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                    {
                        rx_sections_len += 1;
                    }
                    if s.Characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                        w_sections_len += 1;
                    }
                    sizes.push((
                        from_utf8(&s.Name)?.trim_matches(char::from(0)).as_bytes(),
                        s.SizeOfRawData,
                    ));
                    entropies.push((
                        from_utf8(&s.Name)?.trim_matches(char::from(0)).as_bytes(),
                        entropy(
                            &bytes[s.PointerToRawData as usize
                                ..(s.PointerToRawData + s.SizeOfRawData) as usize],
                        ),
                    ));
                    vsizes.push((
                        from_utf8(&s.Name)?.trim_matches(char::from(0)).as_bytes(),
                        s.VirtualSize,
                    ));
                }
                if let Some(s) = res.get_mut("sections") {
                    s.push(hashmap!{
                        "sections_len".to_string() => vec![pe.section_headers().iter().count() as f64],
                        "nonzero_sections_len".to_string() => vec![non_zero_sections_len as f64],
                        "empty_named_sections_len".to_string() => vec![empty_named_sections_len as f64],
                        "rx_sections_len".to_string() => vec![rx_sections_len as f64],
                        "w_sections_len".to_string() => vec![w_sections_len as f64],
                        "section_sizes".to_string() => hasher_bytes_u32_pairs(50, &sizes)?,
                        "section_entropies".to_string() => hasher_bytes_f64_pairs(50, &entropies)?,
                        "section_vsizes".to_string() => hasher_bytes_u32_pairs(50, &vsizes)?
                    });
                }
                res
            }
            Some(PeFile::T64(pe)) => {
                let entry_point_address = pe.optional_header().AddressOfEntryPoint;
                let mut res = hashmap! {
                    "entry".to_string() => vec![],
                    "sections".to_string() => vec![]
                };
                let mut sizes = vec![];
                let mut entropies = vec![];
                let mut vsizes = vec![];
                let mut non_zero_sections_len = 0;
                let mut empty_named_sections_len = 0;
                let mut rx_sections_len = 0;
                let mut w_sections_len = 0;
                for s in pe.section_headers() {
                    if s.VirtualAddress <= entry_point_address
                        && entry_point_address < s.VirtualAddress + s.VirtualSize
                    {
                        if let Some(ss) = res.get_mut("entry") {
                            let section_characteristics =
                                section_characteristics_to_strings(s.Characteristics);
                            let section_characteristics_bytes = section_characteristics
                                .iter()
                                .map(|s| s.as_bytes())
                                .collect();
                            ss.push(hashmap!{
                                "name".to_string() => hasher_bytes(50, from_utf8(&s.Name)?.trim_matches(char::from(0)).as_bytes())?,
                                "characteristics".to_string() => hasher_bytes_vec(50, &section_characteristics_bytes)?,
                            });
                        }
                    }
                    if s.SizeOfRawData != 0 {
                        non_zero_sections_len += 1;
                    }
                    if s.Name[0] == 0 {
                        empty_named_sections_len += 1;
                    }
                    if s.Characteristics & IMAGE_SCN_MEM_READ != 0
                        && s.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                    {
                        rx_sections_len += 1;
                    }
                    if s.Characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                        w_sections_len += 1;
                    }
                    sizes.push((
                        from_utf8(&s.Name)?.trim_matches(char::from(0)).as_bytes(),
                        s.SizeOfRawData,
                    ));
                    entropies.push((
                        from_utf8(&s.Name)?.trim_matches(char::from(0)).as_bytes(),
                        entropy(
                            &bytes[s.PointerToRawData as usize
                                ..(s.PointerToRawData + s.SizeOfRawData) as usize],
                        ),
                    ));
                    vsizes.push((
                        from_utf8(&s.Name)?.trim_matches(char::from(0)).as_bytes(),
                        s.VirtualSize,
                    ));
                }
                if let Some(s) = res.get_mut("sections") {
                    s.push(hashmap!{
                        "sections_len".to_string() => vec![pe.section_headers().iter().count() as f64],
                        "nonzero_sections_len".to_string() => vec![non_zero_sections_len as f64],
                        "empty_named_sections_len".to_string() => vec![empty_named_sections_len as f64],
                        "rx_sections_len".to_string() => vec![rx_sections_len as f64],
                        "w_sections_len".to_string() => vec![w_sections_len as f64],
                        "section_sizes".to_string() => hasher_bytes_u32_pairs(50, &sizes)?,
                        "section_entropies".to_string() => hasher_bytes_f64_pairs(50, &entropies)?,
                        "section_vsizes".to_string() => hasher_bytes_u32_pairs(50, &vsizes)?
                    });
                }
                res
            }
        };
        Ok(res)
    }

    pub fn process_raw_features(
        &self,
        raw_obj: &HashMap<String, Vec<HashMap<String, Vec<f64>>>>,
    ) -> Result<Vec<f64>> {
        let mut res = vec![];
        res.extend(raw_obj["sections"][0]["sections_len"].clone());
        res.extend(raw_obj["sections"][0]["nonzero_sections_len"].clone());
        res.extend(raw_obj["sections"][0]["empty_named_sections_len"].clone());
        res.extend(raw_obj["sections"][0]["rx_sections_len"].clone());
        res.extend(raw_obj["sections"][0]["w_sections_len"].clone());
        res.extend(raw_obj["sections"][0]["section_sizes"].clone());
        res.extend(raw_obj["sections"][0]["section_entropies"].clone());
        res.extend(raw_obj["sections"][0]["section_vsizes"].clone());
        res.extend(raw_obj["entry"][0]["name"].clone());
        res.extend(raw_obj["entry"][0]["characteristics"].clone());
        Ok(res)
    }
}

//ImportsInfoFeature
#[derive(Debug)]
pub struct ImportsInfoFeature {
    _name: String,
    dim: u32,
}

impl ImportsInfoFeature {
    pub fn new() -> ImportsInfoFeature {
        ImportsInfoFeature {
            _name: String::from("imports"),
            dim: 1280,
        }
    }

    pub fn raw_features(
        &self,
        _bytes: &[u8],
        pe: &Option<PeFile>,
    ) -> Result<HashMap<String, Vec<String>>> {
        let res = match pe {
            None => hashmap! {},
            Some(PeFile::T32(pe)) => {
                let mut res = hashmap! {};
                if let Ok(imp) = pe.imports() {
                    for desc in imp {
                        if let Ok(dll_name) = desc.dll_name() {
                            let mut aa = vec![];
                            if let Ok(iat) = desc.iat() {
                                if let Ok(int) = desc.int() {
                                    for (_va, import) in Iterator::zip(iat, int) {
                                        if let Ok(pelite::pe32::imports::Import::ByName {
                                            hint: _h,
                                            name: n,
                                        }) = import
                                        {
                                            aa.push(n.to_string());
                                        }
                                    }
                                }
                            }
                            res.insert(dll_name.to_string(), aa);
                        }
                    }
                }
                res
            }
            Some(PeFile::T64(pe)) => {
                let mut res = hashmap! {};
                if let Ok(imp) = pe.imports() {
                    for desc in imp {
                        if let Ok(dll_name) = desc.dll_name() {
                            let mut aa = vec![];
                            if let Ok(iat) = desc.iat() {
                                if let Ok(int) = desc.int() {
                                    for (_va, import) in Iterator::zip(iat, int) {
                                        if let Ok(pelite::pe32::imports::Import::ByName {
                                            hint: _h,
                                            name: n,
                                        }) = import
                                        {
                                            aa.push(n.to_string());
                                        }
                                    }
                                }
                            }
                            res.insert(dll_name.to_string(), aa);
                        }
                    }
                }
                res
            }
        };
        Ok(res)
    }

    pub fn process_raw_features(&self, raw_obj: &HashMap<String, Vec<String>>) -> Result<Vec<f64>> {
        let libraries: Vec<&[u8]> = raw_obj.iter().map(|(l, _)| l.as_bytes()).collect();
        let libraries_hashed = hasher_bytes_vec(256, &libraries)?;
        let mut imports = vec![];
        for (l, s) in raw_obj {
            for ss in s {
                imports.push(format!("{}:{}", l, ss).to_string());
            }
        }
        let imports_hashed =
            hasher_bytes_vec(1024, &imports.iter().map(|s| s.as_bytes()).collect())?;
        let mut res = vec![];
        res.extend(libraries_hashed);
        res.extend(imports_hashed);
        Ok(res)
    }
}

//ExportsInfoFeature
#[derive(Debug)]
pub struct ExportsInfoFeature {
    _name: String,
    dim: u32,
}

impl ExportsInfoFeature {
    pub fn new() -> ExportsInfoFeature {
        ExportsInfoFeature {
            _name: String::from("exports"),
            dim: 128,
        }
    }

    pub fn raw_features(&self, _bytes: &[u8], pe: &Option<PeFile>) -> Result<Vec<String>> {
        let res = match pe {
            None => vec![],
            Some(PeFile::T32(pe)) => {
                let mut res = vec![];
                let exports = match pe.exports() {
                    Ok(s) => s,
                    Err(pelite::Error::Null) => return Ok(res),
                    Err(e) => return Err(crate::error::Error::PeLite(e)),
                };
                if let Ok(by) = exports.by() {
                    for result in by.iter_names() {
                        if let (Ok(name), Ok(_)) = result {
                            res.push(name.to_string());
                        }
                    }
                }
                res
            }
            Some(PeFile::T64(pe)) => {
                let mut res = vec![];
                let exports = match pe.exports() {
                    Ok(s) => s,
                    Err(pelite::Error::Null) => return Ok(res),
                    Err(e) => return Err(crate::error::Error::PeLite(e)),
                };
                if let Ok(by) = exports.by() {
                    for result in by.iter_names() {
                        if let (Ok(name), Ok(_)) = result {
                            res.push(name.to_string());
                        }
                    }
                }
                res
            }
        };
        Ok(res)
    }

    pub fn process_raw_features(&self, raw_obj: &[String]) -> Result<Vec<f64>> {
        let vv = raw_obj.iter().map(|s| s.as_bytes()).collect::<Vec<&[u8]>>();
        let exports_hashed = hasher_bytes_vec(128, &vv)?;
        Ok(exports_hashed)
    }
}

//DataDirectoryFeature
#[derive(Debug)]
pub struct DataDirectoryFeature {
    _name: String,
    dim: u32,
    name_order: Vec<String>,
}

impl DataDirectoryFeature {
    pub fn new() -> DataDirectoryFeature {
        DataDirectoryFeature {
            _name: String::from("datadirectories"),
            dim: 15 * 2,
            name_order: vec![
                "EXPORT_TABLE".to_string(),
                "IMPORT_TABLE".to_string(),
                "RESOURCE_TABLE".to_string(),
                "EXCEPTION_TABLE".to_string(),
                "CERTIFICATE_TABLE".to_string(),
                "BASE_RELOCATION_TABLE".to_string(),
                "DEBUG".to_string(),
                "ARCHITECTURE".to_string(),
                "GLOBAL_PTR".to_string(),
                "TLS_TABLE".to_string(),
                "LOAD_CONFIG_TABLE".to_string(),
                "BOUND_IMPORT".to_string(),
                "IAT".to_string(),
                "DELAY_IMPORT_DESCRIPTOR".to_string(),
                "CLR_RUNTIME_HEADER".to_string(),
            ],
        }
    }

    pub fn raw_features(&self, _bytes: &[u8], pe: &Option<PeFile>) -> Result<Vec<(u32, u32)>> {
        let res = match pe {
            None => vec![],
            Some(PeFile::T32(pe)) => {
                let mut res = vec![];
                for dd in pe.data_directory() {
                    res.push((dd.VirtualAddress, dd.Size));
                }
                res
            }
            Some(PeFile::T64(pe)) => {
                let mut res = vec![];
                for dd in pe.data_directory() {
                    res.push((dd.VirtualAddress, dd.Size));
                }
                res
            }
        };
        Ok(res)
    }

    pub fn process_raw_features(&self, raw_obj: &[(u32, u32)]) -> Result<Vec<f64>> {
        let mut res = vec![0.0; 2 * self.name_order.len()];
        let mut i = 0;
        while i < raw_obj.len() {
            res[2 * i] = raw_obj[i].0 as f64;
            res[2 * i + 1] = raw_obj[i].1 as f64;
            i += 2;
        }
        Ok(res)
    }
}
