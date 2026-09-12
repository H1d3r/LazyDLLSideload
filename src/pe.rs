//! On-disk PE export walk. Offsets from Microsoft PE/COFF + winnt.h
//! `IMAGE_EXPORT_DIRECTORY`. RVA maps through max(VirtualSize, SizeOfRawData)
//! but the file byte must still sit inside SizeOfRawData.

use std::io;
use std::path::Path;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;
const IMAGE_SIZEOF_SECTION_HEADER: usize = 40;
const IMAGE_FILE_HEADER_SIZE: usize = 20;
const IMAGE_NT_HEADERS_SIGNATURE_SIZE: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub name: Option<String>,
    pub ordinal: u32,
}

#[derive(Debug)]
pub enum PeError {
    Io(io::Error),
    Truncated(&'static str),
    BadDos,
    BadPe,
    BadMagic(u16),
    BadExport(&'static str),
}

impl std::fmt::Display for PeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeError::Io(e) => write!(f, "{e}"),
            PeError::Truncated(what) => write!(f, "truncated PE ({what})"),
            PeError::BadDos => write!(f, "not an MZ image"),
            PeError::BadPe => write!(f, "not a PE image"),
            PeError::BadMagic(m) => write!(f, "unknown optional-header magic 0x{m:04X}"),
            PeError::BadExport(what) => write!(f, "export directory: {what}"),
        }
    }
}

impl std::error::Error for PeError {}

impl From<io::Error> for PeError {
    fn from(e: io::Error) -> Self {
        PeError::Io(e)
    }
}

pub fn parse_pe_exports(path: &Path) -> Result<Vec<Export>, PeError> {
    let buf = std::fs::read(path)?;
    parse_exports_from_bytes(&buf)
}

pub fn parse_exports_from_bytes(buf: &[u8]) -> Result<Vec<Export>, PeError> {
    let u16_at = |off: usize| -> Result<u16, PeError> {
        let b = buf.get(off..off + 2).ok_or(PeError::Truncated("u16"))?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    };
    let u32_at = |off: usize| -> Result<u32, PeError> {
        let b = buf.get(off..off + 4).ok_or(PeError::Truncated("u32"))?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    if u16_at(0)? != IMAGE_DOS_SIGNATURE {
        return Err(PeError::BadDos);
    }
    let e_lfanew = u32_at(0x3C)? as usize;
    if u32_at(e_lfanew)? != IMAGE_NT_SIGNATURE {
        return Err(PeError::BadPe);
    }

    let file_header = e_lfanew + IMAGE_NT_HEADERS_SIGNATURE_SIZE;
    let number_of_sections = u16_at(file_header + 2)? as usize;
    let size_of_optional_header = u16_at(file_header + 16)? as usize;
    let optional = file_header + IMAGE_FILE_HEADER_SIZE;
    if size_of_optional_header < 2 {
        return Err(PeError::Truncated("optional header"));
    }

    let magic = u16_at(optional)?;
    let (rva_count_off, data_dirs_off) = match magic {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC => (optional + 92, optional + 96),
        IMAGE_NT_OPTIONAL_HDR64_MAGIC => (optional + 108, optional + 112),
        other => return Err(PeError::BadMagic(other)),
    };

    if data_dirs_off + 8 > optional + size_of_optional_header {
        return Err(PeError::Truncated(
            "data directories vs SizeOfOptionalHeader",
        ));
    }
    let rva_count = u32_at(rva_count_off)?;
    if rva_count == 0 {
        return Ok(Vec::new());
    }
    let export_rva = u32_at(data_dirs_off)?;
    let export_size = u32_at(data_dirs_off + 4)?;
    if export_rva == 0 || export_size < 40 {
        return Ok(Vec::new());
    }

    let section_headers = optional + size_of_optional_header;
    let rva_to_off = |rva: u32| -> Result<Option<usize>, PeError> {
        for i in 0..number_of_sections {
            let entry = section_headers + i * IMAGE_SIZEOF_SECTION_HEADER;
            let virtual_size = u32_at(entry + 8)?;
            let virtual_address = u32_at(entry + 12)?;
            let size_of_raw_data = u32_at(entry + 16)?;
            let pointer_to_raw_data = u32_at(entry + 20)? as usize;
            let span = virtual_size.max(size_of_raw_data);
            if span == 0 {
                continue;
            }
            if rva >= virtual_address && rva < virtual_address.wrapping_add(span) {
                let delta = (rva - virtual_address) as usize;
                if delta >= size_of_raw_data as usize {
                    return Ok(None);
                }
                let off = pointer_to_raw_data.saturating_add(delta);
                if off >= buf.len() {
                    return Ok(None);
                }
                return Ok(Some(off));
            }
        }
        Ok(None)
    };

    let export_off =
        rva_to_off(export_rva)?.ok_or(PeError::BadExport("export RVA not in a section"))?;

    let ordinal_base = u32_at(export_off + 16)?;
    let number_of_functions = u32_at(export_off + 20)? as usize;
    let number_of_names = u32_at(export_off + 24)? as usize;
    let address_of_functions = u32_at(export_off + 28)?;
    let address_of_names = u32_at(export_off + 32)?;
    let address_of_name_ordinals = u32_at(export_off + 36)?;

    if number_of_functions > 1_000_000 || number_of_names > 1_000_000 {
        return Err(PeError::BadExport("implausible name/function counts"));
    }

    let mut named_by_index = vec![None; number_of_functions];
    if number_of_names > 0 {
        let names_off =
            rva_to_off(address_of_names)?.ok_or(PeError::BadExport("AddressOfNames"))?;
        let ords_off = rva_to_off(address_of_name_ordinals)?
            .ok_or(PeError::BadExport("AddressOfNameOrdinals"))?;

        for i in 0..number_of_names {
            let name_rva = u32_at(names_off + i * 4)?;
            let name_off = match rva_to_off(name_rva)? {
                Some(o) => o,
                None => continue,
            };
            let ordinal_index = u16_at(ords_off + i * 2)? as usize;
            let name = read_ascii_z(buf, name_off);
            if name.is_empty() {
                continue;
            }
            if ordinal_index < named_by_index.len() {
                named_by_index[ordinal_index] = Some(name);
            }
        }
    }

    // AddressOfFunctions is only needed so ordinal-only slots are not dropped.
    // Empty EAT slots (RVA 0) are skipped.
    let functions_off = if number_of_functions > 0 {
        rva_to_off(address_of_functions)?
    } else {
        None
    };

    let mut exports = Vec::with_capacity(number_of_functions);
    for (idx, name) in named_by_index.into_iter().enumerate() {
        let rva = match functions_off {
            Some(base) => u32_at(base + idx * 4).unwrap_or(0),
            None => 0,
        };
        if rva == 0 && name.is_none() {
            continue;
        }
        exports.push(Export {
            name,
            ordinal: ordinal_base.wrapping_add(idx as u32),
        });
    }
    Ok(exports)
}

fn read_ascii_z(buf: &[u8], start: usize) -> String {
    let mut end = start;
    while end < buf.len() && buf[end] != 0 {
        end += 1;
        if end - start > 512 {
            break;
        }
    }
    let bytes = &buf[start..end];
    if bytes.iter().all(|b| {
        (0x20..=0x7E).contains(b)
            || *b == b'.'
            || *b == b'?'
            || *b == b'@'
            || *b == b'$'
            || *b == b'_'
    }) {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        String::from_utf8_lossy(bytes)
            .chars()
            .filter(|c| !c.is_control())
            .collect()
    }
}

#[doc(hidden)]
pub fn build_synthetic_pe32plus(named: &[(&str, u32)], unnamed_ordinals: &[u32]) -> Vec<u8> {
    // Tiny PE32+ that our parser (not the Windows loader) can walk.
    const E_LFANEW: usize = 0x40;
    const FILE_HDR: usize = E_LFANEW + 4;
    const OPTIONAL: usize = FILE_HDR + 20;
    const OPT_SIZE: usize = 120; // 112 + 1 data dir
    const SECTION: usize = OPTIONAL + OPT_SIZE;
    const PTR_RAW: usize = 0x200;
    const VA: u32 = 0x1000;

    let mut names: Vec<(String, u32)> = named.iter().map(|(n, o)| ((*n).to_string(), *o)).collect();
    names.sort_by(|a, b| a.0.cmp(&b.0));

    let mut ordinals: Vec<u32> = names.iter().map(|(_, o)| *o).collect();
    ordinals.extend_from_slice(unnamed_ordinals);
    let base = ordinals.iter().copied().min().unwrap_or(1);
    let max_ord = ordinals.iter().copied().max().unwrap_or(base);
    let nfunc = (max_ord - base + 1) as usize;
    let nnames = names.len();

    let mut eat = vec![0u32; nfunc];
    for (_, ord) in &names {
        eat[(*ord - base) as usize] = 0x1100;
    }
    for ord in unnamed_ordinals {
        eat[(*ord - base) as usize] = 0x1104;
    }

    // Layout inside the section:
    // 0x00 IMAGE_EXPORT_DIRECTORY (40)
    // then EAT, name RVAs, ordinals, then strings
    let mut blob = vec![0u8; 40];
    let mut cursor = 40usize;

    let eat_rva = VA + cursor as u32;
    for r in &eat {
        blob.extend_from_slice(&r.to_le_bytes());
        cursor += 4;
    }
    let names_rva = VA + cursor as u32;
    let names_slot = cursor;
    blob.extend_from_slice(&vec![0u8; nnames * 4]);
    cursor += nnames * 4;
    let ords_rva = VA + cursor as u32;
    let ords_slot = cursor;
    blob.extend_from_slice(&vec![0u8; nnames * 2]);
    cursor += nnames * 2;

    let mut name_rvas = Vec::new();
    let mut name_idxs = Vec::new();
    for (name, ord) in &names {
        name_rvas.push(VA + cursor as u32);
        name_idxs.push((*ord - base) as u16);
        blob.extend_from_slice(name.as_bytes());
        blob.push(0);
        cursor += name.len() + 1;
    }
    for (i, rva) in name_rvas.iter().enumerate() {
        blob[names_slot + i * 4..names_slot + i * 4 + 4].copy_from_slice(&rva.to_le_bytes());
        blob[ords_slot + i * 2..ords_slot + i * 2 + 2].copy_from_slice(&name_idxs[i].to_le_bytes());
    }

    let export_size = blob.len() as u32;
    // IMAGE_EXPORT_DIRECTORY
    blob[16..20].copy_from_slice(&base.to_le_bytes());
    blob[20..24].copy_from_slice(&(nfunc as u32).to_le_bytes());
    blob[24..28].copy_from_slice(&(nnames as u32).to_le_bytes());
    blob[28..32].copy_from_slice(&eat_rva.to_le_bytes());
    blob[32..36].copy_from_slice(&names_rva.to_le_bytes());
    blob[36..40].copy_from_slice(&ords_rva.to_le_bytes());

    let mut file = vec![0u8; PTR_RAW + blob.len().max(0x20)];
    file[0] = 0x4D;
    file[1] = 0x5A;
    file[0x3C..0x40].copy_from_slice(&(E_LFANEW as u32).to_le_bytes());
    file[E_LFANEW..E_LFANEW + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
    file[FILE_HDR..FILE_HDR + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    file[FILE_HDR + 2..FILE_HDR + 4].copy_from_slice(&1u16.to_le_bytes());
    file[FILE_HDR + 16..FILE_HDR + 18].copy_from_slice(&(OPT_SIZE as u16).to_le_bytes());
    file[FILE_HDR + 18..FILE_HDR + 20].copy_from_slice(&0x2002u16.to_le_bytes());
    file[OPTIONAL..OPTIONAL + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes());
    file[OPTIONAL + 108..OPTIONAL + 112].copy_from_slice(&1u32.to_le_bytes());
    file[OPTIONAL + 112..OPTIONAL + 116].copy_from_slice(&VA.to_le_bytes());
    file[OPTIONAL + 116..OPTIONAL + 120].copy_from_slice(&export_size.to_le_bytes());

    let name = *b".edata\0\0";
    file[SECTION..SECTION + 8].copy_from_slice(&name);
    file[SECTION + 8..SECTION + 12].copy_from_slice(&(blob.len() as u32).to_le_bytes());
    file[SECTION + 12..SECTION + 16].copy_from_slice(&VA.to_le_bytes());
    file[SECTION + 16..SECTION + 20].copy_from_slice(&(blob.len() as u32).to_le_bytes());
    file[SECTION + 20..SECTION + 24].copy_from_slice(&(PTR_RAW as u32).to_le_bytes());
    file[PTR_RAW..PTR_RAW + blob.len()].copy_from_slice(&blob);
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            parse_exports_from_bytes(b"not a pe"),
            Err(PeError::Truncated(_) | PeError::BadDos)
        ));
        let mut mz = vec![0u8; 0x80];
        mz[0] = b'M';
        mz[1] = b'Z';
        mz[0x3C] = 0x40;
        assert!(matches!(parse_exports_from_bytes(&mz), Err(PeError::BadPe)));
    }

    #[test]
    fn named_and_ordinal_only() {
        let pe = build_synthetic_pe32plus(&[("Beta", 2), ("Alpha", 1)], &[3]);
        let ex = parse_exports_from_bytes(&pe).expect("parse");
        let named: Vec<_> = ex
            .iter()
            .filter_map(|e| e.name.as_deref().map(|n| (n, e.ordinal)))
            .collect();
        assert!(named.contains(&("Alpha", 1)), "{named:?}");
        assert!(named.contains(&("Beta", 2)), "{named:?}");
        assert!(
            ex.iter().any(|e| e.name.is_none() && e.ordinal == 3),
            "missing ordinal-only: {ex:?}"
        );
    }

    #[test]
    fn empty_export_dir_is_ok() {
        let mut pe = build_synthetic_pe32plus(&[("Only", 1)], &[]);
        // zero the export RVA
        let optional = 0x40 + 4 + 20;
        pe[optional + 112..optional + 116].copy_from_slice(&0u32.to_le_bytes());
        let ex = parse_exports_from_bytes(&pe).expect("parse");
        assert!(ex.is_empty());
    }

    #[test]
    fn live_system32_dll() {
        let path = Path::new(r"C:\Windows\System32\kernel32.dll");
        if !path.exists() {
            return;
        }
        let ex = parse_pe_exports(path).expect("kernel32 exports");
        assert!(
            ex.iter().any(|e| e.name.as_deref() == Some("LoadLibraryA")),
            "LoadLibraryA missing, got {} exports",
            ex.len()
        );
        assert!(
            ex.iter()
                .any(|e| e.name.as_deref() == Some("GetProcAddress")),
            "GetProcAddress missing"
        );
        assert!(ex.len() > 100);
    }
}
