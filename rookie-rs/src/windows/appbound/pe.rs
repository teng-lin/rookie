use anyhow::{anyhow, bail, Result};

#[derive(Debug, Clone)]
struct SectionHeader {
  #[allow(dead_code)]
  name: [u8; 8],
  virtual_size: u32,
  virtual_address: u32,
  size_of_raw_data: u32,
  pointer_to_raw_data: u32,
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
  let bytes = data
    .get(offset..offset + 2)
    .ok_or_else(|| anyhow!("PE truncated while reading u16 at offset 0x{offset:x}"))?;
  Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
  let bytes = data
    .get(offset..offset + 4)
    .ok_or_else(|| anyhow!("PE truncated while reading u32 at offset 0x{offset:x}"))?;
  Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn rva_to_file_offset(sections: &[SectionHeader], rva: u32) -> Result<usize> {
  for s in sections {
    let size = s.virtual_size.max(s.size_of_raw_data);
    if rva >= s.virtual_address && rva < s.virtual_address + size {
      let delta = rva - s.virtual_address;
      if delta < s.size_of_raw_data {
        return Ok((s.pointer_to_raw_data + delta) as usize);
      }
    }
  }
  bail!("RVA 0x{rva:x} does not map to any raw section in PE image")
}

fn read_c_string(data: &[u8], offset: usize) -> Result<&str> {
  let slice = data
    .get(offset..)
    .ok_or_else(|| anyhow!("offset 0x{offset:x} beyond PE data"))?;
  let len = slice
    .iter()
    .position(|&b| b == 0)
    .ok_or_else(|| anyhow!("unterminated C string at offset 0x{offset:x}"))?;
  std::str::from_utf8(&slice[..len])
    .map_err(|e| anyhow!("invalid UTF-8 in export name at offset 0x{offset:x}: {e}"))
}

/// Finds the raw file offset of an exported symbol in a PE32+ (64-bit) binary.
pub fn find_export_file_offset(pe_bytes: &[u8], export_name: &str) -> Result<usize> {
  if pe_bytes.len() < 0x40 {
    bail!("PE buffer too small for DOS header");
  }
  if &pe_bytes[..2] != b"MZ" {
    bail!("invalid DOS header magic (expected MZ)");
  }

  let e_lfanew = read_u32(pe_bytes, 0x3C)? as usize;
  if e_lfanew + 4 + 20 > pe_bytes.len() {
    bail!("PE header offset 0x{e_lfanew:x} out of range");
  }

  if &pe_bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
    bail!("invalid PE signature");
  }

  let file_header_offset = e_lfanew + 4;
  let machine = read_u16(pe_bytes, file_header_offset)?;
  if machine != 0x8664 {
    bail!("unsupported PE machine 0x{machine:x} (expected 0x8664 for AMD64)");
  }

  let number_of_sections = read_u16(pe_bytes, file_header_offset + 2)? as usize;
  let size_of_opt_header = read_u16(pe_bytes, file_header_offset + 16)? as usize;

  let opt_header_offset = file_header_offset + 20;
  if opt_header_offset + size_of_opt_header > pe_bytes.len() {
    bail!("PE optional header exceeds buffer length");
  }

  let opt_magic = read_u16(pe_bytes, opt_header_offset)?;
  if opt_magic != 0x020B {
    bail!("unsupported optional header magic 0x{opt_magic:x} (expected 0x020B for PE32+)");
  }

  // Data directories in PE32+ start at offset 112 from the beginning of OptionalHeader
  // DataDirectory[0] is Export Directory (VirtualAddress: u32, Size: u32)
  let export_dir_entry_offset = opt_header_offset + 112;
  let export_dir_rva = read_u32(pe_bytes, export_dir_entry_offset)?;
  let export_dir_size = read_u32(pe_bytes, export_dir_entry_offset + 4)?;

  if export_dir_rva == 0 || export_dir_size == 0 {
    bail!("PE image has no export directory");
  }

  // Section headers follow the Optional Header
  let section_headers_offset = opt_header_offset + size_of_opt_header;
  let mut sections = Vec::with_capacity(number_of_sections);
  for i in 0..number_of_sections {
    let s_off = section_headers_offset + i * 40;
    if s_off + 40 > pe_bytes.len() {
      bail!("section header {i} exceeds buffer length");
    }
    let mut name = [0u8; 8];
    name.copy_from_slice(&pe_bytes[s_off..s_off + 8]);
    let virtual_size = read_u32(pe_bytes, s_off + 8)?;
    let virtual_address = read_u32(pe_bytes, s_off + 12)?;
    let size_of_raw_data = read_u32(pe_bytes, s_off + 16)?;
    let pointer_to_raw_data = read_u32(pe_bytes, s_off + 20)?;

    sections.push(SectionHeader {
      name,
      virtual_size,
      virtual_address,
      size_of_raw_data,
      pointer_to_raw_data,
    });
  }

  let export_dir_file_off = rva_to_file_offset(&sections, export_dir_rva)?;
  if export_dir_file_off + 40 > pe_bytes.len() {
    bail!("export directory struct exceeds buffer length");
  }

  let num_functions = read_u32(pe_bytes, export_dir_file_off + 20)?;
  let num_names = read_u32(pe_bytes, export_dir_file_off + 24)?;
  let addr_functions_rva = read_u32(pe_bytes, export_dir_file_off + 28)?;
  let addr_names_rva = read_u32(pe_bytes, export_dir_file_off + 32)?;
  let addr_ordinals_rva = read_u32(pe_bytes, export_dir_file_off + 36)?;

  if num_names == 0 || num_functions == 0 {
    bail!("PE image has no named exported functions");
  }

  let funcs_file_off = rva_to_file_offset(&sections, addr_functions_rva)?;
  let names_file_off = rva_to_file_offset(&sections, addr_names_rva)?;
  let ords_file_off = rva_to_file_offset(&sections, addr_ordinals_rva)?;

  for i in 0..num_names as usize {
    let name_rva = read_u32(pe_bytes, names_file_off + i * 4)?;
    let name_off = rva_to_file_offset(&sections, name_rva)?;
    let sym_name = read_c_string(pe_bytes, name_off)?;

    if sym_name == export_name {
      let ordinal = read_u16(pe_bytes, ords_file_off + i * 2)? as usize;
      if ordinal >= num_functions as usize {
        bail!("export ordinal {ordinal} exceeds number of functions {num_functions}");
      }
      let func_rva = read_u32(pe_bytes, funcs_file_off + ordinal * 4)?;
      let func_file_off = rva_to_file_offset(&sections, func_rva)?;
      return Ok(func_file_off);
    }
  }

  bail!("export symbol {export_name:?} not found in PE image")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn finds_bootstrap_in_embedded_payload() {
    let payload = include_bytes!("native/abe_extractor_amd64.bin");
    let offset = find_export_file_offset(payload, "Bootstrap").expect("Bootstrap export found");
    assert!(offset > 0);
    assert!(offset < payload.len());
  }

  #[test]
  fn errors_on_nonexistent_symbol() {
    let payload = include_bytes!("native/abe_extractor_amd64.bin");
    let res = find_export_file_offset(payload, "NonExistentFunction");
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("not found"));
  }

  #[test]
  fn errors_on_invalid_pe_data() {
    assert!(find_export_file_offset(&[], "Bootstrap").is_err());
    assert!(find_export_file_offset(b"NOT A PE FILE", "Bootstrap").is_err());
  }
}
