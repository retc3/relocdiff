use crate::disasm::{decode_function, Instruction};
use crate::{Error, Result};
use serde::Serialize;
use std::collections::BTreeSet;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;

#[derive(Clone, Debug, Serialize)]
/// A mapped PE section.
pub struct Section {
    /// Section name, without trailing NUL bytes.
    pub name: String,
    /// Section RVA.
    pub virtual_address: u32,
    /// Mapped section size.
    pub virtual_size: u32,
    /// Raw file offset.
    pub raw_offset: u32,
    /// Raw file size.
    pub raw_size: u32,
    /// PE section characteristics.
    pub characteristics: u32,
}

impl Section {
    /// Returns true when this section contains executable code.
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    fn contains_rva(&self, rva: u32) -> bool {
        let size = self.virtual_size.max(self.raw_size);
        rva >= self.virtual_address && rva - self.virtual_address < size
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
/// The source used to recover a function boundary.
pub enum FunctionSource {
    /// The PE exception table supplied the range.
    Pdata,
    /// The entry point or a direct call supplied the start.
    Heuristic,
}

#[derive(Clone, Debug, Serialize)]
/// A recovered basic block.
pub struct BasicBlock {
    /// Instruction indexes in this block.
    pub instructions: Vec<usize>,
    /// Successor block indexes when known.
    pub successors: Vec<usize>,
}

#[derive(Clone, Debug, Serialize)]
/// A decoded function and its structural features.
pub struct Function {
    /// Function start VA.
    pub address: u64,
    /// Function start RVA.
    pub rva: u32,
    /// Function byte size from its recovered boundary.
    pub byte_size: u32,
    /// Boundary source.
    pub source: FunctionSource,
    /// Decoded instructions.
    pub instructions: Vec<Instruction>,
    /// Recovered basic blocks.
    pub blocks: Vec<BasicBlock>,
    /// Number of direct calls.
    pub call_count: usize,
    /// Number of conditional branches.
    pub conditional_branch_count: usize,
    /// Number of returns.
    pub return_count: usize,
}

impl Function {
    /// Returns the number of decoded instructions.
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Returns the number of recovered basic blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns a stable normalized instruction sequence.
    pub fn normalized(&self) -> impl Iterator<Item = &crate::NormalizedInstruction> {
        self.instructions
            .iter()
            .map(|instruction| &instruction.normalized)
    }
}

/// A parsed PE32+ image.
pub struct PeImage {
    bytes: Vec<u8>,
    image_base: u64,
    entry_rva: u32,
    size_of_image: u32,
    sections: Vec<Section>,
    ranges: Vec<(u32, u32, FunctionSource)>,
}

impl std::fmt::Debug for PeImage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeImage")
            .field("image_base", &format_args!("{:#x}", self.image_base))
            .field("sections", &self.sections)
            .field("function_count", &self.ranges.len())
            .finish()
    }
}

impl PeImage {
    /// Parse a PE32+ x86-64 image.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let image = Self::parse_headers(bytes)?;
        let ranges = image.recover_ranges();
        Ok(Self { ranges, ..image })
    }

    /// Return the preferred image base.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Return the PE entry point RVA.
    pub fn entry_rva(&self) -> u32 {
        self.entry_rva
    }

    /// Return the mapped image size.
    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    /// Return all parsed sections.
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Convert an RVA to a file offset.
    pub fn rva_to_file_offset(&self, rva: u32) -> Result<usize> {
        let section = self
            .sections
            .iter()
            .find(|section| section.contains_rva(rva))
            .ok_or(Error::OutsideCode(self.image_base + u64::from(rva)))?;
        let delta = rva - section.virtual_address;
        if delta >= section.raw_size {
            return Err(Error::InvalidPe("RVA has no raw file data".into()));
        }
        let offset = usize::try_from(section.raw_offset)
            .ok()
            .and_then(|base| base.checked_add(delta as usize))
            .ok_or_else(|| Error::InvalidPe("file offset overflow".into()))?;
        if offset >= self.bytes.len() {
            return Err(Error::InvalidPe("section points outside the file".into()));
        }
        Ok(offset)
    }

    /// Convert a VA to an RVA.
    pub fn va_to_rva(&self, va: u64) -> Result<u32> {
        let rva = va
            .checked_sub(self.image_base)
            .ok_or(Error::OutsideCode(va))?;
        let rva = u32::try_from(rva).map_err(|_| Error::OutsideCode(va))?;
        if rva >= self.size_of_image {
            return Err(Error::OutsideCode(va));
        }
        Ok(rva)
    }

    /// Convert an RVA to a virtual address.
    pub fn rva_to_va(&self, rva: u32) -> Result<u64> {
        if rva >= self.size_of_image {
            return Err(Error::OutsideCode(self.image_base + u64::from(rva)));
        }
        self.image_base
            .checked_add(u64::from(rva))
            .ok_or(Error::OutsideCode(u64::MAX))
    }

    /// Return the function containing a virtual address.
    pub fn function_at_va(&self, va: u64) -> Result<Function> {
        let rva = self.va_to_rva(va)?;
        self.function_at_rva(rva)
    }

    /// Return the function containing an RVA.
    pub fn function_at_rva(&self, rva: u32) -> Result<Function> {
        let (start, end, source) = self
            .ranges
            .iter()
            .find(|(start, end, _)| rva >= *start && rva < *end)
            .copied()
            .ok_or_else(|| Error::NoFunction(self.image_base + u64::from(rva)))?;
        let offset = self.rva_to_file_offset(start)?;
        let end_offset = self.rva_to_file_offset(end.saturating_sub(1))? + 1;
        let bytes = self
            .bytes
            .get(offset..end_offset)
            .ok_or_else(|| Error::InvalidPe("function range is outside the file".into()))?;
        decode_function(self, start, end, source, bytes)
    }

    /// Return all recovered function starts.
    pub fn function_starts(&self) -> impl Iterator<Item = u64> + '_ {
        self.ranges
            .iter()
            .map(|(start, _, _)| self.image_base + u64::from(*start))
    }

    fn parse_headers(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
            return Err(Error::InvalidPe("missing DOS header".into()));
        }
        let nt_offset = read_u32(bytes, 0x3c)? as usize;
        let signature_end = nt_offset
            .checked_add(4)
            .ok_or_else(|| Error::InvalidPe("header overflow".into()))?;
        if bytes.get(nt_offset..signature_end) != Some(b"PE\0\0") {
            return Err(Error::InvalidPe("missing PE signature".into()));
        }
        let coff = nt_offset + 4;
        let machine = read_u16(bytes, coff)?;
        if machine != 0x8664 {
            return Err(Error::Unsupported(format!(
                "machine {machine:#x}; v0.1 supports x86-64 only"
            )));
        }
        let number_sections = read_u16(bytes, coff + 2)? as usize;
        let optional_size = read_u16(bytes, coff + 16)? as usize;
        let optional = coff + 20;
        if read_u16(bytes, optional)? != 0x20b {
            return Err(Error::Unsupported(
                "input is PE32; v0.1 supports PE32+ x86-64 only".into(),
            ));
        }
        if optional_size < 112 {
            return Err(Error::InvalidPe("optional header is truncated".into()));
        }
        let image_base = read_u64(bytes, optional + 24)?;
        let entry_rva = read_u32(bytes, optional + 16)?;
        let size_of_image = read_u32(bytes, optional + 56)?;
        let directory_count = read_u32(bytes, optional + 108)? as usize;
        let section_offset = optional
            .checked_add(optional_size)
            .ok_or_else(|| Error::InvalidPe("section header overflow".into()))?;
        let mut sections = Vec::with_capacity(number_sections);
        for index in 0..number_sections {
            let offset = section_offset
                .checked_add(
                    index
                        .checked_mul(40)
                        .ok_or_else(|| Error::InvalidPe("section overflow".into()))?,
                )
                .ok_or_else(|| Error::InvalidPe("section overflow".into()))?;
            let header = bytes
                .get(offset..offset + 40)
                .ok_or_else(|| Error::InvalidPe("section header is truncated".into()))?;
            let name_end = header[..8].iter().position(|byte| *byte == 0).unwrap_or(8);
            sections.push(Section {
                name: String::from_utf8_lossy(&header[..name_end]).into_owned(),
                virtual_size: u32::from_le_bytes(header[8..12].try_into().unwrap()),
                virtual_address: u32::from_le_bytes(header[12..16].try_into().unwrap()),
                raw_size: u32::from_le_bytes(header[16..20].try_into().unwrap()),
                raw_offset: u32::from_le_bytes(header[20..24].try_into().unwrap()),
                characteristics: u32::from_le_bytes(header[36..40].try_into().unwrap()),
            });
        }
        let image = Self {
            bytes: bytes.to_vec(),
            image_base,
            entry_rva,
            size_of_image,
            sections,
            ranges: Vec::new(),
        };
        if directory_count > IMAGE_DIRECTORY_ENTRY_EXCEPTION {
            let directory = optional + 112 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
            let _ = (read_u32(bytes, directory)?, read_u32(bytes, directory + 4)?);
        }
        Ok(image)
    }

    fn recover_ranges(&self) -> Vec<(u32, u32, FunctionSource)> {
        let mut ranges = self.pdata_ranges();
        let mut starts = BTreeSet::new();
        starts.extend(ranges.iter().map(|(start, _, _)| *start));
        if self.is_executable_rva(self.entry_rva) {
            starts.insert(self.entry_rva);
        }
        for section in self
            .sections
            .iter()
            .filter(|section| section.is_executable())
        {
            if let Ok(offset) = self.rva_to_file_offset(section.virtual_address) {
                let end = offset
                    .saturating_add(section.raw_size as usize)
                    .min(self.bytes.len());
                let mut cursor = offset;
                while cursor.saturating_add(5) <= end {
                    if self.bytes[cursor] == 0xE8 {
                        let rel = i32::from_le_bytes(
                            self.bytes[cursor + 1..cursor + 5].try_into().unwrap(),
                        );
                        let target = (cursor as i64 + 5 + i64::from(rel)) - offset as i64
                            + i64::from(section.virtual_address);
                        if target >= 0
                            && target <= i64::from(u32::MAX)
                            && self.is_executable_rva(target as u32)
                        {
                            starts.insert(target as u32);
                        }
                    }
                    cursor += 1;
                }
            }
        }
        let mut starts: Vec<u32> = starts.into_iter().collect();
        starts.sort_unstable();
        for (index, start) in starts.iter().copied().enumerate() {
            if ranges.iter().any(|(known, _, _)| *known == start) {
                continue;
            }
            let next = starts
                .get(index + 1)
                .copied()
                .unwrap_or_else(|| self.section_end(start));
            if next > start && next - start <= 0x100000 && self.is_executable_rva(start) {
                ranges.push((start, next, FunctionSource::Heuristic));
            }
        }
        ranges.sort_by_key(|range| range.0);
        ranges
    }

    fn pdata_ranges(&self) -> Vec<(u32, u32, FunctionSource)> {
        let mut result = Vec::new();
        let Some(section) = self
            .sections
            .iter()
            .find(|section| section.name == ".pdata")
        else {
            return result;
        };
        let Ok(offset) = self.rva_to_file_offset(section.virtual_address) else {
            return result;
        };
        let end = offset
            .saturating_add(section.raw_size as usize)
            .min(self.bytes.len());
        let mut cursor = offset;
        while cursor.saturating_add(12) <= end {
            let begin = u32::from_le_bytes(self.bytes[cursor..cursor + 4].try_into().unwrap());
            let finish = u32::from_le_bytes(self.bytes[cursor + 4..cursor + 8].try_into().unwrap());
            if begin == 0 && finish == 0 {
                break;
            }
            if begin < finish && self.is_executable_rva(begin) && self.is_executable_rva(finish - 1)
            {
                result.push((begin, finish, FunctionSource::Pdata));
            }
            cursor += 12;
        }
        result
    }

    fn is_executable_rva(&self, rva: u32) -> bool {
        self.sections
            .iter()
            .any(|section| section.is_executable() && section.contains_rva(rva))
    }

    fn section_end(&self, rva: u32) -> u32 {
        self.sections
            .iter()
            .find(|section| section.contains_rva(rva))
            .map(|section| {
                section
                    .virtual_address
                    .saturating_add(section.virtual_size.max(section.raw_size))
            })
            .unwrap_or(rva)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    bytes
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| Error::InvalidPe("truncated header".into()))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| Error::InvalidPe("truncated header".into()))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    bytes
        .get(offset..offset + 8)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| Error::InvalidPe("truncated header".into()))
}
