use crate::pe::FunctionSource;
use crate::{Error, PeImage, Result};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction as IcedInstruction,
    IntelFormatter, OpKind,
};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
/// A decoded x86-64 instruction.
pub struct Instruction {
    /// Instruction virtual address.
    pub address: u64,
    /// Instruction byte length.
    pub length: u8,
    /// Intel syntax text.
    pub text: String,
    /// Normalized instruction data.
    pub normalized: NormalizedInstruction,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
/// A stable representation of an instruction.
pub struct NormalizedInstruction {
    /// Mnemonic name.
    pub mnemonic: String,
    /// Normalized operands.
    pub operands: Vec<String>,
}

pub(crate) fn decode_function(
    image: &PeImage,
    start: u32,
    end: u32,
    source: FunctionSource,
    bytes: &[u8],
) -> Result<crate::Function> {
    let start_va = image.rva_to_va(start)?;
    let mut decoder = Decoder::with_ip(64, bytes, start_va, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    let mut consumed = 0usize;
    let mut formatter = IntelFormatter::new();
    let limit = bytes.len();
    while consumed < limit && instructions.len() < 100_000 {
        let instruction = decoder.decode();
        let length = instruction.len();
        if instruction.is_invalid() || length == 0 || consumed.saturating_add(length) > limit {
            return Err(Error::Decode(start_va + consumed as u64));
        }
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        let normalized = normalize(image, start_va, end, &instruction);
        instructions.push(Instruction {
            address: instruction.ip(),
            length: length as u8,
            text,
            normalized,
        });
        consumed += length;
        if matches!(instruction.flow_control(), FlowControl::Return) {
            break;
        }
    }
    if instructions.is_empty() {
        return Err(Error::Decode(start_va));
    }
    let blocks = recover_blocks(&instructions, start_va, end);
    let call_count = instructions
        .iter()
        .filter(|instruction| instruction.normalized.mnemonic == "call")
        .count();
    let conditional_branch_count = instructions
        .iter()
        .filter(|instruction| {
            instruction.normalized.mnemonic.starts_with('j')
                && instruction.normalized.mnemonic != "jmp"
        })
        .count();
    let return_count = instructions
        .iter()
        .filter(|instruction| {
            instruction.normalized.mnemonic == "ret"
                || instruction.normalized.mnemonic == "retn"
                || instruction.normalized.mnemonic == "retf"
        })
        .count();
    Ok(crate::Function {
        address: start_va,
        rva: start,
        byte_size: end - start,
        source,
        instructions,
        blocks,
        call_count,
        conditional_branch_count,
        return_count,
    })
}

fn normalize(
    image: &PeImage,
    function_start: u64,
    function_end_rva: u32,
    instruction: &IcedInstruction,
) -> NormalizedInstruction {
    let mnemonic = format!("{:?}", instruction.mnemonic()).to_ascii_lowercase();
    let mut operands = Vec::with_capacity(instruction.op_count() as usize);
    for operand in 0..instruction.op_count() {
        let kind = instruction.op_kind(operand);
        let value = if matches!(
            kind,
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        ) {
            let target = instruction.near_branch_target();
            let end_va = image
                .image_base()
                .saturating_add(u64::from(function_end_rva));
            if target >= function_start && target < end_va {
                "local".to_string()
            } else {
                "external".to_string()
            }
        } else if instruction.is_ip_rel_memory_operand() && kind == OpKind::Memory {
            format!("ripmem:{}", instruction.memory_displ_size())
        } else if matches!(
            kind,
            OpKind::Immediate8
                | OpKind::Immediate8_2nd
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64
        ) {
            let immediate = instruction.immediate(operand);
            if image.va_to_rva(immediate).is_ok() {
                "image-address".to_string()
            } else {
                format!("scalar:{immediate:#x}")
            }
        } else if kind == OpKind::Register {
            format!("reg:{:?}", instruction.op_register(operand)).to_ascii_lowercase()
        } else {
            format!("{:?}", kind).to_ascii_lowercase()
        };
        operands.push(value);
    }
    NormalizedInstruction { mnemonic, operands }
}

fn recover_blocks(
    instructions: &[Instruction],
    function_start: u64,
    function_end_rva: u32,
) -> Vec<crate::BasicBlock> {
    let mut leaders = vec![0usize];
    for (index, instruction) in instructions.iter().enumerate() {
        if instruction.normalized.mnemonic.starts_with('j')
            && instruction.normalized.mnemonic != "jmp"
            && index + 1 < instructions.len()
        {
            leaders.push(index + 1);
        }
        if instruction.normalized.mnemonic == "jmp" && index + 1 < instructions.len() {
            leaders.push(index + 1);
        }
    }
    leaders.sort_unstable();
    leaders.dedup();
    let mut blocks = Vec::with_capacity(leaders.len());
    for (index, start) in leaders.iter().copied().enumerate() {
        let end = leaders
            .get(index + 1)
            .copied()
            .unwrap_or(instructions.len());
        let mut successors = Vec::new();
        if end < instructions.len() {
            successors.push(index + 1);
        }
        let _ = (function_start, function_end_rva);
        blocks.push(crate::BasicBlock {
            instructions: (start..end).collect(),
            successors,
        });
    }
    blocks
}
