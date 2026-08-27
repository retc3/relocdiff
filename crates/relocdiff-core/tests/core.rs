use relocdiff_core::{diff_functions, map_images, DiffKind, MapState, Matcher, PeImage};

fn image(code: &[u8], second_code: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x800];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
    bytes[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes());
    let optional = coff + 20;
    bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[optional + 24..optional + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
    bytes[optional + 56..optional + 60].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
    let exception = optional + 112 + 3 * 8;
    bytes[exception..exception + 4].copy_from_slice(&0x2000u32.to_le_bytes());
    bytes[exception + 4..exception + 8].copy_from_slice(&24u32.to_le_bytes());
    let sections = optional + 0xf0;
    section(
        &mut bytes[sections..sections + 40],
        b".text",
        0x1000,
        0x200,
        0x200,
        0x60000020,
    );
    section(
        &mut bytes[sections + 40..sections + 80],
        b".pdata",
        0x2000,
        0x100,
        0x400,
        0x40000040,
    );
    bytes[0x200..0x200 + code.len()].copy_from_slice(code);
    bytes[0x200 + 0x20..0x200 + 0x20 + second_code.len()].copy_from_slice(second_code);
    bytes[0x400..0x404].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[0x404..0x408].copy_from_slice(&0x1012u32.to_le_bytes());
    bytes[0x408..0x40c].copy_from_slice(&0u32.to_le_bytes());
    bytes[0x40c..0x410].copy_from_slice(&0x1020u32.to_le_bytes());
    bytes[0x410..0x414].copy_from_slice(&0x1030u32.to_le_bytes());
    bytes[0x414..0x418].copy_from_slice(&0u32.to_le_bytes());
    bytes
}

fn section(
    header: &mut [u8],
    name: &[u8],
    rva: u32,
    virtual_size: u32,
    raw_offset: u32,
    characteristics: u32,
) {
    header[..name.len()].copy_from_slice(name);
    header[8..12].copy_from_slice(&virtual_size.to_le_bytes());
    header[12..16].copy_from_slice(&rva.to_le_bytes());
    header[16..20].copy_from_slice(&virtual_size.to_le_bytes());
    header[20..24].copy_from_slice(&raw_offset.to_le_bytes());
    header[36..40].copy_from_slice(&characteristics.to_le_bytes());
}

fn first_code(rip_displacement: u32, call_displacement: u32, constant: u8) -> Vec<u8> {
    let mut code = vec![0x48, 0x8b, 0x05];
    code.extend(rip_displacement.to_le_bytes());
    code.extend([0xe8]);
    code.extend(call_displacement.to_le_bytes());
    code.extend([0x83, 0xf8, constant, 0x75, 0x00, 0xc3]);
    code
}

fn second_code(constant: u8) -> Vec<u8> {
    let mut code = vec![0x48, 0xb8, 0x20, 0x10, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00];
    code.extend([0xb8, constant, 0, 0, 0, 0xc3]);
    code
}

#[test]
fn maps_addresses_and_pdata_ranges() {
    let bytes = image(&first_code(0x20, 5, 0x2a), &second_code(5));
    let image = PeImage::parse(&bytes).unwrap();
    assert_eq!(image.va_to_rva(0x140001000).unwrap(), 0x1000);
    assert_eq!(image.rva_to_va(0x1020).unwrap(), 0x140001020);
    assert_eq!(image.rva_to_file_offset(0x1000).unwrap(), 0x200);
    assert_eq!(
        image.function_at_va(0x140001001).unwrap().address,
        0x140001000
    );
    assert_eq!(image.function_at_va(0x140001000).unwrap().block_count(), 2);
    assert_eq!(
        image.function_starts().collect::<Vec<_>>(),
        vec![0x140001000, 0x140001020]
    );
}

#[test]
fn rejects_malformed_and_unsupported_images() {
    assert!(PeImage::parse(b"not a PE").is_err());
    let mut bytes = image(&first_code(0x20, 5, 0x2a), &second_code(5));
    bytes[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
    assert!(PeImage::parse(&bytes).is_err());

    let mut bytes = image(&first_code(0x20, 5, 0x2a), &second_code(5));
    bytes[0x188 + 20..0x188 + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(PeImage::parse(&bytes).is_err());
}

#[test]
fn uses_the_exception_directory_without_a_pdata_name() {
    let mut bytes = image(&first_code(0x20, 5, 0x2a), &second_code(5));
    bytes[0x1b0..0x1b8].copy_from_slice(b".runtime");
    let image = PeImage::parse(&bytes).unwrap();
    assert_eq!(image.function_starts().count(), 2);
}

#[test]
fn normalizes_relocations_but_keeps_scalars() {
    let old = PeImage::parse(&image(&first_code(0x20, 0x100, 0x2a), &second_code(5))).unwrap();
    let new = PeImage::parse(&image(&first_code(0x80, 0x125, 0x2a), &second_code(6))).unwrap();
    let old_function = old.function_at_va(0x140001000).unwrap();
    let new_function = new.function_at_va(0x140001000).unwrap();
    assert_eq!(
        old_function.normalized().collect::<Vec<_>>(),
        new_function.normalized().collect::<Vec<_>>()
    );
    assert!(old_function.normalized().any(|instruction| instruction
        .operands
        .iter()
        .any(|operand| operand == "ripmem:8")));
    assert!(old_function.normalized().any(|instruction| instruction
        .operands
        .iter()
        .any(|operand| operand == "scalar:0x2a")));
    assert!(old_function.normalized().any(|instruction| instruction
        .operands
        .iter()
        .any(|operand| operand == "image")));
}

#[test]
fn ranks_relocated_function_first_and_orders_ties() {
    let old = PeImage::parse(&image(&first_code(0x20, 0x100, 0x2a), &second_code(5))).unwrap();
    let new = PeImage::parse(&image(&first_code(0x80, 0x125, 0x2a), &second_code(6))).unwrap();
    let source = old.function_at_va(0x140001000).unwrap();
    let matches = Matcher {
        top: 2,
        threshold: 0.0,
    }
    .find(&source, &new)
    .unwrap();
    assert_eq!(matches[0].address, 0x140001000);
    assert_eq!(matches[0].confidence, 100.0);
    assert_eq!(matches[0].score.instruction_similarity, 1.0);
    assert!(matches[1].confidence < matches[0].confidence);
}

#[test]
fn reports_semantic_constant_changes() {
    let old = PeImage::parse(&image(&first_code(0x20, 0x100, 0x2a), &second_code(5))).unwrap();
    let new = PeImage::parse(&image(&first_code(0x80, 0x125, 0x2a), &second_code(6))).unwrap();
    let source = old.function_at_va(0x140001020).unwrap();
    let candidate = Matcher {
        top: 1,
        threshold: 0.0,
    }
    .find(&source, &new)
    .unwrap()
    .pop()
    .unwrap();
    let diff = diff_functions(
        &source,
        &candidate.function,
        candidate.confidence,
        candidate.score,
    );
    assert_eq!(diff.target_address, 0x140001020);
    assert_eq!(diff.changed_constants, 1);
    assert!(diff
        .operations
        .iter()
        .any(|operation| operation.kind == DiffKind::ChangedConstant));
}

#[test]
fn maps_matched_and_changed_functions() {
    let old = PeImage::parse(&image(&first_code(0x20, 0x100, 0x2a), &second_code(5))).unwrap();
    let new = PeImage::parse(&image(&first_code(0x80, 0x125, 0x2a), &second_code(6))).unwrap();
    let map = map_images(&old, &new, 70.0).unwrap();
    assert_eq!(map.entries.len(), 2);
    assert_eq!(map.entries[0].state, MapState::Matched);
    assert_eq!(map.entries[1].state, MapState::Changed);
}

#[test]
fn mapping_does_not_claim_one_target_twice() {
    let old = PeImage::parse(&image(
        &first_code(0x20, 0x100, 0x2a),
        &first_code(0x20, 0x100, 0x2a),
    ))
    .unwrap();
    let new = PeImage::parse(&image(&first_code(0x80, 0x125, 0x2a), &second_code(6))).unwrap();
    let map = map_images(&old, &new, 70.0).unwrap();
    let targets: Vec<_> = map
        .entries
        .iter()
        .filter_map(|entry| entry.target_address)
        .collect();
    assert_eq!(targets.len(), 2);
    assert_ne!(targets[0], targets[1]);
}
