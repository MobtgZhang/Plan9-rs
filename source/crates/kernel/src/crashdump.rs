use alloc::sync::Arc;
use plan9_common::sync::Spinlock;

use crate::devsd::{SdDev, SdError, SdResult, StorageBackend, SD_MAX_UNITS};
use crate::entry::BootInfo;

const PAGE: usize = 4096;
const NOTE_OFFSET: usize = 3072;
const NOTE_NAME: &[u8; 8] = b"Plan9rs\0";
const NOTE_HEADER: usize = 12 + NOTE_NAME.len();
pub(crate) const DIAGNOSTIC_LIMIT: usize = PAGE - NOTE_OFFSET - NOTE_HEADER;
const MAX_RANGES: usize = (NOTE_OFFSET - 64) / 56 - 1;
const MARKER: &[u8; 8] = b"P9DUMP1\0";

struct Capture {
    storage: Arc<dyn StorageBackend>,
    sectors_per_page: u64,
    elf: [u8; PAGE],
}

static CAPTURE: Spinlock<Option<Capture>> = Spinlock::new(None);

pub(crate) fn arm(boot: &BootInfo) {
    let mut page = alloc::vec![0; PAGE];
    for unit in (0..SD_MAX_UNITS).filter_map(|index| SdDev::get_global().get_unit(index)) {
        if !unit.supports_checkpoint() || unit.block_size == 0 || PAGE % unit.block_size != 0 {
            continue;
        }
        if !matches!(unit.read(0, &mut page), Ok(PAGE)) || &page[..8] != MARKER {
            continue;
        }
        let sectors_per_page = (PAGE / unit.block_size) as u64;
        if !matches!(unit.read(sectors_per_page, &mut page), Ok(PAGE)) {
            break;
        }
        if &page[..4] == b"\x7fELF" {
            crate::serial::put_bytes(b"[crashdump] preserving existing dump\n");
            return;
        }
        if let Some((elf, length)) = elf_header(boot) {
            if length / PAGE as u64 + 1 <= unit.sectors / sectors_per_page {
                if let Some(storage) = unit.try_backend() {
                    *CAPTURE.lock() = Some(Capture { storage, sectors_per_page, elf });
                    crate::serial::put_bytes(b"[crashdump] armed\n");
                    return;
                }
            }
        }
        crate::serial::put_bytes(b"[crashdump] unsuitable RAM map or dump disk capacity\n");
        return;
    }
}

fn elf_header(boot: &BootInfo) -> Option<([u8; PAGE], u64)> {
    if boot.memory_map.truncated {
        return None;
    }
    let mut descriptors = alloc::vec::Vec::new();
    for memory in boot.memory_map.iter() {
        if !matches!(memory.region_type, 1..=7 | 9 | 10) || memory.length == 0 {
            continue;
        }
        let end = memory.base.checked_add(memory.length)?;
        if memory.base % PAGE as u64 != 0 || end % PAGE as u64 != 0 {
            return None;
        }
        descriptors.push((memory.base, end));
    }
    descriptors.sort_unstable();
    let mut ranges = [(0u64, 0u64); MAX_RANGES];
    let mut count = 0;
    for (base, end) in descriptors {
        if count > 0 {
            let (_, previous_end) = &mut ranges[count - 1];
            if *previous_end == base {
                *previous_end = end;
                continue;
            }
            if *previous_end > base {
                return None;
            }
        }
        *ranges.get_mut(count)? = (base, end);
        count += 1;
    }
    if count == 0 {
        return None;
    }

    let mut elf = [0u8; PAGE];
    elf[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\x00");
    elf[16..18].copy_from_slice(&4u16.to_le_bytes());
    elf[18..20].copy_from_slice(&crate::rootdisk::MACHINE.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&(count as u16).to_le_bytes());
    let mut offset = PAGE as u64;
    for (program, &(base, end)) in elf[64..].chunks_exact_mut(56).zip(&ranges[..count]) {
        let length = end - base;
        program[..4].copy_from_slice(&1u32.to_le_bytes());
        program[4..8].copy_from_slice(&7u32.to_le_bytes());
        program[8..16].copy_from_slice(&offset.to_le_bytes());
        program[16..24].copy_from_slice(&base.to_le_bytes());
        program[24..32].copy_from_slice(&base.to_le_bytes());
        program[32..40].copy_from_slice(&length.to_le_bytes());
        program[40..48].copy_from_slice(&length.to_le_bytes());
        program[48..56].copy_from_slice(&(PAGE as u64).to_le_bytes());
        offset = offset.checked_add(length)?;
    }
    Some((elf, offset))
}

pub(crate) fn capture(diagnostic: &[u8]) -> SdResult<bool> {
    let mut config = CAPTURE.try_lock().ok_or(SdError::NotOnline)?;
    let Some(config) = config.as_mut() else { return Ok(false) };
    let count = u16::from_le_bytes(config.elf[56..58].try_into().unwrap()) as usize;
    for program in config.elf[64..].chunks_exact(56).take(count) {
        let offset = u64::from_le_bytes(program[8..16].try_into().unwrap());
        let base = u64::from_le_bytes(program[24..32].try_into().unwrap());
        let length = u64::from_le_bytes(program[32..40].try_into().unwrap());
        for page in (0..length).step_by(PAGE) {
            let lba = (1 + (offset + page) / PAGE as u64) * config.sectors_per_page;
            unsafe { config.storage.panic_write_page(lba, base + page)? };
        }
    }
    config.storage.panic_flush()?;
    let diagnostic = &diagnostic[..diagnostic.len().min(DIAGNOSTIC_LIMIT)];
    let note_size = (NOTE_HEADER + diagnostic.len() + 3) & !3;
    let note = &mut config.elf[NOTE_OFFSET..];
    note[..4].copy_from_slice(&(NOTE_NAME.len() as u32).to_le_bytes());
    note[4..8].copy_from_slice(&(diagnostic.len() as u32).to_le_bytes());
    note[8..12].copy_from_slice(&1u32.to_le_bytes());
    note[12..NOTE_HEADER].copy_from_slice(NOTE_NAME);
    note[NOTE_HEADER..NOTE_HEADER + diagnostic.len()].copy_from_slice(diagnostic);
    let program = &mut config.elf[64 + count * 56..][..56];
    program[..4].copy_from_slice(&4u32.to_le_bytes());
    program[8..16].copy_from_slice(&(NOTE_OFFSET as u64).to_le_bytes());
    program[32..40].copy_from_slice(&(note_size as u64).to_le_bytes());
    program[48..56].copy_from_slice(&4u64.to_le_bytes());
    config.elf[56..58].copy_from_slice(&((count + 1) as u16).to_le_bytes());
    config.storage.panic_write(config.sectors_per_page, &config.elf)?;
    config.storage.panic_flush()?;
    Ok(true)
}
