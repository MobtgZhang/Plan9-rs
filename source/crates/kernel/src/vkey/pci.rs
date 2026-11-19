use plan9_drivers::pci::{pci_config_read, pci_config_write, PciConfigAddr};

use super::{
    vring_base, AVAIL_OFF, DESC_OFF, QUEUE_SIZE, S_ACKNOWLEDGE, S_DRIVER, S_DRIVER_OK,
    S_FAILED, S_FEATURES_OK, USED_OFF,
};

const VIRTIO_INPUT_ID: u32 = 0x1052_1af4;
const PCI_VENDOR_CAP: u8 = 0x09;

#[repr(C)]
struct CommonConfig {
    device_feature_select: u32,
    device_feature: u32,
    driver_feature_select: u32,
    driver_feature: u32,
    msix_config: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_desc: u64,
    queue_driver: u64,
    queue_device: u64,
}

struct Region {
    address: u64,
    length: u32,
}

fn config(device: u8, offset: u8) -> PciConfigAddr {
    PciConfigAddr::new(0, device, 0, offset)
}

fn read_config(device: u8, offset: u8) -> u32 {
    pci_config_read(config(device, offset))
}

fn region(device: u8, cap: u8) -> Option<Region> {
    let bar_index = read_config(device, cap + 4) as u8;
    if bar_index >= 6 {
        return None;
    }
    let bar_reg = 0x10 + 4 * bar_index;
    let bar = read_config(device, bar_reg);
    let high = match bar & 0x7 {
        0 => 0,
        4 if bar_index < 5 => u64::from(read_config(device, bar_reg + 4)) << 32,
        _ => return None,
    };
    let base = high | u64::from(bar & !0xf);
    let offset = read_config(device, cap + 8);
    let length = read_config(device, cap + 12);
    let start = base.checked_add(u64::from(offset))?;
    let end = start.checked_add(u64::from(length))?;
    if base < 0x4000_0000 || end > 0x8000_0000 {
        return None;
    }
    Some(Region {
        address: crate::plan9_arch::loongarch64::mmu::mmio_phys_to_virt(start),
        length,
    })
}

fn regions(device: u8) -> Option<(Region, Region, u32)> {
    let mut cap = read_config(device, 0x34) as u8 & !3;
    let mut common = None;
    let mut notify = None;
    for _ in 0..48 {
        if !(0x40..=0xfcu8).contains(&cap) {
            break;
        }
        let [id, next, length, kind] = read_config(device, cap).to_le_bytes();
        if id == PCI_VENDOR_CAP && u16::from(cap) + u16::from(length) <= 256 {
            match kind {
                1 if length >= 16 => {
                    common = region(device, cap).filter(|entry| {
                        entry.length as usize >= core::mem::size_of::<CommonConfig>()
                            && entry.address % 8 == 0
                    });
                }
                2 if length >= 20 => {
                    notify = region(device, cap)
                        .map(|entry| (entry, read_config(device, cap + 16)));
                }
                _ => {}
            }
        }
        cap = next & !3;
    }
    let (notify, multiplier) = notify?;
    Some((common?, notify, multiplier))
}

pub(super) fn init_transport() -> Option<u64> {
    let device = (0..32).find(|&device| read_config(device, 0) == VIRTIO_INPUT_ID)?;
    let (common, notify, multiplier) = regions(device)?;
    let command = read_config(device, 4) & 0xffff;
    pci_config_write(config(device, 4), command | 0x406);

    let regs = common.address as *mut CommonConfig;
    unsafe {
        let device_status = &raw mut (*regs).device_status;
        device_status.write_volatile(0);
        for _ in 0..1000 {
            if device_status.read_volatile() == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        if device_status.read_volatile() != 0 {
            return None;
        }

        let status = S_ACKNOWLEDGE | S_DRIVER;
        device_status.write_volatile(S_ACKNOWLEDGE);
        device_status.write_volatile(status);
        (&raw mut (*regs).device_feature_select).write_volatile(1);
        if (&raw const (*regs).device_feature).read_volatile() & 1 == 0 {
            device_status.write_volatile(status | S_FAILED);
            return None;
        }
        (&raw mut (*regs).driver_feature_select).write_volatile(0);
        (&raw mut (*regs).driver_feature).write_volatile(0);
        (&raw mut (*regs).driver_feature_select).write_volatile(1);
        (&raw mut (*regs).driver_feature).write_volatile(1);
        let status = status | S_FEATURES_OK;
        device_status.write_volatile(status);
        if device_status.read_volatile() & S_FEATURES_OK == 0 {
            device_status.write_volatile(status | S_FAILED);
            return None;
        }

        (&raw mut (*regs).queue_select).write_volatile(0);
        let notify_offset = u64::from((&raw const (*regs).queue_notify_off).read_volatile())
            * u64::from(multiplier);
        let notify_address = notify.address + notify_offset;
        if (&raw const (*regs).queue_size).read_volatile() < QUEUE_SIZE as u16
            || notify_offset + 2 > u64::from(notify.length)
            || notify_address % 2 != 0
        {
            device_status.write_volatile(status | S_FAILED);
            return None;
        }

        let ring = vring_base() as u64;
        (&raw mut (*regs).queue_size).write_volatile(QUEUE_SIZE as u16);
        (&raw mut (*regs).queue_msix_vector).write_volatile(u16::MAX);
        (&raw mut (*regs).queue_desc).write_volatile(ring + DESC_OFF as u64);
        (&raw mut (*regs).queue_driver).write_volatile(ring + AVAIL_OFF as u64);
        (&raw mut (*regs).queue_device).write_volatile(ring + USED_OFF as u64);
        (&raw mut (*regs).queue_enable).write_volatile(1);
        device_status.write_volatile(status | S_DRIVER_OK);
        Some(notify_address)
    }
}
