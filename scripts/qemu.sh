#!/bin/bash
# Run Plan 9 in QEMU

set -e

ARCH="${1:-x86_64}"
BUILD_DIR="build/$ARCH"
KERNEL="$BUILD_DIR/system/kernel"
EFI_DIR="$BUILD_DIR/system/EFI"

if [ ! -f "$KERNEL" ]; then
    echo "Kernel not found. Run ./scripts/build.sh first."
    exit 1
fi

# Create EFI disk image if needed
if [ ! -f "$BUILD_DIR/esp.img" ]; then
    echo "Creating EFI system partition..."
    dd if=/dev/zero of="$BUILD_DIR/esp.img" bs=1M count=64
    mkfs.fat -F 32 "$BUILD_DIR/esp.img"
    mkdir -p /tmp/esp
    mount "$BUILD_DIR/esp.img" /tmp/esp
    mkdir -p /tmp/esp/EFI/BOOT
    cp "$EFI_DIR/BOOT/BOOTX64.EFI" /tmp/esp/EFI/BOOT/
    umount /tmp/esp
fi

# Determine QEMU binary based on architecture
case "$ARCH" in
    x86_64|i386)
        QEMU="qemu-system-x86_64"
        QEMU_ARCH="x86_64"
        ;;
    aarch64)
        QEMU="qemu-system-aarch64"
        QEMU_ARCH="aarch64"
        ;;
    riscv64)
        QEMU="qemu-system-riscv64"
        QEMU_ARCH="riscv64"
        ;;
    loongarch64)
        QEMU="qemu-system-loongarch64"
        QEMU_ARCH="loongarch64"
        ;;
    *)
        echo "Unknown architecture: $ARCH"
        exit 1
        ;;
esac

echo "Starting QEMU with $ARCH kernel..."
$QEMU \
    -machine virt \
    -kernel "$KERNEL" \
    -append "console=ttyS0" \
    -nographic \
    -m 256M
