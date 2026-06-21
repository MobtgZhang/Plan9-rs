#!/bin/bash
# Create bootable ISO and IMG images

set -e

ARCH="${1:-x86_64}"
BUILD_DIR="build/$ARCH"
SYSTEM_DIR="$BUILD_DIR/system"
EFI_DIR="$SYSTEM_DIR/EFI"

echo "Creating bootable images for $ARCH..."

# Check if kernel exists
if [ ! -f "$SYSTEM_DIR/kernel" ]; then
    echo "Kernel not found. Run ./scripts/build.sh first."
    exit 1
fi

# Create EFI system partition
mkdir -p "$BUILD_DIR/esp"
mkdir -p "$BUILD_DIR/esp/EFI/BOOT"
cp "$EFI_DIR/BOOT/BOOTX64.EFI" "$BUILD_DIR/esp/EFI/BOOT/" 2>/dev/null || true

# Create FAT32 image (IMG)
echo "Creating IMG image..."
dd if=/dev/zero of="$BUILD_DIR/image.img" bs=1M count=256
mkfs.fat -F 32 "$BUILD_DIR/image.img"

# Copy files to IMG
mkdir -p /tmp/plan9_mount
sudo mount "$BUILD_DIR/image.img" /tmp/plan9_mount
sudo mkdir -p /tmp/plan9_mount/EFI/BOOT
sudo cp "$EFI_DIR/BOOT/BOOTX64.EFI" /tmp/plan9_mount/EFI/BOOT/ 2>/dev/null || true
sudo cp "$SYSTEM_DIR/kernel" /tmp/plan9_mount/
sudo umount /tmp/plan9_mount
rmdir /tmp/plan9_mount

echo "IMG image created: $BUILD_DIR/image.img"

# Create ISO image
echo "Creating ISO image..."
mkdir -p "$BUILD_DIR/iso_root"
mkdir -p "$BUILD_DIR/iso_root/EFI/BOOT"
cp -r "$SYSTEM_DIR/"* "$BUILD_DIR/iso_root/"

xorriso -as mkisofs \
    -no-emul-boot \
    -boot-load-size 4 \
    -efi-boot-part \
    --efi-boot-image \
    -efi-boot "$EFI_DIR/BOOT/BOOTX64.EFI" \
    -o "$BUILD_DIR/image.iso" \
    "$BUILD_DIR/iso_root"

echo "ISO image created: $BUILD_DIR/image.iso"

echo "Done!"
