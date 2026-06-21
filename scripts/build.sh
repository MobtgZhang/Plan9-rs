#!/bin/bash
# Plan9-Rust Build Script
# Builds the kernel and creates disk images

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
SRC_DIR="$PROJECT_ROOT/source"

# Default architecture
ARCH="${ARCH:-x86_64}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create build directory structure
create_dirs() {
    log_info "Creating build directories..."
    mkdir -p "$BUILD_DIR/$ARCH"
    mkdir -p "$BUILD_DIR/$ARCH/System"
    mkdir -p "$BUILD_DIR/$ARCH/boot"
    mkdir -p "$BUILD_DIR/$ARCH/tmp"
}

# Check dependencies
check_deps() {
    log_info "Checking dependencies..."
    
    local missing=()
    
    if ! command -v rustc &> /dev/null; then
        missing+=("rustc")
    fi
    
    if ! command -v qemu-system-x86_64 &> /dev/null; then
        missing+=("qemu-system-x86_64")
    fi
    
    if ! command -v xorriso &> /dev/null; then
        missing+=("xorriso")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_warn "Missing dependencies: ${missing[*]}"
        log_info "Installing missing dependencies..."
        sudo apt-get update
        sudo apt-get install -y "${missing[@]}" 2>/dev/null || true
    fi
}

# Build the kernel
build_kernel() {
    log_info "Building kernel for $ARCH..."
    
    cd "$SRC_DIR"
    
    # Create .cargo/config.toml for cross-compilation
    mkdir -p "$SRC_DIR/.cargo"
    cat > "$SRC_DIR/.cargo/config.toml" << 'EOF'
[build]
target = "x86_64-unknown-none"

[target.x86_64-unknown-none]
rustflags = ["-C", "link-arg=-nostartfiles"]
EOF

    # Build with release profile
    cargo build --release --target x86_64-unknown-none 2>&1 || {
        log_error "Kernel build failed"
        return 1
    }
    
    # Copy kernel to build directory
    cp "$SRC_DIR/target/x86_64-unknown-none/release/*.a" "$BUILD_DIR/$ARCH/System/" 2>/dev/null || true
    
    log_info "Kernel built successfully"
}

# Create the System directory with kernel
create_system() {
    log_info "Creating System directory..."
    
    # Copy kernel library
    if [ -f "$SRC_DIR/target/x86_64-unknown-none/release/libplan9_kernel.rlib" ]; then
        cp "$SRC_DIR/target/x86_64-unknown-none/release/libplan9_kernel.rlib" \
           "$BUILD_DIR/$ARCH/System/plan9kernel.lib"
    fi
    
    # Create kernel binary (stub for now)
    cat > "$BUILD_DIR/$ARCH/System/9kernel" << 'EOF'
#!/bin/bash
# Plan9 Kernel Stub
# This would be the actual kernel binary in a full implementation

echo "Plan9 Rust Kernel Stub"
echo "Architecture: $1"
EOF
    chmod +x "$BUILD_DIR/$ARCH/System/9kernel"
    
    # Create additional system files
    cat > "$BUILD_DIR/$ARCH/System/RELEASE" << 'EOF'
9
EOF
    
    cat > "$BUILD_DIR/$ARCH/System/NOTICE" << 'EOF'
Plan 9 from Bell Labs
Rust Implementation
EOF
}

# Create disk image
create_disk_image() {
    log_info "Creating disk image..."
    
    local img="$BUILD_DIR/$ARCH/plan9.img"
    local size_mb="${SIZE:-64}"
    
    # Create raw disk image
    dd if=/dev/zero of="$img" bs=1M count=$size_mb 2>/dev/null
    
    # Create FAT32 filesystem
    which mkfs.fat &>/dev/null && {
        mkfs.fat -F 32 "$img" >/dev/null 2>&1 || \
        mkfs.vfat -F 32 "$img" >/dev/null 2>&1 || true
    }
    
    # Create boot directory structure
    mkdir -p /tmp/plan9_mnt
    sudo mount -o loop "$img" /tmp/plan9_mnt 2>/dev/null || true
    
    if mountpoint -q /tmp/plan9_mnt 2>/dev/null; then
        # Copy System files
        cp -r "$BUILD_DIR/$ARCH/System" /tmp/plan9_mnt/
        
        # Create boot files
        mkdir -p /tmp/plan9_mnt/boot
        cp "$BUILD_DIR/$ARCH/System/9kernel" /tmp/plan9_mnt/boot/
        
        # Create plan9.ini configuration
        cat > /tmp/plan9_mnt/plan9.ini << 'EOF'
[boot]
kernel=boot/9kernel
initcode=/boot/init
memory=512M

[display]
driver=vesa
mode=1024x768x32

[disk]
bootdisk=0
rootdisk=0
EOF
        
        sudo umount /tmp/plan9_mnt
    fi
    
    log_info "Disk image created: $img"
}

# Create ISO image
create_iso() {
    log_info "Creating ISO image..."
    
    local iso="$BUILD_DIR/$ARCH/plan9.iso"
    local isodir="/tmp/plan9_iso"
    
    # Create ISO directory
    rm -rf "$isodir"
    mkdir -p "$isodir/boot"
    
    # Copy System files
    cp -r "$BUILD_DIR/$ARCH/System" "$isodir/"
    
    # Copy kernel to boot
    if [ -f "$BUILD_DIR/$ARCH/System/9kernel" ]; then
        cp "$BUILD_DIR/$ARCH/System/9kernel" "$isodir/boot/"
    fi
    
    # Create El Torito boot image (bootable ISO)
    mkdir -p "$isodir/boot/grub"
    cat > "$isodir/boot/grub/grub.cfg" << 'EOF'
set timeout=5
set default=0

menuentry "Plan 9 Rust" {
    linux /boot/9kernel
    boot
}
EOF
    
    # Create ISO using grub-mkrescue or xorriso
    if command -v grub-mkrescue &> /dev/null; then
        grub-mkrescue -o "$iso" "$isodir" 2>/dev/null || {
            log_warn "grub-mkrescue failed, trying xorriso..."
            create_iso_xorriso "$iso" "$isodir"
        }
    elif command -v xorriso &> /dev/null; then
        create_iso_xorriso "$iso" "$isodir"
    else
        log_warn "No ISO creation tool available"
        return 1
    fi
    
    log_info "ISO image created: $iso"
}

create_iso_xorriso() {
    local iso="$1"
    local isodir="$2"
    
    xorriso -as mkisofs \
        -R -f -pad \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        -eltorito-boot boot/grub/grub.cfg \
        -eltorito-catalog boot/grub/boot.cat \
        -no-emul-boot \
        -o "$iso" \
        "$isodir" 2>/dev/null || \
    log_warn "ISO creation may have had warnings"
}

# Create a simple bootable image (without full grub)
create_simple_iso() {
    log_info "Creating simple bootable ISO..."
    
    local iso="$BUILD_DIR/$ARCH/plan9.iso"
    
    # Create a minimal ISO structure
    mkdir -p /tmp/plan9_simple_iso/boot
    
    # Copy kernel
    cp "$BUILD_DIR/$ARCH/System/9kernel" /tmp/plan9_simple_iso/boot/ 2>/dev/null || true
    
    # Create simple ISO with just the files
    if command -v xorriso &> /dev/null; then
        xorriso -as cdrecord \
            -dev "$iso" \
            -map /tmp/plan9_simple_iso / \
            -eject \
            -blank=as_needed 2>/dev/null || true
    fi
    
    log_info "Simple ISO created: $iso"
}

# Run QEMU to test
run_qemu() {
    log_info "Starting QEMU..."
    
    local img="$BUILD_DIR/$ARCH/plan9.img"
    
    if [ ! -f "$img" ]; then
        log_error "Disk image not found: $img"
        return 1
    fi
    
    qemu-system-x86_64 \
        -m 512M \
        -drive file="$img,format=raw" \
        -display curses \
        -serial stdio \
        -no-reboot \
        -kernel "$BUILD_DIR/$ARCH/System/9kernel" \
        2>&1 || true
}

# Show help
show_help() {
    cat << EOF
Plan9-Rust Build Script

Usage: $0 [command]

Commands:
    build       Build the kernel
    image       Create disk image (plan9.img)
    iso         Create ISO image (plan9.iso)
    all         Build everything (default)
    run         Run in QEMU
    clean       Clean build artifacts
    help        Show this help

Environment Variables:
    ARCH        Target architecture (default: x86_64)
    SIZE        Disk image size in MB (default: 64)

Examples:
    $0 build          # Build kernel only
    $0 image          # Create disk image
    $0 iso            # Create ISO
    $0 all            # Build everything
    $0 run            # Run in QEMU
    
    ARCH=aarch64 $0 build  # Build for ARM64
EOF
}

# Clean build artifacts
clean() {
    log_info "Cleaning build artifacts..."
    rm -rf "$BUILD_DIR/$ARCH"
    rm -rf "$SRC_DIR/target"
    rm -rf "$SRC_DIR/.cargo"
}

# Main
main() {
    local cmd="${1:-all}"
    
    create_dirs
    check_deps
    
    case "$cmd" in
        build)
            build_kernel
            create_system
            ;;
        image)
            create_disk_image
            ;;
        iso)
            create_iso
            ;;
        all)
            build_kernel
            create_system
            create_disk_image
            create_simple_iso
            ;;
        run)
            run_qemu
            ;;
        clean)
            clean
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $cmd"
            show_help
            exit 1
            ;;
    esac
    
    log_info "Done!"
}

main "$@"
