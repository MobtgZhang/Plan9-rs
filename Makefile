# =============================================================================
# Plan 9 from Outer Space — Rust Edition
#
# Build and QEMU smoke helpers for the four supported bare-metal targets:
#   x86_64, aarch64, riscv64, loongarch64
#
# All build orchestration is handled by:
#   cd source && cargo run -p build-tool -- [command]
#
# Usage:
#   make                          # Build ISO for the selected ARCH
#   make build-tool               # Build the build-tool itself
#   make kernel                   # Build kernel (and init) only
#   make init                     # Build init only
#   make esp                      # Build the EFI System Partition
#   make rootfs                   # Build the root filesystem
#   make iso                      # Build the bootable ISO
#   make check-all                # cargo check for all four targets
#   make clean                    # Clean build artifacts
#   make run                      # Launch the selected ARCH in QEMU
#   make run-console              # Launch QEMU with an interactive serial console
#   make run-serial               # Launch QEMU with serial output to a file
#   make boot-smoke               # Test the GOP menu, graphical console and shell
#   make help                     # Print this help message
#
# Override defaults:
#   make ARCH=aarch64             # aarch64 | riscv64 | loongarch64 | x86_64
#   make MEM=512                  # QEMU memory in MB
# =============================================================================

CARGO      ?= cargo
ARCH       ?= x86_64
MEM        ?= 512

PROJECT_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SOURCE_DIR   := $(PROJECT_ROOT)/source
BUILD_DIR    := $(PROJECT_ROOT)/build/$(ARCH)
ISO_FILE     = $(BUILD_DIR)/plan9.iso

# Cargo commands should run from source/ where the workspace is.
CARGO_CMD = cd $(SOURCE_DIR) && $(CARGO)

.PHONY: all build-tool kernel init esp rootfs iso check-all clean run run-console run-serial boot-smoke net-smoke mount-smoke native-9p-smoke panic-smoke rc-diff help

# =============================================================================
# Build targets (delegate to build-tool)
# =============================================================================

all: iso

build-tool:
	$(CARGO_CMD) build -p build-tool

kernel: build-tool
	$(CARGO_CMD) run -p build-tool -- --arch $(ARCH) kernel

init: build-tool
	$(CARGO_CMD) run -p build-tool -- --arch $(ARCH) init

esp: build-tool
	$(CARGO_CMD) run -p build-tool -- --arch $(ARCH) esp

rootfs: build-tool
	$(CARGO_CMD) run -p build-tool -- --arch $(ARCH) rootfs

iso: build-tool
	$(CARGO_CMD) run -p build-tool -- --arch $(ARCH) iso

check-all: build-tool
	$(CARGO_CMD) run -p build-tool -- check-all

clean:
	$(CARGO_CMD) run -p build-tool -- clean

# =============================================================================
# QEMU launcher
#
# The EFI loader supplies the kernel with the memory map, init and rootfs.
# Boot the freshly built ISO on every target. A bare kernel alone cannot
# start user space, so a missing firmware is an error, not a fallback.
UEFI_FW_x86_64 ?= $(firstword $(wildcard /usr/share/ovmf/OVMF.fd /usr/share/qemu/OVMF.fd /usr/share/OVMF/OVMF_CODE_4M.fd))
UEFI_FW_aarch64 ?= $(firstword $(wildcard /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/edk2-aarch64/QEMU_EFI.fd))
UEFI_FW_riscv64 ?= $(firstword $(wildcard /usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd /usr/share/edk2-riscv64/RISCV_VIRT_CODE.fd))
UEFI_FW_loongarch64 ?= $(firstword $(wildcard /usr/share/qemu-efi-loongarch64/QEMU_EFI.fd /usr/share/edk2-loongarch64/QEMU_EFI.fd))
UEFI_VARS_riscv64 ?= $(firstword $(wildcard /usr/share/qemu-efi-riscv64/RISCV_VIRT_VARS.fd /usr/share/edk2-riscv64/RISCV_VIRT_VARS.fd))
UEFI_VARS_x86_64 ?= $(if $(filter %OVMF_CODE_4M.fd,$(UEFI_FW_x86_64)),$(dir $(UEFI_FW_x86_64))OVMF_VARS_4M.fd)
UEFI_FW = $(UEFI_FW_$(ARCH))
UEFI_VARS = $(UEFI_VARS_$(ARCH))
UEFI_PFLASH = -drive if=pflash,format=raw,readonly=on,file="$(UEFI_FW)" \
	-drive if=pflash,format=raw,snapshot=on,file="$(UEFI_VARS)"
UEFI_ARGS = $(if $(UEFI_VARS),$(UEFI_PFLASH),-bios "$(UEFI_FW)")

QEMU_UEFI_KEYBOARD = -device qemu-xhci -device usb-kbd
QEMU_MACHINE_aarch64 = -M virt,highmem-mmio=off -cpu cortex-a72 -device ramfb $(QEMU_UEFI_KEYBOARD) -device virtio-keyboard-device
QEMU_MACHINE_riscv64 = -M virt -device VGA $(QEMU_UEFI_KEYBOARD) -device virtio-keyboard-device
QEMU_MACHINE_loongarch64 = -M virt -cpu la464 -device VGA $(QEMU_UEFI_KEYBOARD) -device virtio-keyboard-pci
QEMU_NIC ?= e1000
QEMU_CMD = qemu-system-$(ARCH) $(QEMU_MACHINE_$(ARCH)) -m $(MEM) $(UEFI_ARGS) \
	-netdev user,id=net0$(QEMU_NET_OPTIONS) -device $(QEMU_NIC),netdev=net0 $(QEMU_EXTRA_NETWORK) \
	-cdrom "$(ISO_FILE)" -monitor none

run: QEMU_OUTPUT = -display gtk
run-console: QEMU_OUTPUT = -display none -serial stdio
run-serial: QEMU_OUTPUT = -display none -serial file:"$(BUILD_DIR)/serial.log"
boot-smoke net-smoke mount-smoke native-9p-smoke rc-diff: QEMU_OUTPUT = -display none -serial stdio
boot-smoke: QEMU_RUNNER = python3 "$(PROJECT_ROOT)/scripts/boot-smoke.py" "$(ARCH)" "$(BUILD_DIR)/smoke-serial.log" --
net-smoke: QEMU_RUNNER = python3 "$(PROJECT_ROOT)/scripts/boot-smoke.py" --network "$(ARCH)" "$(BUILD_DIR)/net-serial.log" --
mount-smoke: QEMU_RUNNER = python3 "$(PROJECT_ROOT)/scripts/boot-smoke.py" --mount "$(ARCH)" "$(BUILD_DIR)/mount-serial.log" --
native-9p-smoke: QEMU_RUNNER = python3 "$(PROJECT_ROOT)/scripts/boot-smoke.py" --plan9port "$(PLAN9PORT)" $(if $(PLAN9_TICKET_PORT),--ticket-port "$(PLAN9_TICKET_PORT)") "$(ARCH)" "$(BUILD_DIR)/native-9p-serial.log" --
rc-diff: QEMU_RUNNER = python3 "$(PROJECT_ROOT)/scripts/boot-smoke.py" --rc-reference "$(RC_REFERENCE)" "$(ARCH)" "$(BUILD_DIR)/rc-diff-serial.log" --

panic-smoke: BUILD_DIR := $(PROJECT_ROOT)/build/$(ARCH)/panic-smoke
panic-smoke: QEMU_OUTPUT = -display none -serial stdio
panic-smoke: build-tool
	@test -f "$(UEFI_FW)" || { echo "No UEFI firmware for $(ARCH)." >&2; exit 1; }
	cd "$(SOURCE_DIR)" && PLAN9_PANIC_SMOKE=1 $(CARGO) run -p build-tool -- --arch $(ARCH) --build-dir "$(BUILD_DIR)" iso
	python3 "$(PROJECT_ROOT)/scripts/boot-smoke.py" --panic "$(ARCH)" "$(BUILD_DIR)/halt-serial.log" -- $(QEMU_CMD) $(QEMU_OUTPUT)
	python3 "$(PROJECT_ROOT)/scripts/boot-smoke.py" --panic --cpu-service "$(ARCH)" "$(BUILD_DIR)/reboot-serial.log" -- $(QEMU_CMD) $(QEMU_OUTPUT)

run run-console run-serial boot-smoke net-smoke mount-smoke native-9p-smoke rc-diff: iso
	@test -f "$(UEFI_FW)" || { echo "No UEFI firmware for $(ARCH); set UEFI_FW_$(ARCH)." >&2; exit 1; }
	@if [ "$(ARCH)" = "riscv64" ] || [ -n "$(UEFI_VARS)" ]; then \
		test -f "$(UEFI_VARS)" || { echo "No UEFI variables image for $(ARCH); set UEFI_VARS_$(ARCH)." >&2; exit 1; }; \
	fi
	$(QEMU_RUNNER) $(QEMU_CMD) $(QEMU_OUTPUT)

# =============================================================================
# Help
# =============================================================================

help:
	@echo "Plan 9 Rust Build System"
	@echo ""
	@echo "Build targets (via build-tool):"
	@echo "  all          - Build everything (default)"
	@echo "  build-tool   - Build the Rust build tool"
	@echo "  kernel       - Build the kernel ELF"
	@echo "  init         - Build the init binary"
	@echo "  esp          - Build the EFI System Partition"
	@echo "  rootfs       - Build the root filesystem"
	@echo "  iso          - Build the bootable ISO image"
	@echo "  check-all    - cargo check all four bare-metal targets"
	@echo "  clean        - Clean build artifacts"
	@echo ""
	@echo "Runtime targets:"
	@echo "  run          - Launch QEMU with a graphical console"
	@echo "  run-console  - Launch QEMU with an interactive serial console"
	@echo "  run-serial   - Launch QEMU with serial output to build/<arch>/serial.log"
	@echo "  boot-smoke   - Test the GOP menu, graphical keyboard and shell"
	@echo "  net-smoke    - Test DHCP, ICMP, TCP and UDP in QEMU"
	@echo "  mount-smoke  - Test authenticated 9P mounts and remote file operations in QEMU"
	@echo "  native-9p-smoke - Test factotum, Fossil and Venti with PLAN9PORT=/path/to/plan9port"
	@echo "                    Set PLAN9_TICKET_PORT to test an independent Plan 9 authsrv instead"
	@echo "  panic-smoke  - Test panic diagnostics, halt and restart in QEMU"
	@echo "  rc-diff      - Compare shell behavior with RC_REFERENCE=/path/to/plan9port/bin/rc"
	@echo ""
	@echo "Variables:"
	@echo "  ARCH=x86_64|aarch64|riscv64|loongarch64"
	@echo "  MEM=512                    # QEMU memory in MB"
	@echo ""
	@echo "Examples:"
	@echo "  make ARCH=aarch64 boot-smoke"
	@echo "  make ARCH=riscv64 run-console"
