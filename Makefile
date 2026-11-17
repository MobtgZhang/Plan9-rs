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
#   make run-serial               # Launch QEMU with serial output to a file
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
ISO_FILE     := $(BUILD_DIR)/plan9.iso

# Cargo commands should run from source/ where the workspace is.
CARGO_CMD = cd $(SOURCE_DIR) && $(CARGO)

# Per-architecture target triple and boot image.
TARGET_TRIPLE = $(shell case "$(ARCH)" in \
	x86_64) echo x86_64-unknown-none ;; \
	aarch64) echo aarch64-unknown-none ;; \
	riscv64) echo riscv64gc-unknown-none-elf ;; \
	loongarch64) echo loongarch64-unknown-none ;; \
	*) echo x86_64-unknown-none ;; \
esac)

KERNEL_ELF := $(BUILD_DIR)/kernel/plan9_kernel.elf

# x86_64 boots from the GRUB/OVMF ISO; the other targets are loaded
# directly by QEMU with -kernel.
ifeq ($(ARCH),x86_64)
RUN_DEPS  := iso
ALL_TARGET := iso
else
RUN_DEPS  := kernel
ALL_TARGET := kernel
endif

# Firmware paths (only needed by the x86 UEFI smoke path).
OVMF_FD_2M   := /usr/share/ovmf/OVMF.fd
OVMF_WORK_FILE := $(BUILD_DIR)/OVMF.fd
OPENSBI      := /usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin

# Per-arch QEMU tweaks: CPU model and extra BIOS for the direct fallback.
QEMU_CPU_x86_64      :=
QEMU_CPU_aarch64     := -cpu cortex-a72
QEMU_CPU_riscv64     :=
QEMU_CPU_loongarch64 := -cpu la464
QEMU_BIOS_riscv64    := -bios $(OPENSBI)
QEMU_BIOS_aarch64    :=
QEMU_BIOS_loongarch64 :=

.PHONY: all build-tool kernel init esp rootfs iso check-all clean run run-serial help

# =============================================================================
# Build targets (delegate to build-tool)
# =============================================================================

all: $(ALL_TARGET)

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
# x86_64 uses a GRUB-multiboot2 ISO with OVMF because QEMU's direct
# `-kernel` path does not understand the Multiboot2 image without a PVH
# ELF note.  All architectures boot the same way: UEFI firmware + the
# GRUB ISO.  Per-arch firmware:
#   x86_64      OVMF                (ovmf package)
#   aarch64     OVMF-AA64           (edk2-aarch64 package, QEMU_EFI.fd)
#   riscv64     edk2-riscv64        (QEMU_EFI.fd) or OpenSBI+GRUB
#   loongarch64 edk2-loongarch64    (QEMU_EFI.fd)
# If a per-arch firmware is not installed, non-x86 targets fall back to
# the direct `-kernel` path.
# =============================================================================

# Per-architecture UEFI firmware candidates, first match wins.
#   aarch64     qemu-efi-aarch64 -> QEMU_EFI.fd (loaded with -bios)
#   riscv64     qemu-efi-riscv64 -> RISCV_VIRT_CODE.fd + VARS (pflash)
#   loongarch64 edk2-loongarch64 -> QEMU_EFI.fd (pflash)
UEFI_FW_aarch64  = $(firstword $(wildcard /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/edk2-aarch64/QEMU_EFI.fd /usr/share/ovmf/OVMF.fd))
UEFI_FW_riscv64  = $(firstword $(wildcard /usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd /usr/share/edk2-riscv64/RISCV_VIRT_CODE.fd))
UEFI_VARS_riscv64_SRC = $(firstword $(wildcard /usr/share/qemu-efi-riscv64/RISCV_VIRT_VARS.fd /usr/share/edk2-riscv64/RISCV_VIRT_VARS.fd))
# EDK2 writes variable stores back, so the template must be copied into
# the build tree (the packaged file is read-only).
UEFI_VARS_riscv64 = $(BUILD_DIR)/RISCV_VIRT_VARS.fd
UEFI_FW_loongarch64 = $(firstword $(wildcard /usr/share/qemu-efi-loongarch64/QEMU_EFI.fd /usr/share/edk2-loongarch64/QEMU_EFI.fd))
UEFI_FW = $(UEFI_FW_$(ARCH))

# Extra firmware wiring: riscv64/loongarch64 EDK2 images are pflash
# devices, not -bios blobs.
UEFI_ARGS_aarch64  = -bios $(UEFI_FW)
UEFI_ARGS_riscv64  = -drive if=pflash,format=raw,readonly=on,file=$(UEFI_FW) \
                     -drive if=pflash,format=raw,file=$(UEFI_VARS_riscv64)
UEFI_ARGS_loongarch64 = -bios $(UEFI_FW)
UEFI_ARGS = $(UEFI_ARGS_$(ARCH))

run: $(RUN_DEPS)
	@mkdir -p $(BUILD_DIR)
	@if [ "$(ARCH)" = "x86_64" ] && [ -f "$(OVMF_FD_2M)" ] && [ ! -f "$(OVMF_WORK_FILE)" ]; then \
		cp "$(OVMF_FD_2M)" "$(OVMF_WORK_FILE)"; \
	fi; \
	if [ "$(ARCH)" = "riscv64" ] && [ -n "$(UEFI_VARS_riscv64_SRC)" ] && [ ! -f "$(UEFI_VARS_riscv64)" ]; then \
		cp "$(UEFI_VARS_riscv64_SRC)" "$(UEFI_VARS_riscv64)"; \
	fi; \
	case "$(ARCH)" in \
		x86_64) \
			qemu-system-x86_64 -m $(MEM) \
				-bios $(OVMF_WORK_FILE) \
				-cdrom $(ISO_FILE) \
				-display gtk -monitor none ;; \
		aarch64|riscv64|loongarch64) \
			if [ -n "$(UEFI_FW)" ]; then \
				echo "[RUN] $(ARCH) UEFI firmware: $(UEFI_FW)"; \
				qemu-system-$(ARCH) -M virt -m $(MEM) \
					$(QEMU_CPU_$(ARCH)) \
					$(UEFI_ARGS) \
					-cdrom $(ISO_FILE) \
					-display gtk -monitor none; \
			else \
				echo "[RUN] no UEFI firmware for $(ARCH) (install edk2-$(ARCH) / qemu-efi-$(ARCH)); falling back to direct -kernel boot"; \
				qemu-system-$(ARCH) -M virt -m $(MEM) \
					$(QEMU_CPU_$(ARCH)) \
					$(QEMU_BIOS_$(ARCH)) \
					-kernel $(KERNEL_ELF) \
					-display gtk -monitor none; \
			fi ;; \
		*) \
			echo "Unsupported ARCH=$(ARCH)"; exit 1 ;; \
	esac

run-serial: $(RUN_DEPS)
	@mkdir -p $(BUILD_DIR)
	@rm -f $(BUILD_DIR)/serial.log
	@if [ "$(ARCH)" = "x86_64" ] && [ -f "$(OVMF_FD_2M)" ] && [ ! -f "$(OVMF_WORK_FILE)" ]; then \
		cp "$(OVMF_FD_2M)" "$(OVMF_WORK_FILE)"; \
	fi; \
	if [ "$(ARCH)" = "riscv64" ] && [ -n "$(UEFI_VARS_riscv64_SRC)" ] && [ ! -f "$(UEFI_VARS_riscv64)" ]; then \
		cp "$(UEFI_VARS_riscv64_SRC)" "$(UEFI_VARS_riscv64)"; \
	fi; \
	case "$(ARCH)" in \
		x86_64) \
			qemu-system-x86_64 -m $(MEM) \
				-bios $(OVMF_WORK_FILE) \
				-cdrom $(ISO_FILE) \
				-display none -monitor none \
				-serial file:$(BUILD_DIR)/serial.log ;; \
		aarch64|riscv64|loongarch64) \
			if [ -n "$(UEFI_FW)" ]; then \
				echo "[RUN] $(ARCH) UEFI firmware: $(UEFI_FW)"; \
				qemu-system-$(ARCH) -M virt -m $(MEM) \
					$(QEMU_CPU_$(ARCH)) \
					$(UEFI_ARGS) \
					-cdrom $(ISO_FILE) \
					-display none -monitor none \
					-serial file:$(BUILD_DIR)/serial.log; \
			else \
				echo "[RUN] no UEFI firmware for $(ARCH); falling back to direct -kernel boot"; \
				qemu-system-$(ARCH) -M virt -m $(MEM) \
					$(QEMU_CPU_$(ARCH)) \
					$(QEMU_BIOS_$(ARCH)) \
					-kernel $(KERNEL_ELF) \
					-display none -monitor none \
					-serial file:$(BUILD_DIR)/serial.log; \
			fi ;; \
		*) \
			echo "Unsupported ARCH=$(ARCH)"; exit 1 ;; \
	esac

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
	@echo "  run          - Launch selected ARCH in QEMU (graphical)"
	@echo "  run-serial   - Launch QEMU with serial output to build/<arch>/serial.log"
	@echo ""
	@echo "Variables:"
	@echo "  ARCH=x86_64|aarch64|riscv64|loongarch64"
	@echo "  MEM=512                    # QEMU memory in MB"
	@echo ""
	@echo "Examples:"
	@echo "  make ARCH=aarch64 kernel && make ARCH=aarch64 run-serial"
	@echo "  make ARCH=riscv64 run-serial"
	@echo "  make ARCH=x86_64 run-serial"
