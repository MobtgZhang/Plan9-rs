# =============================================================================
# Plan 9 from Outer Space — Rust Edition
#
# Minimal Makefile for QEMU launching only.
# All build logic is handled by: cargo run -p build-tool -- [command]
#
# Usage:
#   make                          # Build all (kernel, ESP, rootfs, ISO)
#   make build-tool               # Build the build-tool itself
#   make kernel                   # Build kernel only
#   make init                     # Build init only
#   make esp                      # Build ESP only
#   make rootfs                   # Build rootfs only
#   make iso                      # Build ISO only
#   make clean                    # Clean build artifacts
#   make run                      # Launch in QEMU (graphical)
#   make run-serial               # Launch QEMU, serial output to file
#   make help                     # Print this help message
#
# Override defaults:
#   make ARCH=aarch64             # Build for a different architecture
#   make MEM=512                  # Set QEMU memory in MB
# =============================================================================

CARGO      ?= cargo
ARCH       ?= x86_64
MEM        ?= 256

PROJECT_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SOURCE_DIR   := $(PROJECT_ROOT)/source
BUILD_DIR    := $(PROJECT_ROOT)/build/$(ARCH)
ISO_FILE     := $(BUILD_DIR)/plan9.iso

# Cargo commands should run from source/ where the workspace is
CARGO_CMD = cd $(SOURCE_DIR) && $(CARGO)

OVMF_FD_2M   := /usr/share/ovmf/OVMF.fd
OVMF_CODE_4M := /usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS_4M := /usr/share/OVMF/OVMF_VARS_4M.fd
OVMF_WORK_FILE := $(BUILD_DIR)/OVMF.fd

.PHONY: all build-tool kernel init esp rootfs iso clean run run-serial help

# =============================================================================
# Build targets (delegate to build-tool)
# =============================================================================

all: iso

build-tool:
	$(CARGO_CMD) build -p build-tool

kernel: build-tool
	$(CARGO_CMD) run -p build-tool -- kernel --arch $(ARCH)

init: build-tool
	$(CARGO_CMD) run -p build-tool -- init --arch $(ARCH)

esp: build-tool
	$(CARGO_CMD) run -p build-tool -- esp --arch $(ARCH)

rootfs: build-tool
	$(CARGO_CMD) run -p build-tool -- rootfs --arch $(ARCH)

iso: build-tool
	$(CARGO_CMD) run -p build-tool -- iso --arch $(ARCH)

clean:
	$(CARGO_CMD) run -p build-tool -- clean

# =============================================================================
# QEMU launcher
# =============================================================================

run: iso
	@mkdir -p $(BUILD_DIR)
	@if [ -n "$(OVMF_FD_2M)" ] && [ -f "$(OVMF_FD_2M)" ] && [ ! -f "$(OVMF_WORK_FILE)" ]; then \
		cp $(OVMF_FD_2M) $(OVMF_WORK_FILE); \
		echo "  OVMF    prepared $(OVMF_WORK_FILE)"; \
	fi
	@if [ -n "$(OVMF_FD_2M)" ] && [ -f "$(OVMF_FD_2M)" ]; then \
		echo "Booting with UEFI firmware: $(OVMF_FD_2M)"; \
	else \
		echo "WARNING: OVMF firmware not found"; \
	fi
	@case "$(ARCH)" in \
		x86_64) QEMU=qemu-system-x86_64 ;; \
		aarch64) QEMU=qemu-system-aarch64 ;; \
		riscv64) QEMU=qemu-system-riscv64 ;; \
		loongarch64) QEMU=qemu-system-loongarch64 ;; \
		*) QEMU=qemu-system-$(ARCH) ;; \
	esac; \
	$$QEMU \
		-m $(MEM) \
		-cdrom $(ISO_FILE) \
		-no-reboot \
		-machine q35,smm=on \
		-drive if=pflash,format=raw,unit=0,file=$(OVMF_WORK_FILE) \
		-display gtk

run-serial: iso
	@mkdir -p $(BUILD_DIR)
	@if [ -n "$(OVMF_FD_2M)" ] && [ -f "$(OVMF_FD_2M)" ] && [ ! -f "$(OVMF_WORK_FILE)" ]; then \
		cp $(OVMF_FD_2M) $(OVMF_WORK_FILE); \
	fi
	@echo "Booting with serial output."
	@echo "  serial  -> $(BUILD_DIR)/serial.log"
	@echo "  monitor -> $(BUILD_DIR)/qemu-monitor.sock"
	@rm -f $(BUILD_DIR)/serial.log $(BUILD_DIR)/qemu-monitor.sock
	qemu-system-$(ARCH) \
		-m $(MEM) \
		-cdrom $(ISO_FILE) \
		-no-reboot \
		-machine q35,smm=on \
		-drive if=pflash,format=raw,unit=0,file=$(OVMF_WORK_FILE) \
		-display none \
		-serial file:$(BUILD_DIR)/serial.log \
		-monitor unix:$(BUILD_DIR)/qemu-monitor.sock,server,nowait

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
	@echo "  clean        - Clean build artifacts"
	@echo ""
	@echo "Runtime targets:"
	@echo "  run          - Launch in QEMU (graphical)"
	@echo "  run-serial   - Launch QEMU, serial output to file"
	@echo ""
	@echo "Variables:"
	@echo "  ARCH=x86_64|aarch64|riscv64|loongarch64"
	@echo "  MEM=256                    # QEMU memory in MB"
