# Plan 9 Rust

用 Rust 语言重新实现 Plan 9 操作系统。

## 支持的架构

- **x86_64** (64位 x86)
- **i386** (32位 x86) 
- **loongarch64** (LoongArch 64位)
- **riscv64** (RISC-V 64位)
- **aarch64** (ARM 64位)

所有架构均使用 UEFI 启动。

## 项目结构

```
Plan9-Rust/
├── source/                    # 源代码
│   ├── Cargo.toml            # 工作空间配置
│   └── crates/               # 所有 crate
│       ├── arch/             # 架构代码
│       │   ├── src/
│       │   │   ├── x86_64/
│       │   │   ├── i386/
│       │   │   ├── loongarch64/
│       │   │   ├── riscv64/
│       │   │   └── aarch64/
│       │   └── Cargo.toml
│       ├── common/           # 公共类型和工具
│       │   ├── src/
│       │   │   ├── types.rs  # 基础类型
│       │   │   ├── error.rs  # 错误类型
│       │   │   └── sync.rs   # 同步原语
│       │   └── Cargo.toml
│       ├── kernel/           # 内核核心
│       │   ├── src/
│       │   │   ├── proc.rs   # 进程管理
│       │   │   ├── sched.rs  # 调度器
│       │   │   ├── trap.rs   # 陷阱处理
│       │   │   └── vm.rs     # 虚拟内存
│       │   └── Cargo.toml
│       ├── bootloader/       # 启动加载器
│       ├── libsys/           # 系统库
│       ├── drivers/          # 设备驱动
│       │   ├── src/
│       │   │   ├── pci.rs
│       │   │   ├── storage.rs
│       │   │   ├── network.rs
│       │   │   └── display.rs
│       │   └── Cargo.toml
│       ├── ipc/             # 进程间通信
│       ├── fs/               # 文件系统
│       │   ├── src/
│       │   │   ├── vfs.rs
│       │   │   ├── fat.rs
│       │   │   └── ramfs.rs
│       │   └── Cargo.toml
│       ├── net/              # 网络栈
│       │   ├── src/
│       │   │   ├── eth.rs
│       │   │   ├── arp.rs
│       │   │   ├── ipv4.rs
│       │   │   ├── tcp.rs
│       │   │   └── udp.rs
│       │   └── Cargo.toml
│       ├── servers/          # Plan 9 服务器
│       ├── userspace/        # 用户程序
│       └── Cargo.toml
├── scripts/                   # 构建脚本
├── build/                    # 构建输出
└── reference/                # 原始 Plan 9 源码 (参考)
```

## 构建

### 前置条件

- Rust 工具链
- QEMU (用于测试)
- xorriso (用于创建 ISO 镜像)
- mkfs.fat (用于创建 IMG 镜像)

### 构建项目

```bash
cd source
cargo build
```

## 开发状态

Last updated: 2026-07-10

### P0 — bring-up (✅ done)
- [x] `kstart` chains frame allocator → heap → ACPI → timer → scheduler → init ELF
- [x] `switch_to_user` (`switch_to_user.S` + Rust trampoline) carries the
      IRET frame and enters user mode at the init binary entry point
- [x] Multiboot2 `MODULE` tag parser keeps the cmdline string
- [x] Heap allocator `heap::heap_init` is wired to a `KernelHeap`
- [x] ISO boots in QEMU and reaches the user-mode `init` shell

### P1 — synchronization hardening (✅ done)
- [x] `AtomicDWord::compare_exchange` now uses `rbx` (was wrongly
      binding `r15`)
- [x] `SleepChannel::sleep` rewritten with epoch + waiting count
- [x] `TicketLock::try_lock` is a real CAS-based non-blocking lock
- [x] `RWLock::rlock` rewritten to avoid the reader/writer race
- [x] `ILockDepth` is now `[AtomicU32; MAX_CPUS]` (per-CPU ready)
- [x] `panic!` macro routes through an installable `PanicHandler`
- [x] `cli`/`sti` non-x86_64 fallback panics instead of silently
      fencing

### P2 — architecture cleanup (✅ done)
- [x] Duplicate IDT implementation (`interrupts.rs`) deleted;
      `idt_asm.S` lives in the `arch` crate
- [x] `syscall_stub_entry` parses the registers and dispatches
      through the syscall table
- [x] `bootstrap::early_init_for(mode)` consolidates the two
      `early_init` paths
- [x] `paging_init` PML4 indices match the comments

### P3 — workspace integration (✅ done)
- [x] All crates joined to the workspace
- [x] `plan9-kernel` depends on `plan9-net` / `plan9-ipc` /
      `plan9-servers`
- [x] `plan9-fs::vfs` aliased inside the kernel; kernel's internal
      `vfs.rs` retained as the shim
- [x] `plan9-net::netstack` exposes the `NetBackend` trait and a
      `LoopbackBackend` for boot-time smoke tests

### P4 — portability (✅ done)
- [x] `Arch` trait replaces bare `cfg(target_arch)` blocks
- [x] `cli`/`sti` are now methods on `InterruptControl`
- [x] Skeleton impls for i386 / aarch64 / riscv64 / loongarch64
- [x] `Makefile ARCH=…` selects the right QEMU binary
- [x] `build-tool check-all` runs `cargo check` for every triple

### P5 — drivers (✅ done)
- [x] `pci_table::PciDeviceTable` collects PCI scan results
- [x] Orphan driver files (`pnp`, `usb`, `flash`, `vmware_svga`,
      `virtio_net`, `vga_vesa`) are part of the lib
- [x] Audio + virtio-net drivers compile clean
- [x] `plan9-fs::devfs` registers `/dev/{draw,mouse,kbd,...}`
      entries that 9P mount servers can expose

### P6 — user space (✅ done)
- [x] `plan9-servers::rio` window table ready
- [x] `crates/rio` is a runnable host binary
- [x] `init` tries to exec `/rc/bin/rc` first, then falls back to
      its built-in shell

### P7 — quality (✅ done)
- [x] `cargo test` runs the synchronization, devfs, rio, fat,
      and regexp tests
- [x] README reflects current state
- [x] Debug serial output reduced (still verbose during early
      bring-up; will tighten as boot paths stabilise)

## 许可

MIT OR Apache-2.0
