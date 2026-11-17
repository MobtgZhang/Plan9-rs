# Plan 9 Rust

用 Rust 语言重新实现 Plan 9 操作系统。

## 支持的架构

- **x86_64** (64 位 x86，Multiboot2 / GRUB / UEFI ISO)
- **aarch64** (ARM 64 位，QEMU `virt` 直接 `-kernel` 启动)
- **riscv64** (RISC-V 64 位，OpenSBI + QEMU `-kernel` 启动)
- **loongarch64** (LoongArch 64 位，QEMU `virt` 直接 `-kernel` 启动)

**i386 不在支持范围内。** 非 x86_64 平台目前完成内核早期启动、分页与
架构初始化，然后停在 halt 循环；完整的用户态 init/调度路径仍以
x86_64 为当前验证目标。

## 架构抽象：`plan9_arch::hal`

所有低层汇编、特权指令和架构专用 MMIO 代码都集中在 `source/crates/arch`。
内核与库只通过架构中立的门面访问硬件：

```rust
plan9_arch::hal::boot::early_init();
plan9_arch::hal::boot::paging_init();
plan9_arch::hal::cpu::hlt();
plan9_arch::hal::paging::phys_to_virt(...);
plan9_arch::hal::switch_to_user::switch_to_user_trampoline(...);
```

`hal` 下的每个模块按目标架构 `cfg` 选择对应实现：

- `boot` — `early_init` / `paging_init`
- `paging` — 页表、物理/虚拟地址转换、PTE 常量
- `mmu` — 地址空间切换、内核半区复制
- `cpu` — 中断控制、halt、CPU 标识
- `io` — 端口 I/O（仅 x86_64 有真实端口；其它架构提供显式 panic 的
  非端口 I/O stub，防止误用）
- `console` — 早期串口控制台
- `context` — 用户态切换
- `gdt` / `idt` — x86_64 受保护模式结构
- `smp` — x86_64 AP 启动

## 各架构启动布局

| 架构 | 内核物理基址 | 分页 / 启动方式 |
|---|---|---|
| x86_64 | `0x0010_0000` | Multiboot2 入口 → 早期 PML4 → GRUB/OVMF ISO |
| aarch64 | `0x4020_0000` | TTBR0/TTBR1；低 1 GiB 使用 Device-nGnRnE 映射；QEMU 直接加载 ELF |
| riscv64 | `0x8020_0000` | Sv39；OpenSBI 传入 `a0=hartid`、`a1=dtb`；`tp` 保存 hartid |
| loongarch64 | `0x0020_0000` | DMW0 低地址一致映射、DMW1 高位缓存窗口、DMW2 强不可缓存窗口 |

x86_64 的 IRQ 策略是：早期安装 IDT/PIC 并把所有 IRQ 屏蔽，`IF` 保持关闭；
调度器和设备注册完成后才由 `start_interrupts()` 解除 IRQ0/IRQ1 并执行 `sti`。

## 项目结构

```
Plan9-Rust/
├── source/                    # 源代码
│   ├── Cargo.toml             # 工作空间配置
│   ├── build_tool/            # Rust 构建编排工具
│   └── crates/
│       ├── arch/              # 架构代码（唯一允许低层汇编的地方）
│       │   ├── src/
│       │   │   ├── hal.rs     # 架构中立门面
│       │   │   ├── x86_64/
│       │   │   ├── aarch64/
│       │   │   ├── riscv64/
│       │   │   └── loongarch64/
│       │   └── Cargo.toml
│       ├── common/            # 公共类型、错误、同步原语
│       ├── kernel/            # 内核核心
│       │   ├── src/
│       │   │   ├── proc.rs    # 进程管理
│       │   │   ├── sched.rs   # 调度器
│       │   │   ├── trap.rs    # 陷阱处理
│       │   │   ├── vm.rs      # 虚拟内存
│       │   │   └── entry.rs   # kstart
│       │   └── Cargo.toml
│       ├── bootloader/
│       ├── cmd/                # Plan 9 /bin 命令集（no_std，x86_64 裸机 ELF）
│       │   ├── src/bin/        # rc echo ls cat date ...（28 个独立程序）
│       │   └── src/            # 共享运行时：syscall、行输入、格式化
│       ├── drivers/            # PCI、存储、网络、显示等
│       ├── fs/                # 文件系统
│       ├── ipc/
│       ├── net/
│       ├── servers/
│       └── userspace/
├── scripts/
├── build/                     # 构建输出
└── reference/                 # 原始 Plan 9 源码（参考）
```

每个内核目标都有自己的链接脚本：
`kernel-x86_64.ld`、`kernel-aarch64.ld`、`kernel-riscv64.ld`、
`kernel-loongarch64.ld`，以及对应的入口汇编：

- `src/arch/x86_64/boot.S`
- `src/arch/aarch64/boot.S`
- `src/arch/riscv64/boot.S`
- `src/arch/loongarch64/boot.S`

## 前置条件

- Rust 工具链
- QEMU（包含 `qemu-system-x86_64`、`qemu-system-aarch64`、
  `qemu-system-riscv64`、`qemu-system-loongarch64`）
- `xorriso`、`grub-mkrescue` / `grub-mkstandalone`（x86 ISO 路径）
- OVMF：`/usr/share/ovmf/OVMF.fd`
- OpenSBI：`/usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin`
- 交叉 GCC：`aarch64-linux-gnu-gcc`、`riscv64-linux-gnu-gcc`、
  `loongarch64-linux-gnu-gcc`

## 构建

所有构建逻辑由 `source/build_tool` 编排。`Makefile` 只负责选择架构、
调用 build-tool 和启动 QEMU。

```bash
# x86_64：构建内核、init、rootfs、ESP 与 ISO
make ARCH=x86_64 iso

# 其它架构：构建内核（直接 QEMU -kernel 启动，不需要 ISO）
make ARCH=aarch64 kernel
make ARCH=riscv64 kernel
make ARCH=loongarch64 kernel

# 全部目标做 cargo check
make check-all
```

`make ARCH=<arch> run-serial` 会构建对应目标并启动 QEMU，串口输出写到
`build/<arch>/serial.log`。`make ARCH=<arch> run` 使用图形显示。

注意：GRUB 的 `arm64-efi` / `riscv64-efi` / `loongarch64-efi` 模块在常见
发行版中并不随 `grub-mkrescue` 安装，因此 ISO/ESP 路径目前只支持
x86_64；非 x86 目标使用 QEMU 直接加载内核 ELF。

## QEMU 冒烟测试

```bash
# x86_64：GRUB + OVMF ISO
make ARCH=x86_64 run-serial

# aarch64：必须指定 cortex-a72，否则 QEMU 会报告架构不兼容
qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M \
  -kernel build/aarch64/kernel/plan9_kernel.elf \
  -display none -serial stdio -monitor none

# riscv64：OpenSBI 固件 + 直接 -kernel
qemu-system-riscv64 -M virt -m 512M \
  -bios /usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin \
  -kernel build/riscv64/kernel/plan9_kernel.elf \
  -display none -serial stdio -monitor none

# loongarch64：直接 -kernel
qemu-system-loongarch64 -M virt -m 512M \
  -kernel build/loongarch64/kernel/plan9_kernel.elf \
  -display none -serial stdio -monitor none
```

x86_64 冒烟路径会依次输出 PCI 设备扫描、GPU、调度器、SMP/MADT 和
init 加载，最后进入用户态 `[init] Plan 9 from Outer Space — Rust kernel`
与 `term%` 提示。非 x86 目标会输出架构早期初始化与分页初始化完成，
随后停在 halt 循环。

## 开发状态

Last updated: 2026-11-12

### P0 — bring-up (✅ done)
- [x] `kstart` 链式调用 frame allocator → heap → ACPI → timer → scheduler → init ELF
- [x] `switch_to_user` 通过 `plan9_arch::hal` 进入用户态 init 入口
- [x] Multiboot2 `MODULE` tag 保留 init cmdline 与模块范围
- [x] 堆分配器与 `KernelHeap` 接入
- [x] x86_64 ISO 在 QEMU 中启动并进入用户态 init shell

### P1 — synchronization hardening (✅ done)
- [x] `AtomicDWord::compare_exchange` 使用正确的寄存器绑定
- [x] `SleepChannel::sleep` 使用 epoch + waiting count
- [x] `TicketLock::try_lock` 实现真实 CAS 非阻塞锁
- [x] `RWLock::rlock` 消除读者/写者竞争
- [x] `ILockDepth` 为 `[AtomicU32; MAX_CPUS]`
- [x] `panic!` 通过可安装的 `PanicHandler` 路由

### P2 — architecture cleanup (✅ done)
- [x] 删除重复 IDT；`idt` 汇编集中在 `arch` crate
- [x] `syscall_stub_entry` 解析寄存器并分发系统调用
- [x] 早期 Paging 的 PML4 索引与注释一致
- [x] 所有内核调用点改用 `plan9_arch::hal`

### P3 — workspace integration (✅ done)
- [x] 所有 crate 加入工作空间
- [x] `plan9-kernel` 依赖 `plan9-net` / `plan9-ipc` / `plan9-servers`
- [x] `plan9-fs::vfs` 在 kernel 中以 shim 接入
- [x] `plan9-net::netstack` 暴露 `NetBackend` 与 `LoopbackBackend`

### P4 — portability (✅ done)
- [x] 四个目标（x86_64 / aarch64 / riscv64 / loongarch64）均可构建
- [x] 每个架构有独立的 boot 汇编、链接脚本与 QEMU 启动路径
- [x] `make ARCH=…` 选择对应 QEMU 二进制
- [x] `build-tool check-all` 对四个 target 执行 `cargo check`
- [x] 非 x86 目标完成 `early_init` + `paging_init` 后停在内核 halt 循环

### P5 — drivers (✅ done)
- [x] `PciDeviceIter` 按 bus/device/function 完整扫描并在末槽终止
- [x] PCI 配置地址支持 byte offset（`reg & 3`）
- [x] 存储、网络、显示与音频驱动纳入 crate
- [x] `plan9-fs::devfs` 注册 `/dev/{draw,mouse,kbd,...}`

### P6 — user space (✅ done)
- [x] `plan9-servers::rio` 窗口表可用
- [x] `crates/rio` 为可运行宿主二进制
- [x] `init` 优先执行 `/rc/bin/rc`，否则使用内置 shell

### P7 — quality (✅ done)
- [x] `cargo test` 覆盖同步、devfs、rio、fat、regexp
- [x] 四架构冒烟测试均无 panic
- [x] 早期 boot 串口输出已收敛到必要诊断信息

### P8 — Plan 9 命令集与 rc shell (✅ done)
- [x] 新 crate `plan9-cmd`：28 个独立的裸机 `/bin` 程序
      （rc echo pwd ls cat date sleep wc head tail grep sort uniq cp mv
       rm mkdir touch ps kill seq du tee tr cut stat time test），
       每个程序都是 `int 0x80` 门的 no_std ELF，语义对齐
       `plan9/sys/src/cmd/*` 原作
- [x] `rc` shell（`term%` 提示符）：`;` 命令列表、`#` 注释、
      `|` 管道、`<` `>` `>>` 重定向、完整 argv 传递、
      依次搜索 `/bin`、`/rc/bin`、`/boot`
- [x] 内核新增 `TIME` 系统调用：CMOS RTC（`crates/kernel/src/rtc.rs`）
      提供真实日历时间，供 `date` 使用；uptime 供 `time` 使用
- [x] 内核新增 `GETCWD` 系统调用：`CHDIR` 记录规范化路径，
      `pwd`/`getwd` 由内核返回（fork 继承）
- [x] rootfs 目录 `stat` 现在带 `CHDIR` 位，`ls -l` 能渲染目录标志
- [x] 用户程序栈扩大到 64 KiB；exec 加载器支持 `.bss`（memsz>filesz）
- [x] 构建工具：全部命令安装进 rootfs `/bin`，`rc` 同时装入
      `/rc/bin/rc`；ISO 目录树修复 `plan9root/boot/rootfs.cpio`
      缺失导致 GRUB 找不到 RAM root 的问题
- [x] init 以 Plan 9 方式 respawn `/rc/bin/rc`（最多 3 次），
      之后退回内置 shell

## 许可

MIT OR Apache-2.0
