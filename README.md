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

- [x] 项目结构
- [x] 核心 crate (common, kernel, arch)
- [x] 同步原语
- [x] 进程管理
- [x] 调度器
- [ ] 虚拟内存
- [ ] 设备驱动
- [ ] 网络栈
- [ ] 文件系统
- [ ] 启动加载器

## 许可

MIT OR Apache-2.0
