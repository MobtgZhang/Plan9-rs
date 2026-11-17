//! Plan 9 Build Tool
//!
//! A Rust-based build orchestration tool that handles:
//! - Kernel and init binary compilation
//! - UEFI boot-loader construction (replaces GRUB on all four archs)
//!   - x86_64/aarch64: `*-unknown-uefi` target -> PE32+ EFI directly
//!   - riscv64/loongarch64: bare-metal ELF -> ELF→PE32+ wrap.rs packager
//! - Root filesystem generation
//! - EFI System Partition (ESP) creation
//! - ISO image building
//!
//! This tool replaces the Makefile-based build system with a pure Rust solution.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::Command;

mod wrap;

/// Build command options (applied globally)
#[derive(Parser, Debug)]
struct BuildOpts {
    /// Architecture to build for
    #[arg(short, long, default_value = "x86_64")]
    arch: String,

    /// Build directory (default: <project_root>/build)
    #[arg(short = 'B', long)]
    build_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Build everything: kernel, bootloader, ESP, rootfs, and ISO
    All(#[allow(dead_code)] BuildOpts),
    /// Build the kernel ELF
    Kernel(#[allow(dead_code)] BuildOpts),
    /// Build the init binary
    Init(#[allow(dead_code)] BuildOpts),
    /// Build the UEFI boot loader (replaces GRUB)
    Bootloader(#[allow(dead_code)] BuildOpts),
    /// Build the EFI System Partition
    Esp(#[allow(dead_code)] BuildOpts),
    /// Build the root filesystem
    Rootfs(#[allow(dead_code)] BuildOpts),
    /// Build the ISO image
    Iso(#[allow(dead_code)] BuildOpts),
    /// Clean build artifacts
    Clean,
    /// Run `cargo check` for every supported architecture. Used by
    /// CI to make sure the kernel keeps cross-compiling cleanly.
    CheckAll,
}

#[derive(Parser, Debug)]
#[command(
    name = "plan9-build",
    about = "Build tool for Plan 9 from Outer Space (Rust Edition)"
)]
struct Args {
    #[command(flatten)]
    opts: BuildOpts,

    #[command(subcommand)]
    command: Commands,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Find project root (parent of source/)
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source_dir = manifest_dir.parent().unwrap();
    let project_root = source_dir.parent().unwrap();

    let opts = &args.opts;
    let build_dir = opts.build_dir.clone().unwrap_or_else(|| project_root.join("build").join(&opts.arch));
    let build = Builder::new(project_root, source_dir, &build_dir, &opts.arch);

    match args.command {
        Commands::All(_) => build.build_all(),
        Commands::Kernel(_) => build.build_kernel(),
        Commands::Init(_) => build.build_init(),
        Commands::Bootloader(_) => build.build_bootloader(),
        Commands::Esp(_) => build.build_esp(),
        Commands::Rootfs(_) => build.build_rootfs(),
        Commands::Iso(_) => build.build_iso(),
        Commands::CheckAll => build.check_all_archs(),
        Commands::Clean => {
            // Clean uses default paths for all architectures
            let build_dir = project_root.join("build");
            let target_dir = source_dir.join("target");
            
            println!("[CLEAN] Removing build directory...");
            if build_dir.exists() {
                std::fs::remove_dir_all(&build_dir)?;
            }
            if target_dir.exists() {
                std::fs::remove_dir_all(&target_dir)?;
            }
            println!("[CLEAN] Done");
            Ok(())
        }
    }
}

/// Main build orchestrator
struct Builder {
    #[allow(dead_code)]
    project_root: PathBuf,
    source_dir: PathBuf,
    build_dir: PathBuf,
    arch: String,
}

impl Builder {
    fn new(
        project_root: &Path,
        source_dir: &Path,
        build_dir: &Path,
        arch: &str,
    ) -> Self {
        Self {
            project_root: project_root.to_path_buf(),
            source_dir: source_dir.to_path_buf(),
            build_dir: build_dir.to_path_buf(),
            arch: arch.to_string(),
        }
    }

    fn target_triple(&self) -> &str {
        match self.arch.as_str() {
            "x86_64" => "x86_64-unknown-uefi",
            "aarch64" => "aarch64-unknown-uefi",
            "riscv64" => "riscv64gc-unknown-none-elf",
            "loongarch64" => "loongarch64-unknown-none",
            _ => "x86_64-unknown-uefi",
        }
    }

    /// Bare-metal target triple used for the kernel, init and user commands
    /// (they are plain ELF images loaded by uefiboot, not EFI applications).
    fn kernel_triple(&self) -> &str {
        match self.arch.as_str() {
            "x86_64" => "x86_64-unknown-none",
            "aarch64" => "aarch64-unknown-none",
            "riscv64" => "riscv64gc-unknown-none-elf",
            "loongarch64" => "loongarch64-unknown-none",
            _ => "x86_64-unknown-none",
        }
    }

    /// Is the arch's uefiboot built via an official `*-unknown-uefi` target
    /// (producing a PE32+ EFI directly)?  riscv64/loongarch64 use bare-metal
    /// ELF + the ELF→PE packager instead.
    fn is_uefi_target(&self) -> bool {
        self.arch == "x86_64" || self.arch == "aarch64"
    }

    /// Name of the firmware-loadable EFI application for this arch.
    fn efi_app_name(&self) -> &str {
        match self.arch.as_str() {
            "x86_64" => "BOOTX64.EFI",
            "aarch64" => "BOOTAA64.EFI",
            "riscv64" => "BOOTRISCV64.EFI",
            "loongarch64" => "BOOTLOONGARCH64.EFI",
            _ => "BOOTX64.EFI",
        }
    }


    /// User-space init, bash and ssh are x86_64 programs that use the
    /// `int 0x80` syscall gate.  Other architectures currently only bring
    /// up the kernel.
    fn is_x86_64(&self) -> bool {
        self.arch == "x86_64"
    }

    /// Architectures with a ported ring-3 user space (init + plan9-cmd
    /// built for the bare-metal kernel triple with a `svc`/`int 0x80`
    /// syscall gate).  Bash and SSH ports remain x86_64-only.
    fn has_user_space(&self) -> bool {
        self.arch == "x86_64" || self.arch == "aarch64"
    }

    /// Build the Plan 9 command binaries (`/bin/*`, `/rc/bin/rc`).
    fn build_cmds(&self) -> Result<()> {
        if !self.has_user_space() {
            println!("[BUILD] Skipping plan9-cmd (user space not ported to this architecture)");
            return Ok(());
        }
        println!("[BUILD] Compiling plan9-cmd commands...");
        let status = Command::new("cargo")
            .arg("build")
            .arg("--manifest-path")
            .arg(self.source_dir.join("Cargo.toml"))
            .arg("-p")
            .arg("plan9-cmd")
            .arg("--target")
            .arg(self.kernel_triple())
            .arg("--release")
            .status()
            .context("Failed to build plan9-cmd")?;
        if !status.success() {
            anyhow::bail!("plan9-cmd build failed");
        }
        println!("[BUILD] plan9-cmd commands built");
        Ok(())
    }

    /// Install the command binaries into the root filesystem.
    fn install_cmds(&self) -> Result<Vec<String>> {
        let mut installed = Vec::new();
        if !self.has_user_space() {
            return Ok(installed);
        }
        let bin_dir = self.rootfs_dir().join("bin");
        std::fs::create_dir_all(&bin_dir)?;
        let rc_bin_dir = self.rootfs_dir().join("rc").join("bin");
        std::fs::create_dir_all(&rc_bin_dir)?;

        let release = self
            .source_dir
            .join("target")
            .join(self.kernel_triple())
            .join("release");
        for name in [
            "rc", "echo", "pwd", "ls", "cat", "date", "sleep", "wc", "head", "tail",
            "grep", "sort", "uniq", "cp", "mv", "rm", "mkdir", "touch", "ps", "kill",
            "seq", "du", "tee", "tr", "cut", "stat", "time", "test",
            // Identity and permission management.
            "whoami", "hostname", "id", "chmod", "chown", "useradd", "usermod",
            "group", "su", "passwd",
            // Extended coreutils set.
            "clear", "env", "basename", "dirname", "true", "false", "cmp", "diff",
            "nl", "more", "rmdir", "ln", "uptime", "who", "expr", "fortune",
            "units", "dc", "ed", "yes", "tty", "uname", "printf",
        ] {
            let src = release.join(name);
            if !src.exists() {
                anyhow::bail!("command binary not found: {}", src.display());
            }
            std::fs::copy(&src, bin_dir.join(name))?;
            installed.push(name.to_string());
        }
        // Plan 9 keeps the shell in /rc/bin.
        std::fs::copy(release.join("rc"), rc_bin_dir.join("rc"))?;
        installed.push("rc@/rc/bin".to_string());
        Ok(installed)
    }

    // =============================================================================
    // UEFI boot-loader construction (replaces GRUB)
    // =============================================================================

    /// Build the UEFI boot loader for this architecture:
    ///   - x86_64/aarch64: `*-unknown-uefi` target -> PE32+ EFI directly
    ///   - riscv64/loongarch64: bare-metal ELF -> ELF→PE32+ wrap.rs packager
    fn build_bootloader(&self) -> Result<()> {
        println!("[BUILD] Building UEFI boot loader for {} ...", self.arch);
        self.ensure_dirs()?;

        let uefi_elf = self.uefi_elf_source();
        if !uefi_elf.exists() {
            anyhow::bail!(
                "uefiboot ELF not found at {}. Build it first with \
                 'cargo build -p plan9-uefiboot --target {} --release'",
                uefi_elf.display(),
                self.target_triple()
            );
        }

        let out_efi = self.boot_efi();
        std::fs::create_dir_all(out_efi.parent().unwrap())?;

        if self.is_uefi_target() {
            // Official UEFI target emits PE32+ directly: just copy it.
            std::fs::copy(&uefi_elf, &out_efi)?;
            println!("[BUILD] Bootloader (PE32+): {}", out_efi.display());
        } else {
            // Bare-metal ELF -> wrap into a PE32+ EFI application.
            wrap::wrap_elf_to_pe(&uefi_elf, &out_efi, self.arch.as_str())?;
        }
        Ok(())
    }

    /// Path to the freshly compiled uefiboot ELF/PE for this arch.
    fn uefi_elf_source(&self) -> PathBuf {
        let base = if self.is_uefi_target() {
            "uefiboot.efi"
        } else {
            "uefiboot"
        };
        self.source_dir
            .join("target")
            .join(self.target_triple())
            .join("release")
            .join(base)
    }

    // =============================================================================
    // Directory paths
    // =============================================================================
    /// triple. Useful as a CI gate: it ensures that the kernel /
    /// arch crates keep cross-compiling cleanly even on architectures
    /// we don't yet boot.
    fn check_all_archs(&self) -> Result<()> {
        let triples = [
            "x86_64-unknown-none",
            "aarch64-unknown-none",
            "riscv64gc-unknown-none-elf",
            "loongarch64-unknown-none",
        ];
        let mut failures: Vec<String> = Vec::new();
        for triple in &triples {
            println!("[CHECK] {}", triple);
            let status = Command::new("cargo")
                .arg("check")
                .arg("-p")
                .arg("plan9-kernel")
                .arg("--manifest-path")
                .arg(self.source_dir.join("Cargo.toml"))
                .arg("--target")
                .arg(triple)
                .arg("--release")
                .status()
                .with_context(|| format!("cargo check for {}", triple))?;
            if !status.success() {
                failures.push(triple.to_string());
            }
        }
        if !failures.is_empty() {
            anyhow::bail!("cargo check failed for: {}", failures.join(", "));
        }
        println!("[CHECK] all targets OK");
        Ok(())
    }

    fn boot_efi_name(&self) -> &str {
        self.efi_app_name()
    }

    // =============================================================================
    // Directory paths
    // =============================================================================

    fn kernel_build_dir(&self) -> PathBuf {
        self.build_dir.join("kernel")
    }

    fn kernel_elf_source(&self) -> PathBuf {
        // Kernel is built with --target x86_64-unknown-none
        self.source_dir
            .join("target")
            .join(self.kernel_triple())
            .join("release")
            .join("plan9_kernel")
    }

    fn kernel_elf(&self) -> PathBuf {
        self.kernel_build_dir().join("plan9_kernel.elf")
    }

    fn kernel_boot_elf(&self) -> PathBuf {
        self.rootfs_dir().join("boot").join("9kernel.elf")
    }

    fn init_elf_source(&self) -> PathBuf {
        // Init is built with --target x86_64-unknown-none --release
        self.source_dir
            .join("target")
            .join(self.kernel_triple())
            .join("release")
            .join("plan9_init")
    }

    fn init_boot_elf(&self) -> PathBuf {
        self.rootfs_dir().join("boot").join("init")
    }

    fn bash_elf_source(&self) -> PathBuf {
        self.source_dir
            .join("target")
            .join(self.kernel_triple())
            .join("release")
            .join("bash")
    }

    fn ssh_elf_source(&self) -> PathBuf {
        self.source_dir
            .join("target")
            .join(self.kernel_triple())
            .join("release")
            .join("ssh")
    }

    fn rootfs_cpio(&self) -> PathBuf {
        self.build_dir.join("rootfs.cpio")
    }

    fn rootfs_dir(&self) -> PathBuf {
        self.build_dir.join("plan9root")
    }

    fn esp_dir(&self) -> PathBuf {
        self.build_dir.join("esp")
    }

    fn boot_efi(&self) -> PathBuf {
        self.esp_dir()
            .join("EFI")
            .join("BOOT")
            .join(self.boot_efi_name())
    }

    fn iso_file(&self) -> PathBuf {
        self.build_dir.join("plan9.iso")
    }

    fn stamp_file(&self, name: &str) -> PathBuf {
        self.build_dir.join(format!(".{}", name))
    }

    // =============================================================================
    // Build steps
    // =============================================================================

    fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(self.kernel_build_dir())?;
        std::fs::create_dir_all(self.rootfs_dir().join("boot"))?;
        std::fs::create_dir_all(self.esp_dir().join("EFI").join("BOOT"))?;
        std::fs::create_dir_all(self.esp_dir().join("EFI").join("PLAN9"))?;
        Ok(())
    }

    fn sync_rootfs(&self) -> Result<()> {
        println!("[BUILD] Creating root filesystem structure...");

        // Delete and recreate rootfs
        if self.rootfs_dir().exists() {
            std::fs::remove_dir_all(&self.rootfs_dir())?;
        }

        // Create standard Plan 9 directory structure
        let plan9_dirs = [
            "bin", "boot", "cfg", "dev", "etc", "home", "home/glenda", "proc",
            "tmp", "usr", "adm", "env", "fd", "mnt", "n", "net", "rc", "rc/bin",
            "srv", "lib", "lib/modules", "lib/modules/dev",
            "lib/modules/fs", "lib/modules/ipc", "lib/modules/net",
            "usr/glenda",
        ];

        for dir in &plan9_dirs {
            let path = self.rootfs_dir().join(dir);
            std::fs::create_dir_all(&path)?;
        }
        std::fs::create_dir_all(self.rootfs_dir().join("lib").join("fonts"))?;

        // Touch stamp file
        std::fs::write(self.stamp_file("rootfs-stamp"), "")?;

        println!("[BUILD] Rootfs created: {}", self.rootfs_dir().display());
        Ok(())
    }

    fn build_init(&self) -> Result<()> {
        if !self.has_user_space() {
            println!("[BUILD] Skipping plan9-init (user space not ported to this architecture)");
            return Ok(());
        }
        println!("[BUILD] Compiling plan9-init...");
        self.ensure_dirs()?;
        
        // Build init from workspace with bare-metal target and release profile.
        let mut cmd = std::process::Command::new("cargo");
        cmd.arg("build")
           .arg("--manifest-path")
           .arg(self.source_dir.join("Cargo.toml"))
           .arg("-p")
           .arg("plan9-init")
           .arg("--target")
           .arg(self.kernel_triple())
           .arg("--release");
        let status = cmd.status().context("Failed to build init")?;
        if !status.success() {
            anyhow::bail!("init build failed");
        }
        
        // Ensure the init binary exists
        if !self.init_elf_source().exists() {
            anyhow::bail!(
                "Init binary not found at {}. Build may have failed.",
                self.init_elf_source().display()
            );
        }
        if !self.bash_elf_source().exists() {
            anyhow::bail!("bash binary not found at {}", self.bash_elf_source().display());
        }
        if !self.ssh_elf_source().exists() {
            anyhow::bail!("ssh binary not found at {}", self.ssh_elf_source().display());
        }
        
        println!("[BUILD] plan9-init, bash and ssh built successfully");
        Ok(())
    }

    fn build_kernel(&self) -> Result<()> {
        println!("[BUILD] Compiling plan9-kernel...");
        self.ensure_dirs()?;
        
        // The x86_64 boot image carries init; other architectures only
        // build the kernel at this stage.
        if self.has_user_space() {
            self.build_init()?;
        }
        
        // Build kernel with the bare-metal target and release profile.
        let mut cmd = std::process::Command::new("cargo");
        cmd.arg("build")
           .arg("-p")
           .arg("plan9-kernel")
           .arg("--manifest-path")
           .arg(self.source_dir.join("Cargo.toml"))
           .arg("--target")
           .arg(self.kernel_triple())
           .arg("--release");
        let status = cmd.status().context("Failed to build kernel")?;
        if !status.success() {
            anyhow::bail!("kernel build failed");
        }
        
        // Copy kernel from crate's target to build directory
        let src_kernel = self.kernel_elf_source();
        
        if !src_kernel.exists() {
            anyhow::bail!("Kernel binary not found at {}. Build may have failed.", src_kernel.display());
        }
        
        std::fs::create_dir_all(&self.kernel_build_dir())?;
        std::fs::copy(&src_kernel, &self.kernel_elf())
            .context("Failed to copy kernel to build directory")?;
        
        println!("[BUILD] Kernel built: {}", self.kernel_elf().display());
        Ok(())
    }

    /// Build the EFI System Partition for all four architectures:
    ///
    ///   EFI/BOOT/BOOT<ARCH>.EFI    (the uefiboot boot loader)
    ///   \boot\9kernel.elf          (kernel image, loaded by uefiboot)
    ///   \boot\init                   (x86_64 only: userspace init)
    ///   \boot\rootfs.cpio            (x86_64 only: RAM root archive)
    fn build_esp(&self) -> Result<()> {
        println!("[BUILD] Building EFI System Partition for {} ...", self.arch);
        self.ensure_dirs()?;

        // Always build rootfs (+ kernel) so a source change lands in the ISO.
        self.build_rootfs()?;

        // Build the UEFI boot loader (replaces GRUB).
        self.build_bootloader()?;

        let esp_boot = self.esp_dir().join("boot");
        std::fs::create_dir_all(&esp_boot)?;
        std::fs::copy(&self.kernel_elf(), esp_boot.join("9kernel.elf"))?;
        // init/bash/ssh are x86_64 user-space binaries (ring-3 ELF over
        // int 0x80); other architectures ship kernel + rootfs only.
        if self.init_elf_source().exists() {
            std::fs::copy(&self.init_elf_source(), esp_boot.join("init"))?;
        }
        std::fs::copy(&self.rootfs_cpio(), esp_boot.join("rootfs.cpio"))?;

        println!("[BUILD] ESP built: {}", self.esp_dir().display());
        Ok(())
    }

    fn build_rootfs(&self) -> Result<()> {
        println!("[BUILD] Building root filesystem...");
        self.ensure_dirs()?;
        
        // Sync base rootfs
        self.sync_rootfs()?;        
        // Always rebuild the kernel and user programs so a source change is
        // reflected in the boot image and the root archive.
        self.build_kernel()?;

        // Install kernel to boot; init is only present for x86_64.
        std::fs::copy(&self.kernel_elf(), &self.kernel_boot_elf())?;
        if self.has_user_space() {
            self.build_init()?;
            std::fs::copy(&self.init_elf_source(), &self.init_boot_elf())?;
        }

        // Build and install the Plan 9 command binaries into /bin and
        // /rc/bin/rc.
        self.build_cmds()?;
        let installed = self.install_cmds()?;
        println!(
            "[BUILD] Installed {} user commands into /bin (+ /rc/bin/rc)",
            installed.len()
        );

        // Install the built-in Sarasa-Gothic terminal font.
        let font_src = self.project_root.join("source").join("fonts")
            .join("SarasaTermSC-Regular-subset.ttf");
        if font_src.exists() {
            std::fs::create_dir_all(self.rootfs_dir().join("lib").join("fonts"))?;
            std::fs::copy(&font_src, self.rootfs_dir().join("lib").join("fonts")
                .join("SarasaTermSC-Regular.ttf"))?;
        }

        // Install the Bash and SSH ports into /bin (x86_64-only).
        // NOTE: /rc/bin/rc is installed by install_cmds() from the real
        // plan9-cmd shell; do not overwrite it with the (broken) bash ELF.
        if self.is_x86_64() {
            std::fs::create_dir_all(self.rootfs_dir().join("bin"))?;
            std::fs::copy(&self.bash_elf_source(), self.rootfs_dir().join("bin").join("bash"))?;
            std::fs::copy(&self.ssh_elf_source(), self.rootfs_dir().join("bin").join("ssh"))?;
        }
        
        // Make them executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&self.kernel_boot_elf())?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&self.kernel_boot_elf(), perms)?;
            
            if self.has_user_space() {
                let mut perms = std::fs::metadata(&self.init_boot_elf())?.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&self.init_boot_elf(), perms)?;
            }

            if self.is_x86_64() {
                for p in [
                    self.rootfs_dir().join("bin").join("bash"),
                    self.rootfs_dir().join("bin").join("ssh"),
                    self.rootfs_dir().join("rc").join("bin").join("rc"),
                ] {
                    let mut perms = std::fs::metadata(&p)?.permissions();
                    perms.set_mode(0o755);
                    std::fs::set_permissions(&p, perms)?;
                }
            }
        }

        // Package the root tree as a newc cpio archive. GRUB loads it as
        // a Multiboot2 module, and the kernel imports it into the RAM root.
        println!("[BUILD] Creating rootfs.cpio...");
        let cpio = self.rootfs_cpio();
        let status = Command::new("bash")
            .arg("-c")
            // The kernel image is only needed for ISO (multiboot) boots;
            // shipping it inside the RAM rootfs would waste ~8 MiB of kernel
            // heap, which the boot bump-allocator cannot reclaim.
            .arg(format!(
                "find . -print | grep -v -x -e './boot/9kernel.elf' | cpio -o -H newc -O '{}'",
                cpio.display()
            ))
            .current_dir(self.rootfs_dir())
            .status()
            .context("Failed to create rootfs.cpio")?;
        if !status.success() {
            anyhow::bail!("cpio failed");
        }

        println!("[BUILD] Rootfs built: {}", self.rootfs_dir().display());
        println!("[BUILD] Rootfs archive: {}", cpio.display());

        // The ISO grub.cfg boots the kernel from /plan9root/boot/, so the
        // RAM-root archive must be present inside the ISO tree as well.
        // (Copied after cpio creation so the archive never contains itself.)
        std::fs::create_dir_all(self.rootfs_dir().join("boot"))?;
        std::fs::copy(&cpio, self.rootfs_dir().join("boot").join("rootfs.cpio"))?;
        Ok(())
    }

    fn build_iso(&self) -> Result<()> {
        println!("[BUILD] Building ISO image for {} ...", self.arch);

        // Always rebuild ESP/rootfs so a freshly built kernel and init are
        // reflected in the ISO.  All four architectures share the same UEFI
        // layout: EFI/BOOT/BOOT<ARCH>.EFI + \boot\*.
        self.build_esp()?;

        // Assemble the ISO tree.
        let tmp_dir = tempfile::tempdir_in(self.build_dir.parent().unwrap())?;

        // Build a FAT12 ESP image holding the boot loader + kernel (+init/rootfs).
        // xorriso's -e needs a real FAT El Torito boot image, not a directory.
        let esp_img = tmp_dir.path().join("esp.img");
        let esp_mb: u64 = 32;
        let status = Command::new("dd")
            .arg("if=/dev/zero")
            .arg(format!("of={}", esp_img.display()))
            .arg("bs=1024")
            .arg(format!("count={}", esp_mb * 1024))
            .status()
            .context("Failed to create ESP image")?;
        if !status.success() {
            anyhow::bail!("dd failed to create ESP image");
        }
        let mkfs = Command::new("mkfs.vfat")
            .arg("-F")
            .arg("12")
            .arg("-n")
            .arg("PLAN9ESP")
            .arg(&esp_img)
            .status()
            .context("Failed to run mkfs.vfat")?;
        if !mkfs.success() {
            anyhow::bail!("mkfs.vfat failed");
        }

        // Copy EFI/BOOT/BOOT<ARCH>.EFI and \boot\* into the ESP image.
        let mcopy = |src: &Path, dst: &str| -> Result<()> {
            let st = Command::new("mcopy")
                .arg("-i")
                .arg(&esp_img)
                .arg(src)
                .arg(format!("::{}", dst))
                .status()
                .context("Failed to run mcopy")?;
            if !st.success() {
                anyhow::bail!("mcopy {} -> {}", src.display(), dst);
            }
            Ok(())
        };
        let mmd = |path: &str| -> Result<()> {
            let st = Command::new("mmd")
                .arg("-i")
                .arg(&esp_img)
                .arg(format!("::{}", path))
                .status()
                .context("Failed to run mmd")?;
            if !st.success() {
                anyhow::bail!("mmd {}", path);
            }
            Ok(())
        };

        mmd("/EFI")?;
        mmd("/EFI/BOOT")?;
        mmd("/boot")?;
        mcopy(&self.boot_efi(), &format!("/EFI/BOOT/{}", self.boot_efi_name()))?;
        mcopy(&self.kernel_boot_elf(), "/boot/9kernel.elf")?;
        if self.init_boot_elf().exists() {
            mcopy(&self.init_boot_elf(), "/boot/init")?;
        }
        mcopy(&self.rootfs_cpio(), "/boot/rootfs.cpio")?;

        // Volume label matters: OVMF/EDK2 scans every El Torito/ISO9660
        // volume for EFI/BOOT.
        let mut cmd = Command::new("xorriso");
        cmd.arg("-as").arg("mkisofs")
            .arg("-r")
            .arg("-V").arg("PLAN9BOOT")
            .arg("-e").arg("esp.img").arg("-no-emul-boot")
            .arg("-o").arg(&self.iso_file())
            .arg(tmp_dir.path());
        let status = cmd.status().context("Failed to run xorriso")?;
        if !status.success() {
            anyhow::bail!("xorriso failed for {}", self.arch);
        }

        println!("[BUILD] ISO built: {}", self.iso_file().display());
        Ok(())
    }

    fn build_all(&self) -> Result<()> {
        println!("[BUILD] Building all components for {}...", self.arch);
        self.build_iso()?;
        println!("[BUILD] All components built successfully!");
        Ok(())
    }
}

/// Recursively copy a directory (kept for possible future use).
#[allow(dead_code)]
fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        
        if ty.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    
    Ok(())
}
