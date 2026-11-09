//! Plan 9 Build Tool
//!
//! A Rust-based build orchestration tool that handles:
//! - Kernel and init binary compilation
//! - Root filesystem generation
//! - EFI System Partition (ESP) creation
//! - ISO image building
//!
//! This tool replaces the Makefile-based build system with a pure Rust solution.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::Command;

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
    /// Build everything: kernel, ESP, rootfs, and ISO
    All(#[allow(dead_code)] BuildOpts),
    /// Build the kernel ELF
    Kernel(#[allow(dead_code)] BuildOpts),
    /// Build the init binary
    Init(#[allow(dead_code)] BuildOpts),
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
            "x86_64" => "x86_64-unknown-none",
            "aarch64" => "aarch64-unknown-none",
            "riscv64" => "riscv64gc-unknown-none-elf",
            "loongarch64" => "loongarch64-unknown-none",
            _ => "x86_64-unknown-none",
        }
    }

    fn grub_platform(&self) -> &str {
        match self.arch.as_str() {
            "x86_64" => "x86_64-efi",
            "aarch64" => "arm64-efi",
            "riscv64" => "riscv64-efi",
            "loongarch64" => "loongarch64-efi",
            _ => "x86_64-efi",
        }
    }

    /// Run `cargo check` against every supported architecture
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
        match self.arch.as_str() {
            "x86_64" => "BOOTX64.EFI",
            "aarch64" => "BOOTAA64.EFI",
            "riscv64" => "BOOTRISCV64.EFI",
            "loongarch64" => "BOOTLOONGARCH64.EFI",
            _ => "BOOTX64.EFI",
        }
    }

    fn grub_efi_name(&self) -> &str {
        match self.arch.as_str() {
            "x86_64" => "grub-x86_64.efi",
            "aarch64" => "grub-aarch64.efi",
            "riscv64" => "grub-riscv64.efi",
            "loongarch64" => "grub-loongarch64.efi",
            _ => "grub-x86_64.efi",
        }
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
            .join(self.target_triple())
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
            .join(self.target_triple())
            .join("release")
            .join("plan9_init")
    }

    fn init_boot_elf(&self) -> PathBuf {
        self.rootfs_dir().join("boot").join("init")
    }

    fn bash_elf_source(&self) -> PathBuf {
        self.source_dir
            .join("target")
            .join(self.target_triple())
            .join("release")
            .join("bash")
    }

    fn ssh_elf_source(&self) -> PathBuf {
        self.source_dir
            .join("target")
            .join(self.target_triple())
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

    fn grub_cfg_esp(&self) -> PathBuf {
        self.esp_dir().join("EFI").join("PLAN9").join("grub.cfg")
    }

    fn grub_cfg_iso(&self) -> PathBuf {
        self.build_dir.join("boot-grub.cfg")
    }

    fn grub_efi(&self) -> PathBuf {
        self.esp_dir()
            .join("EFI")
            .join("PLAN9")
            .join(self.grub_efi_name())
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

    fn grub_cfg_bin(&self) -> PathBuf {
        // grub-cfg is a host tool, built in workspace target directory
        self.source_dir.join("target").join("debug").join("grub-cfg")
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

    fn build_init(&self) -> Result<()> {
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
           .arg(self.target_triple())
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
        
        // Kernel build depends on init, so build it first
        self.build_init()?;
        
        // Build kernel with the bare-metal target and release profile.
        let mut cmd = std::process::Command::new("cargo");
        cmd.arg("build")
           .arg("-p")
           .arg("plan9-kernel")
           .arg("--manifest-path")
           .arg(self.source_dir.join("Cargo.toml"))
           .arg("--target")
           .arg(self.target_triple())
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

    fn build_grub_cfg_tool(&self) -> Result<()> {
        // Always build the host grub-cfg tool so the generated config does
        // not use a stale binary from a previous checkout.
        println!("[BUILD] Building grub-cfg tool...");
        let mut cmd = std::process::Command::new("cargo");
        cmd.arg("build")
           .arg("--manifest-path")
           .arg(self.source_dir.join("Cargo.toml"))
           .arg("-p")
           .arg("grub-cfg");
        let status = cmd.status().context("Failed to build grub-cfg")?;
        if !status.success() {
            anyhow::bail!("grub-cfg build failed");
        }
        Ok(())
    }

    fn generate_grub_cfg(&self, output: &Path, iso_mode: bool) -> Result<()> {
        self.build_grub_cfg_tool()?;
        
        let cmdline = "console=0 serial";
        
        let mut cmd = Command::new(&self.grub_cfg_bin());
        cmd.arg(&self.kernel_boot_elf())
           .arg(&self.init_boot_elf())
           .arg(cmdline)
           .arg(output);

        if iso_mode {
            cmd.arg("--iso");
        }
        if self.rootfs_cpio().exists() {
            cmd.arg("--module");
            cmd.arg(&self.rootfs_cpio());
        }

        let status = cmd.status().context("Failed to run grub-cfg")?;
        
        if !status.success() {
            anyhow::bail!("grub-cfg failed with exit code {:?}", status.code());
        }

        println!("[BUILD] Generated: {}", output.display());
        Ok(())
    }

    fn build_esp(&self) -> Result<()> {
        println!("[BUILD] Building EFI System Partition...");
        self.ensure_dirs()?;

        // The ESP needs the kernel, init and the rootfs archive together.
        self.build_rootfs()?;

        let esp_boot = self.esp_dir().join("boot");
        std::fs::create_dir_all(&esp_boot)?;
        std::fs::copy(&self.kernel_elf(), esp_boot.join("9kernel.elf"))?;
        std::fs::copy(&self.init_elf_source(), esp_boot.join("init"))?;
        std::fs::copy(&self.rootfs_cpio(), esp_boot.join("rootfs.cpio"))?;

        // Copy user programs and boot files into the ESP for completeness.
        std::fs::copy(&self.bash_elf_source(), esp_boot.join("bash"))?;
        std::fs::copy(&self.ssh_elf_source(), esp_boot.join("ssh"))?;

        // Generate grub.cfg for ESP
        self.generate_grub_cfg(&self.grub_cfg_esp(), false)?;
        
        // Create standalone GRUB EFI
        let tmp_dir = tempfile::tempdir()?;
        std::fs::copy(
            &self.grub_cfg_esp(),
            tmp_dir.path().join("grub.cfg"),
        )?;

        let mut cmd = Command::new("grub-mkstandalone");
        cmd.current_dir(tmp_dir.path());
        cmd.arg("-O")
           .arg(self.grub_platform())
           .arg("--locales=")
           .arg("--themes=")
           .arg("--install-modules=efi_gop all_video font gfxterm gfxmenu png terminal terminfo serial multiboot2 normal regexp cat ls echo test sleep configfile search search_fs_uuid search_fs_file part_gpt part_msdos fat ext2")
           .arg("-o")
           .arg(&self.grub_efi())
           .arg("boot/grub/grub.cfg=grub.cfg")
           .arg(format!("boot/9kernel.elf={}", self.kernel_elf().display()))
           .arg(format!("boot/init={}", self.init_elf_source().display()))
           .arg(format!("boot/rootfs.cpio={}", self.rootfs_cpio().display()))
           .arg(format!("boot/bash={}", self.bash_elf_source().display()))
           .arg(format!("boot/ssh={}", self.ssh_elf_source().display()));

        let status = cmd.status().context("Failed to run grub-mkstandalone")?;
        
        if !status.success() {
            anyhow::bail!("grub-mkstandalone failed");
        }

        // Copy to BOOT directory
        std::fs::create_dir_all(self.boot_efi().parent().unwrap())?;
        std::fs::copy(&self.grub_efi(), &self.boot_efi())?;

        println!("[BUILD] ESP built: {}", self.esp_dir().display());
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
            "bin", "boot", "cfg", "dev", "proc", "tmp", "usr",
            "adm", "env", "fd", "mnt", "n", "net", "rc", "rc/bin",
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

    fn build_rootfs(&self) -> Result<()> {
        println!("[BUILD] Building root filesystem...");
        self.ensure_dirs()?;
        
        // Sync base rootfs
        self.sync_rootfs()?;
        
        // Always rebuild the kernel and user programs so a source change is
        // reflected in the boot image and the root archive.
        self.build_kernel()?;
        self.build_init()?;

        // Install kernel and init to boot
        std::fs::copy(&self.kernel_elf(), &self.kernel_boot_elf())?;
        std::fs::copy(&self.init_elf_source(), &self.init_boot_elf())?;

        // Install the built-in Sarasa-Gothic terminal font.
        let font_src = self.project_root.join("source").join("fonts")
            .join("SarasaTermSC-Regular-subset.ttf");
        if font_src.exists() {
            std::fs::create_dir_all(self.rootfs_dir().join("lib").join("fonts"))?;
            std::fs::copy(&font_src, self.rootfs_dir().join("lib").join("fonts")
                .join("SarasaTermSC-Regular.ttf"))?;
        }

        // Install the Bash and SSH ports into /bin.
        std::fs::create_dir_all(self.rootfs_dir().join("bin"))?;
        std::fs::copy(&self.bash_elf_source(), self.rootfs_dir().join("bin").join("bash"))?;
        std::fs::copy(&self.ssh_elf_source(), self.rootfs_dir().join("bin").join("ssh"))?;
        std::fs::create_dir_all(self.rootfs_dir().join("rc").join("bin"))?;
        std::fs::copy(&self.bash_elf_source(), self.rootfs_dir().join("rc").join("bin").join("rc"))?;
        
        // Make them executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&self.kernel_boot_elf())?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&self.kernel_boot_elf(), perms)?;
            
            let mut perms = std::fs::metadata(&self.init_boot_elf())?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&self.init_boot_elf(), perms)?;

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

        // Copy grub.cfg to boot/grub
        if self.grub_cfg_esp().exists() {
            std::fs::create_dir_all(self.rootfs_dir().join("boot").join("grub"))?;
            std::fs::copy(
                &self.grub_cfg_esp(),
                self.rootfs_dir().join("boot").join("grub").join("grub.cfg"),
            )?;
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
        Ok(())
    }

    fn build_iso(&self) -> Result<()> {
        println!("[BUILD] Building ISO image...");
        
        // Ensure ESP and rootfs are built
        if !self.grub_efi().exists() {
            self.build_esp()?;
        }
        if !self.rootfs_dir().join("boot").join("9kernel.elf").exists() {
            self.build_rootfs()?;
        }
        
        // Generate ISO-specific grub.cfg
        self.generate_grub_cfg(&self.grub_cfg_iso(), true)?;
        
        // Create temporary directory for ISO structure
        let tmp_dir = tempfile::tempdir_in(self.build_dir.parent().unwrap())?;
        
        // Copy ESP structure
        copy_dir_all(&self.esp_dir(), &tmp_dir.path().join("esp"))?;
        
        // Copy rootfs
        copy_dir_all(&self.rootfs_dir(), &tmp_dir.path().join("plan9root"))?;
        
        // Create boot/grub
        std::fs::create_dir_all(tmp_dir.path().join("boot").join("grub"))?;
        std::fs::copy(
            &self.grub_cfg_iso(),
            tmp_dir.path().join("boot").join("grub").join("grub.cfg"),
        )?;
        
        // Create EFI/BOOT
        std::fs::create_dir_all(tmp_dir.path().join("EFI").join("BOOT"))?;
        std::fs::copy(
            &self.grub_cfg_iso(),
            tmp_dir.path().join("EFI").join("BOOT").join("grub.cfg"),
        )?;
        std::fs::copy(
            &self.grub_efi(),
            tmp_dir.path().join("EFI").join("BOOT").join("BOOTX64.EFI"),
        )?;

        // Build ISO with grub-mkrescue
        let mut cmd = Command::new("grub-mkrescue");
        cmd.arg("-o")
           .arg(&self.iso_file())
           .arg(tmp_dir.path());

        let status = cmd.output().context("Failed to run grub-mkrescue")?;
        
        if !status.status.success() {
            println!("grub-mkrescue stderr: {}", String::from_utf8_lossy(&status.stderr));
            anyhow::bail!("grub-mkrescue failed");
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

/// Recursively copy a directory
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
