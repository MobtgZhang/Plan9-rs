/* Multiboot2 header & boot-info tag constants used by boot.S.
 *
 * NB: the Multiboot2 specification reuses numeric tag-type values between
 * the header (sent to the bootloader) and the information structure
 * (returned by the bootloader) but they describe completely different
 * fields in each context. We use clear prefixes here to avoid confusion.
 */
#ifndef ARCH_X86_64_MULTIBOOT2_CONSTANTS_S
#define ARCH_X86_64_MULTIBOOT2_CONSTANTS_S

/* Header magic — identifies the start of a Multiboot2 header. */
#define MB2_MAGIC             0xE85250D6

/* Architecture fields */
#define MB2_ARCH_I386         0
#define MB2_ARCH_MIPS32       4

/* ------------------------------------------------------------------------
 * Header tag types (sent to the bootloader in the .multiboot2 section).
 * ------------------------------------------------------------------------ */
#define HDR_TAG_END                       0
#define HDR_TAG_INFORMATION_REQUEST       1
#define HDR_TAG_ADDRESS                   2
#define HDR_TAG_ENTRY_ADDRESS             3
#define HDR_TAG_CONSOLE_FLAGS             4
#define HDR_TAG_FRAMEBUFFER               5
#define HDR_TAG_MODULE_ALIGN              6
#define HDR_TAG_EFI_BS                    7
#define HDR_TAG_ENTRY_ADDRESS_EFI32       8
#define HDR_TAG_RELOCATABLE               9

/* ------------------------------------------------------------------------
 * Information-structure tag types (returned by GRUB in the boot info).
 * ------------------------------------------------------------------------ */
#define INFO_TAG_END                      0
#define INFO_TAG_CMDLINE                  1
#define INFO_TAG_BOOT_LOADER_NAME         2
#define INFO_TAG_MODULE                   3
#define INFO_TAG_BASIC_MEMINFO            4
#define INFO_TAG_BOOTDEV                  5
#define INFO_TAG_MEMORY_MAP               6
#define INFO_TAG_VBE                      7
#define INFO_TAG_FRAMEBUFFER              8
#define INFO_TAG_ELF_SYMBOLS              9
#define INFO_TAG_APM                      10
#define INFO_TAG_EFI32                    11
#define INFO_TAG_EFI64                    12
#define INFO_TAG_SMBIOS                   13
#define INFO_TAG_ACPI_OLD                 14
#define INFO_TAG_ACPI_NEW                 15
#define INFO_TAG_NETWORK                  16
#define INFO_TAG_EFI_MMAP                 17
#define INFO_TAG_EFI_BS_NOT_TERMINATED   18
#define INFO_TAG_EFI32_IMAGE_HANDLE       19
#define INFO_TAG_EFI64_IMAGE_HANDLE       20
#define INFO_TAG_LOAD_BASE                21

#endif