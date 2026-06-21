//! i386 registers

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Frame {
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub eax: u32,
    pub xcs: u32,
    pub xflags: u32,
    pub esp: u32,
    pub xss: u32,
}
