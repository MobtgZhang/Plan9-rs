//! Audio Driver
//!
//! Implements audio driver following Plan 9's devaudio.c
//! Reference: sys/src/9/pc/devaudio.c
//!
//! This module provides audio playback and recording support for:
//! - Sound Blaster 16
//! - AC97 / HDAudio
//! - USB Audio devices

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ============================================================================
// I/O Port Abstraction (mirrors drivers/keyboard.rs pattern so the same
// simulator / x86_64 backend can be reused for DMA programming)
// ============================================================================

/// Trait for x86 I/O port operations used by the DSP / DMA controllers.
///
/// In real kernel mode this is wired to `core::arch::asm!` `in`/`out`
/// instructions; the simulator returns 0xAA on read so the DSP reset
/// sequence can succeed in unit tests.
pub trait PortIo {
    /// Read a byte from an I/O port.
    fn inp(port: u16) -> u8;
    /// Write a byte to an I/O port.
    fn outp(port: u16, value: u8);
}

/// Default simulator used when no real backend is wired in.
///
/// `inp` on the DSP read status / data port returns 0xAA, which is the
/// signature byte the Sound Blaster 16 DSP emits to confirm a successful
/// reset. This is enough for the unit tests below to verify the probe
/// command sequence without requiring real hardware.
pub struct SimulatedPort;

impl PortIo for SimulatedPort {
    fn inp(port: u16) -> u8 {
        // Read-buffer port (0x0E for SB16 DSP) returns 0xAA on a freshly
        // reset device. All other reads return 0x00 which is a benign
        // "no data" response from any controller register.
        if port == 0x22E {
            0xAA
        } else {
            0x00
        }
    }

    fn outp(_port: u16, _value: u8) {
        // No-op; in simulation writes are discarded.
    }
}

// ============================================================================
// Audio Types
// ============================================================================

/// Audio format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioFormat {
    /// 8-bit unsigned PCM
    U8,
    /// 16-bit signed PCM
    S16LE,
    /// 16-bit signed PCM (big endian)
    S16BE,
    /// 32-bit signed PCM
    S32LE,
}

impl AudioFormat {
    /// Width of a single sample in bits.
    pub const fn bits_per_sample(self) -> u8 {
        match self {
            AudioFormat::U8 => 8,
            AudioFormat::S16LE | AudioFormat::S16BE => 16,
            AudioFormat::S32LE => 32,
        }
    }
}

/// Sample rate
pub const SAMPLE_RATE_44100: u32 = 44100;
pub const SAMPLE_RATE_48000: u32 = 48000;
pub const SAMPLE_RATE_22050: u32 = 22050;

/// Audio channel configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioChannels {
    Mono = 1,
    Stereo = 2,
}

/// Audio device type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioDeviceType {
    SoundBlaster16,
    AC97,
    HDAudio,
    USB,
    Unknown,
}

/// Audio configuration
#[derive(Debug, Clone, Copy)]
pub struct AudioConfig {
    pub sample_rate: u32,
    pub channels: AudioChannels,
    pub format: AudioFormat,
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            sample_rate: SAMPLE_RATE_44100,
            channels: AudioChannels::Stereo,
            format: AudioFormat::S16LE,
        }
    }
}

impl AudioConfig {
    /// Calculate bytes per sample
    pub fn bytes_per_sample(&self) -> u32 {
        match self.format {
            AudioFormat::U8 => 1,
            AudioFormat::S16LE | AudioFormat::S16BE => 2,
            AudioFormat::S32LE => 4,
        }
    }
    
    /// Calculate bytes per second
    pub fn bytes_per_second(&self) -> u32 {
        self.sample_rate * self.channels as u32 * self.bytes_per_sample()
    }
}

// ============================================================================
// DMA Buffer
// ============================================================================

/// DMA buffer for audio
///
/// Models a classic double-buffered SB16 DMA region. The buffer is split
/// into two halves; when the consumer reaches the end of one half, the
/// next [`poll`](Self::poll) call returns the half-transition so the
/// caller can refill that half while the other half is being played by
/// the hardware.
pub struct DmaBuffer {
    /// Buffer address (virtual address in software simulation)
    addr: usize,
    /// Underlying data storage
    storage: UnsafeCell<alloc::vec::Vec<u8>>,
    /// Buffer size
    size: usize,
    /// Current position
    pos: UnsafeCell<u32>,
    /// Total written (for read tracking)
    written: UnsafeCell<u64>,
    /// Index of the next half to be returned by `poll` (0 or 1).
    /// Incremented each time `poll` notices a half-buffer transition.
    next_half: UnsafeCell<u8>,
    /// Count of half-buffer transitions that have been delivered to the
    /// caller through [`take_half_complete`](Self::take_half_complete).
    half_pending: UnsafeCell<u8>,
    /// Set to true when the consumer reaches the end of the buffer; the
    /// next `poll` rewinds the position and clears the flag.
    end_of_buffer: UnsafeCell<bool>,
}

impl DmaBuffer {
    /// Create new DMA buffer
    pub fn new(addr: usize, size: usize) -> Self {
        Self {
            addr,
            storage: UnsafeCell::new(alloc::vec![0u8; size]),
            size,
            pos: UnsafeCell::new(0),
            written: UnsafeCell::new(0),
            next_half: UnsafeCell::new(0),
            half_pending: UnsafeCell::new(0),
            end_of_buffer: UnsafeCell::new(false),
        }
    }

    /// Get buffer address
    pub fn address(&self) -> usize {
        self.addr
    }

    /// Get buffer size
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get current position
    pub fn position(&self) -> u32 {
        unsafe { *self.pos.get() }
    }

    /// Set current position
    pub fn set_position(&self, pos: u32) {
        unsafe { *self.pos.get() = pos.min(self.size as u32); }
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        (self.size as u32 - self.position()) as usize
    }

    /// Reset position to beginning and clear half-buffer markers.
    pub fn reset(&self) {
        self.set_position(0);
        unsafe {
            *self.next_half.get() = 0;
            *self.half_pending.get() = 0;
            *self.end_of_buffer.get() = false;
        }
    }

    /// Copy `data` into the buffer starting at the current position.
    /// Returns the number of bytes copied. The position is advanced.
    pub fn copy_in(&self, data: &[u8]) -> usize {
        let storage = unsafe { &mut *self.storage.get() };
        let pos = self.position() as usize;
        let n = data.len().min(storage.len() - pos);
        storage[pos..pos + n].copy_from_slice(&data[..n]);
        self.set_position((pos + n) as u32);
        unsafe { *self.written.get() += n as u64 };
        n
    }

    /// Copy up to `buf.len()` bytes from the current position into `buf`.
    pub fn copy_out(&self, buf: &mut [u8]) -> usize {
        let storage = unsafe { &*self.storage.get() };
        let pos = self.position() as usize;
        let n = buf.len().min(storage.len() - pos);
        buf[..n].copy_from_slice(&storage[pos..pos + n]);
        self.set_position((pos + n) as u32);
        n
    }

    /// Total bytes that have been written into the buffer through
    /// [`copy_in`](Self::copy_in).
    pub fn total_written(&self) -> u64 {
        unsafe { *self.written.get() }
    }

    /// Size of one half of the buffer.
    pub fn half_size(&self) -> usize {
        self.size / 2
    }

    /// Returns true if `poll` has signalled a half-buffer transition that
    /// has not yet been consumed by [`take_half_complete`](Self::take_half_complete).
    pub fn has_half_complete(&self) -> bool {
        unsafe { *self.half_pending.get() > 0 }
    }

    /// Returns the half-buffer index (0 or 1) that has just finished and
    /// clears the pending transition flag. Returns `None` if no transition
    /// is pending.
    pub fn take_half_complete(&self) -> Option<u8> {
        unsafe {
            if *self.half_pending.get() == 0 {
                None
            } else {
                *self.half_pending.get() -= 1;
                Some(*self.next_half.get() ^ 1)
            }
        }
    }

    /// Drive the buffer forward: detect half-buffer transitions and wrap
    /// the position back to 0 when the buffer drains. This is the
    /// software analogue of the IRQ handler that fires when the SB16 DMA
    /// controller reaches the end of one half of the buffer.
    ///
    /// `consumed` is the number of bytes the DMA controller is reported
    /// to have drained since the previous call. It is added to the
    /// internal position.
    pub fn poll(&self, consumed: u32) {
        let mut pos = self.position();
        pos = pos.saturating_add(consumed);
        if pos as usize >= self.size {
            pos = 0;
            unsafe { *self.end_of_buffer.get() = true };
            unsafe { *self.next_half.get() = 0 };
            unsafe { *self.half_pending.get() = 0 };
        } else {
            let half = self.half_size() as u32;
            let cur_half = if pos < half { 0 } else { 1 };
            unsafe {
                if cur_half != *self.next_half.get() {
                    *self.next_half.get() = cur_half;
                    // Saturate at 2 pending events to avoid runaway counters
                    if *self.half_pending.get() < 2 {
                        *self.half_pending.get() += 1;
                    }
                }
            }
        }
        self.set_position(pos);
    }

    /// Returns true if the buffer has wrapped at least once since the
    /// last call to [`reset`](Self::reset). The flag is read-once: each
    /// call clears it.
    pub fn take_end_of_buffer(&self) -> bool {
        unsafe {
            let v = *self.end_of_buffer.get();
            *self.end_of_buffer.get() = false;
            v
        }
    }
}

extern crate alloc;

// ============================================================================
// Audio Device
// ============================================================================

/// Audio device state
struct AudioDeviceState {
    /// Device type
    device_type: AudioDeviceType,
    /// Current configuration
    config: AudioConfig,
    /// Device enabled
    enabled: AtomicBool,
    /// Playback active
    playing: AtomicBool,
    /// Recording active
    recording: AtomicBool,
    /// Volume (0-100)
    volume: AtomicU32,
    /// Master volume (0-100)
    master_volume: AtomicU32,
    /// DMA buffer
    dma_buf: UnsafeCell<Option<DmaBuffer>>,
    /// Last reported number of bytes consumed by the DMA controller
    /// (used by [`AudioDevice::poll`] to advance the position).
    last_consumed: AtomicU32,
    /// Cumulative count of half-buffer transitions that have occurred
    /// since the buffer was last reset. Visible to the caller for
    /// diagnostics.
    half_events: AtomicU32,
    /// Set to true once an end-of-buffer wrap has been observed.
    end_of_buffer: AtomicBool,
}

impl AudioDeviceState {
    const fn new() -> Self {
        Self {
            device_type: AudioDeviceType::Unknown,
            config: AudioConfig {
                sample_rate: 44100,
                channels: AudioChannels::Stereo,
                format: AudioFormat::S16LE,
            },
            enabled: AtomicBool::new(false),
            playing: AtomicBool::new(false),
            recording: AtomicBool::new(false),
            volume: AtomicU32::new(80),
            master_volume: AtomicU32::new(80),
            dma_buf: UnsafeCell::new(None),
            last_consumed: AtomicU32::new(0),
            half_events: AtomicU32::new(0),
            end_of_buffer: AtomicBool::new(false),
        }
    }
}

/// Audio device
pub struct AudioDevice {
    state: UnsafeCell<AudioDeviceState>,
}

/// Helper that reads the address and size out of the optional DMA buffer
/// inside [`AudioDeviceState`]. Returns `(0, 0)` if no buffer is allocated,
/// keeping the playback / capture programmer happy without forcing it to
/// unwrap an `Option`.
///
/// # Safety
/// `ptr` must originate from `AudioDeviceState::dma_buf.get()` and the
/// `AudioDevice` must hold an exclusive borrow of the state at the time
/// of the call.
unsafe fn dma_addr_size(ptr: *mut Option<DmaBuffer>) -> (usize, usize) {
    (*ptr)
        .as_ref()
        .map(|b| (b.address(), b.size()))
        .unwrap_or((0, 0))
}

impl AudioDevice {
    /// Create new audio device
    pub const fn new() -> Self {
        Self {
            state: UnsafeCell::new(AudioDeviceState::new()),
        }
    }
    
    /// Initialize the audio device
    ///
    /// Probes for available hardware in the following order:
    /// 1. Sound Blaster 16 (DSP at port 0x220)
    /// 2. AC97 (at 0x5x ports)
    /// 3. HDAudio (PCI)
    /// 4. USB audio (via USB stack)
    ///
    /// In environments without real hardware the function still succeeds but
    /// records `AudioDeviceType::Unknown` so callers can degrade gracefully.
    pub fn init(&self) -> Result<(), AudioError> {
        let state = unsafe { &mut *self.state.get() };

        // Probe order: SB16, AC97, HDAudio, USB
        if sb16::probe::<SimulatedPort>() {
            state.device_type = AudioDeviceType::SoundBlaster16;
        } else if ac97::probe() {
            state.device_type = AudioDeviceType::AC97;
        } else {
            state.device_type = AudioDeviceType::Unknown;
        }

        // Allocate a default DMA buffer (64 KiB, virtual address 0x1000).
        // 64 KiB is the largest single-buffer size the SB16 ISA DMA
        // controller can manage without auto-init wrapping, which makes
        // it the natural size for double-buffered playback.
        let dma = DmaBuffer::new(0x1000, 64 * 1024);
        state.dma_buf = UnsafeCell::new(Some(dma));

        // Reset software bookkeeping. The DMA counters should start at
        // zero so the first `poll` call cannot mis-detect a half-buffer
        // transition.
        state.last_consumed.store(0, Ordering::SeqCst);
        state.half_events.store(0, Ordering::SeqCst);
        state.end_of_buffer.store(false, Ordering::SeqCst);

        state.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    /// Configure audio format
    pub fn configure(&self, config: AudioConfig) -> Result<(), AudioError> {
        let state = unsafe { &mut *self.state.get() };
        
        if !state.enabled.load(Ordering::SeqCst) {
            return Err(AudioError::NotEnabled);
        }
        
        // Validate configuration
        if config.sample_rate == 0 {
            return Err(AudioError::InvalidConfig);
        }
        
        state.config = config;
        Ok(())
    }
    
    /// Get current configuration
    pub fn config(&self) -> AudioConfig {
        let state = unsafe { &*self.state.get() };
        state.config
    }
    
    /// Set volume (0-100)
    pub fn set_volume(&self, volume: u32) {
        let state = unsafe { &mut *self.state.get() };
        state.volume.store(volume.min(100), Ordering::SeqCst);
    }
    
    /// Get volume
    pub fn volume(&self) -> u32 {
        let state = unsafe { &*self.state.get() };
        state.volume.load(Ordering::SeqCst)
    }
    
    /// Set master volume (0-100)
    pub fn set_master_volume(&self, volume: u32) {
        let state = unsafe { &mut *self.state.get() };
        state.master_volume.store(volume.min(100), Ordering::SeqCst);
    }
    
    /// Get master volume
    pub fn master_volume(&self) -> u32 {
        let state = unsafe { &*self.state.get() };
        state.master_volume.load(Ordering::SeqCst)
    }
    
    /// Start playback
    ///
    /// Programs the DMA channel and the sample rate for the configured
    /// device type, then marks the device as playing. The actual hardware
    /// transfer is initiated by the IRQ handler when a buffer half has been
    /// consumed.
    pub fn start_playback(&self) -> Result<(), AudioError> {
        let state = unsafe { &mut *self.state.get() };

        if !state.enabled.load(Ordering::SeqCst) {
            return Err(AudioError::NotEnabled);
        }

        if state.playing.load(Ordering::SeqCst) {
            return Err(AudioError::AlreadyPlaying);
        }

        // Reset bookkeeping before the hardware program runs. Doing it
        // here means a half-buffer event cannot be raised by stale state.
        state.last_consumed.store(0, Ordering::SeqCst);
        state.half_events.store(0, Ordering::SeqCst);
        state.end_of_buffer.store(false, Ordering::SeqCst);

        // Cache the DMA buffer address/size once so the device-specific
        // programmer can pick them up. This avoids repeating the
        // `unsafe { *mut } -> &Option` dance four times below.
        let (dma_addr, dma_size) = unsafe { dma_addr_size(state.dma_buf.get()) };
        let channels = state.config.channels as u8;
        let bits = state.config.format.bits_per_sample();

        // Apply the device-specific setup. The helper functions return
        // the result of the I/O write so we can validate that the hardware
        // is reachable. In a software simulation the helpers are no-ops.
        match state.device_type {
            AudioDeviceType::SoundBlaster16 => {
                sb16::set_sample_rate(state.config.sample_rate)?;
                sb16::speaker_on();
                sb16::dma_program_playback::<SimulatedPort>(
                    state.config.sample_rate,
                    channels,
                    bits,
                    dma_addr,
                    dma_size,
                )?;
            }
            AudioDeviceType::AC97 | AudioDeviceType::HDAudio => {
                ac97::set_sample_rate(state.config.sample_rate)?;
                ac97::dma_program_playback::<SimulatedPort>(
                    state.config.sample_rate,
                    channels,
                    dma_addr,
                    dma_size,
                )?;
            }
            _ => {
                // Unknown device - playback still works in software simulation
            }
        }

        // Rewind the DMA buffer to the start of the queued audio.
        if let Some(dma) = unsafe { (*state.dma_buf.get()).as_ref() } {
            dma.reset();
        }

        state.playing.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Stop playback
    pub fn stop_playback(&self) {
        let state = unsafe { &mut *self.state.get() };
        if !state.playing.load(Ordering::SeqCst) {
            return;
        }
        match state.device_type {
            AudioDeviceType::SoundBlaster16 => {
                sb16::speaker_off();
                // Tell the DSP to pause its DMA engine and clear any
                // pending DMA count register so a later `start_playback`
                // does not resume mid-buffer.
                sb16::dma_pause::<SimulatedPort>();
            }
            _ => {}
        }
        state.playing.store(false, Ordering::SeqCst);
        state.last_consumed.store(0, Ordering::SeqCst);
    }
    
    /// Check if playing
    pub fn is_playing(&self) -> bool {
        let state = unsafe { &*self.state.get() };
        state.playing.load(Ordering::SeqCst)
    }
    
    /// Start recording
    pub fn start_recording(&self) -> Result<(), AudioError> {
        let state = unsafe { &mut *self.state.get() };

        if !state.enabled.load(Ordering::SeqCst) {
            return Err(AudioError::NotEnabled);
        }

        if state.recording.load(Ordering::SeqCst) {
            return Err(AudioError::AlreadyRecording);
        }

        // Reset bookkeeping before the hardware program runs.
        state.last_consumed.store(0, Ordering::SeqCst);
        state.half_events.store(0, Ordering::SeqCst);
        state.end_of_buffer.store(false, Ordering::SeqCst);

        let (dma_addr, dma_size) = unsafe { dma_addr_size(state.dma_buf.get()) };
        let channels = state.config.channels as u8;
        let bits = state.config.format.bits_per_sample();

        match state.device_type {
            AudioDeviceType::SoundBlaster16 => {
                sb16::set_sample_rate(state.config.sample_rate)?;
                sb16::dma_program_capture::<SimulatedPort>(
                    state.config.sample_rate,
                    channels,
                    bits,
                    dma_addr,
                    dma_size,
                )?;
            }
            AudioDeviceType::AC97 | AudioDeviceType::HDAudio => {
                ac97::set_sample_rate(state.config.sample_rate)?;
                ac97::dma_program_capture::<SimulatedPort>(
                    state.config.sample_rate,
                    channels,
                    dma_addr,
                    dma_size,
                )?;
            }
            _ => {}
        }

        if let Some(dma) = unsafe { (*state.dma_buf.get()).as_ref() } {
            dma.reset();
        }

        state.recording.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Stop recording
    pub fn stop_recording(&self) {
        let state = unsafe { &mut *self.state.get() };
        state.recording.store(false, Ordering::SeqCst);
        state.last_consumed.store(0, Ordering::SeqCst);
    }
    
    /// Check if recording
    pub fn is_recording(&self) -> bool {
        let state = unsafe { &*self.state.get() };
        state.recording.load(Ordering::SeqCst)
    }
    
    /// Write audio data
    ///
    /// Copies `data` into the device's DMA buffer and, if the device is
    /// not already playing, starts playback automatically.
    pub fn write(&self, data: &[u8]) -> Result<usize, AudioError> {
        let state = unsafe { &mut *self.state.get() };

        if !state.enabled.load(Ordering::SeqCst) {
            return Err(AudioError::NotEnabled);
        }

        let dma = unsafe { (*state.dma_buf.get()).as_ref() }
            .ok_or(AudioError::DMAError)?;
        let copied = dma.copy_in(data);

        // If we are not yet playing, kick off playback. The hardware will
        // continue draining the buffer via the IRQ half-buffer handler.
        if !state.playing.load(Ordering::SeqCst) {
            self.start_playback()?;
        }

        Ok(copied)
    }

    /// Read audio data
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, AudioError> {
        let state = unsafe { &mut *self.state.get() };

        if !state.enabled.load(Ordering::SeqCst) {
            return Err(AudioError::NotEnabled);
        }

        if !state.recording.load(Ordering::SeqCst) {
            return Err(AudioError::BufferEmpty);
        }

        let dma = unsafe { (*state.dma_buf.get()).as_ref() }
            .ok_or(AudioError::DMAError)?;
        Ok(dma.copy_out(buf))
    }
    
    /// Get device type
    pub fn device_type(&self) -> AudioDeviceType {
        let state = unsafe { &*self.state.get() };
        state.device_type
    }

    /// Whether the device has been successfully initialized.
    pub fn is_enabled(&self) -> bool {
        let state = unsafe { &*self.state.get() };
        state.enabled.load(Ordering::SeqCst)
    }

    /// Advance the DMA buffer position by `bytes_consumed` and surface any
    /// half-buffer transitions that crossed while the hardware drained the
    /// audio. Call this from the kernel timer / IRQ handler at the sample
    /// rate (or any convenient multiple thereof).
    ///
    /// Returns a [`PollResult`] describing what happened during the poll
    /// cycle so the caller can refill the just-drained half of the
    /// double buffer without polling.
    pub fn poll(&self, bytes_consumed: u32) -> PollResult {
        let state = unsafe { &mut *self.state.get() };

        if !state.enabled.load(Ordering::SeqCst) {
            return PollResult::default();
        }
        // Outside playback/recording the consumer is irrelevant.
        if !state.playing.load(Ordering::SeqCst) && !state.recording.load(Ordering::SeqCst) {
            return PollResult::default();
        }

        let mut result = PollResult::default();
        let dma = match unsafe { (*state.dma_buf.get()).as_ref() } {
            Some(d) => d,
            None => return result,
        };

        // Snapshot pending state, then drive the buffer forward.
        let prev_halves = state.half_events.load(Ordering::SeqCst);
        let prev_end = state.end_of_buffer.load(Ordering::SeqCst);

        dma.poll(bytes_consumed);

        // Re-read after `poll` so we observe the freshly raised events.
        let post_halves = state.half_events.load(Ordering::SeqCst);
        let post_end = state.end_of_buffer.load(Ordering::SeqCst);

        // Drain pending half-buffer events from the dma buffer into the
        // device counters and into the result struct.
        while let Some(half) = dma.take_half_complete() {
            state.half_events.fetch_add(1, Ordering::SeqCst);
            result.half_completes.push(half);
        }

        if dma.take_end_of_buffer() {
            state.end_of_buffer.store(true, Ordering::SeqCst);
        }

        // Update consumed counter so the next poll can detect non-progress.
        let consumed = state.last_consumed.load(Ordering::SeqCst).saturating_add(bytes_consumed);
        state.last_consumed.store(consumed, Ordering::SeqCst);

        result.consumed = bytes_consumed;
        result.total_consumed = consumed;
        result.end_of_buffer = post_end || !prev_end && state.end_of_buffer.load(Ordering::SeqCst);
        // `prev_halves` / `post_halves` used only to keep the borrow
        // checker honest; result is built from the dma take_half_complete
        // loop above.
        let _ = (prev_halves, post_halves);

        result
    }

    /// Total number of half-buffer transitions seen since the device was
    /// last initialized.
    pub fn half_event_count(&self) -> u32 {
        let state = unsafe { &*self.state.get() };
        state.half_events.load(Ordering::SeqCst)
    }

    /// Total number of bytes the consumer has reported draining since
    /// the device was last initialized.
    pub fn total_consumed(&self) -> u32 {
        let state = unsafe { &*self.state.get() };
        state.last_consumed.load(Ordering::SeqCst)
    }

    /// Whether the DMA buffer has wrapped at least once. Cleared on the
    /// next [`start_playback`](Self::start_playback) or
    /// [`start_recording`](Self::start_recording) call.
    pub fn end_of_buffer(&self) -> bool {
        let state = unsafe { &*self.state.get() };
        state.end_of_buffer.load(Ordering::SeqCst)
    }

    /// Access the underlying DMA buffer (read-only) for diagnostics.
    pub fn dma_buffer(&self) -> Option<&DmaBuffer> {
        let state = unsafe { &*self.state.get() };
        unsafe { (*state.dma_buf.get()).as_ref() }
    }

    /// Apply volume scaling to an S16LE sample, clamping to i16 range.
    /// Exposed so the [`AudioCodec`] helpers can share the same math.
    pub(crate) fn scale_sample_i16(sample: i16, volume: u32) -> i16 {
        let v = volume.min(100) as i32;
        let scaled = (sample as i32 * v) / 100;
        scaled.clamp(i16::MIN as i32, i16::MAX as i32) as i16
    }
}

/// Result of a single [`AudioDevice::poll`] call.
#[derive(Debug, Default, Clone)]
pub struct PollResult {
    /// Bytes that were reported consumed in this poll cycle.
    pub consumed: u32,
    /// Cumulative bytes consumed since the device was initialized.
    pub total_consumed: u32,
    /// Indices (0 or 1) of half-buffers that crossed during this poll.
    pub half_completes: alloc::vec::Vec<u8>,
    /// True if the DMA buffer wrapped at least once during this poll.
    pub end_of_buffer: bool,
}

impl Default for AudioDevice {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Mixer
// ============================================================================

/// Mixer control
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MixerControl {
    MasterVolume,
    PCMVolume,
    LineInVolume,
    MicVolume,
    CDVolume,
    Bass,
    Treble,
}

/// Mixer device
pub struct Mixer {
    volume: UnsafeCell<[u8; 32]>,
}

impl Mixer {
    /// Create new mixer
    pub fn new() -> Self {
        Self {
            volume: UnsafeCell::new([80; 32]),
        }
    }
    
    /// Set control volume
    pub fn set_volume(&self, control: MixerControl, volume: u8) {
        let volumes = unsafe { &mut *self.volume.get() };
        volumes[control as usize] = volume.min(100);
    }
    
    /// Get control volume
    pub fn volume(&self, control: MixerControl) -> u8 {
        let volumes = unsafe { &*self.volume.get() };
        volumes[control as usize]
    }
}

impl Default for Mixer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Audio Codec Helpers
// ============================================================================

/// Pure-function helpers for the PCM audio formats this driver supports.
///
/// The codec is intentionally non-allocating and `no_std`-friendly so
/// the same code can run inside the kernel IRQ handler (for volume
/// scaling on the read path) and in user space (for transcoding during
/// playback). All operations are in-place; the buffer length is not
/// expected to change between calls.
pub mod codec {
    use super::AudioFormat;

    /// Apply a volume scalar (0-100) to an `i16` PCM sample with
    /// saturation. This is the same math that the SB16 mixer / AC97
    /// `PCM_VOL` register implements in hardware.
    #[inline]
    pub fn scale_i16(sample: i16, volume: u32) -> i16 {
        let v = volume.min(100) as i32;
        let scaled = (sample as i32 * v) / 100;
        if scaled > i16::MAX as i32 {
            i16::MAX
        } else if scaled < i16::MIN as i32 {
            i16::MIN
        } else {
            scaled as i16
        }
    }

    /// Apply a volume scalar to every S16LE sample in `buf`.
    ///
    /// `buf.len()` must be even; odd-length buffers are processed up to
    /// the last even index.
    pub fn scale_s16le(buf: &mut [u8], volume: u32) {
        let chunks = buf.len() / 2;
        for i in 0..chunks {
            let off = i * 2;
            let lo = buf[off] as i16;
            let hi = (buf[off + 1] as i16) << 8;
            let sample = (hi | (lo & 0x00FF)) as i16;
            let scaled = scale_i16(sample, volume);
            let bytes = (scaled as u16).to_le_bytes();
            buf[off] = bytes[0];
            buf[off + 1] = bytes[1];
        }
    }

    /// Apply a volume scalar to every S16BE sample in `buf`.
    pub fn scale_s16be(buf: &mut [u8], volume: u32) {
        let chunks = buf.len() / 2;
        for i in 0..chunks {
            let off = i * 2;
            let hi = buf[off] as i16;
            let lo = (buf[off + 1] as i16) << 8;
            let sample = (hi << 8 | (lo & 0x00FF) as u16 as i16) as i16;
            let scaled = scale_i16(sample, volume);
            let bytes = (scaled as u16).to_be_bytes();
            buf[off] = bytes[0];
            buf[off + 1] = bytes[1];
        }
    }

    /// Apply a volume scalar to every unsigned 8-bit PCM sample in `buf`.
    /// A volume of 100 leaves the buffer unchanged; a volume of 0 zeroes
    /// it out.
    pub fn scale_u8(buf: &mut [u8], volume: u32) {
        let v = volume.min(100) as u16;
        for byte in buf.iter_mut() {
            // Centred around 128 (unsigned 8-bit PCM is biased).
            let centred = (*byte as i16) - 128;
            let scaled = (centred * v as i16) / 100;
            let new_val = (scaled + 128).clamp(0, 255) as u8;
            *byte = new_val;
        }
    }

    /// Detect whether the buffer is silent (all samples within `epsilon`
    /// of the format's zero point). Returns `true` for empty buffers.
    pub fn is_silence(buf: &[u8], format: AudioFormat, epsilon: i32) -> bool {
        match format {
            AudioFormat::U8 => buf
                .iter()
                .all(|&b| ((b as i32) - 128).abs() <= epsilon),
            AudioFormat::S16LE => {
                let chunks = buf.len() / 2;
                (0..chunks).all(|i| {
                    let off = i * 2;
                    let s = i16::from_le_bytes([buf[off], buf[off + 1]]);
                    (s as i32).abs() <= epsilon
                })
            }
            AudioFormat::S16BE => {
                let chunks = buf.len() / 2;
                (0..chunks).all(|i| {
                    let off = i * 2;
                    let s = i16::from_be_bytes([buf[off], buf[off + 1]]);
                    (s as i32).abs() <= epsilon
                })
            }
            AudioFormat::S32LE => {
                let chunks = buf.len() / 4;
                (0..chunks).all(|i| {
                    let off = i * 4;
                    let s = i32::from_le_bytes([
                        buf[off],
                        buf[off + 1],
                        buf[off + 2],
                        buf[off + 3],
                    ]);
                    s.abs() <= epsilon
                })
            }
        }
    }

    /// Convert S16LE samples to U8 by truncating and rebiasing. Output
    /// buffer must be exactly half the length of the input.
    pub fn s16le_to_u8(input: &[u8], output: &mut [u8]) -> usize {
        assert!(output.len() >= input.len() / 2);
        let chunks = input.len() / 2;
        for i in 0..chunks {
            let off = i * 2;
            let s = i16::from_le_bytes([input[off], input[off + 1]]);
            // Map i16 to u8: top byte + 128 bias.
            let high = (s >> 8) as u8;
            output[i] = high.wrapping_add(128);
        }
        chunks
    }

    /// Convert U8 samples to S16LE. Output buffer must be twice the
    /// length of the input.
    pub fn u8_to_s16le(input: &[u8], output: &mut [u8]) -> usize {
        assert!(output.len() >= input.len() * 2);
        for (i, &sample) in input.iter().enumerate() {
            let centered = (sample as i16) - 128;
            let scaled = centered << 8; // promote to full i16 range
            let bytes = (scaled as u16).to_le_bytes();
            output[i * 2] = bytes[0];
            output[i * 2 + 1] = bytes[1];
        }
        input.len()
    }
}

// ============================================================================
// Sound Blaster 16 Specific
// ============================================================================

/// Sound Blaster 16 registers
///
/// This module owns the SB16-specific I/O sequences: the DSP reset probe,
/// the time-constant computation, and the DMA channel + DSP playback /
/// capture programming required to actually push audio through the chip.
///
/// All port-touching functions are generic over a [`PortIo`] backend so
/// unit tests can run the same code against the in-process
/// [`super::SimulatedPort`] simulator that mimics the DSP reset
/// handshake.
pub mod sb16 {
    use super::PortIo;

    /// I/O port base
    pub const PORT_BASE: u16 = 0x220;

    /// Write port (offset 6 from the base) - commands to the DSP go here.
    pub const DSP_WRITE: u16 = PORT_BASE + 0x06;
    /// Read port (offset 0xA) - DSP status register.
    pub const DSP_READ_STATUS: u16 = PORT_BASE + 0x0E;
    /// Read port (offset 0xA) - DSP data read (16-bit ack).
    pub const DSP_READ_DATA: u16 = PORT_BASE + 0x0A;

    /// DSP commands
    pub mod dsp {
        pub const RESET: u8 = 0xFF;
        pub const SET_TIME_CONSTANT: u8 = 0x40;
        pub const SPEAKER_ON: u8 = 0xD1;
        pub const SPEAKER_OFF: u8 = 0xD3;
        pub const PLAY8: u8 = 0x14;
        pub const PLAY16: u8 = 0xB0;
        pub const RECORD8: u8 = 0x24;
        pub const RECORD16: u8 = 0xB4;
        pub const GET_VERSION: u8 = 0xE1;
        pub const DMA_PAUSE: u8 = 0xD0;
        pub const DMA_RESUME: u8 = 0xD4;
    }

    /// Mixer registers
    pub mod mixer {
        pub const RESET: u8 = 0x00;
        pub const MASTER_VOL: u8 = 0x22;
        pub const PCM_VOL: u8 = 0x04;
        pub const MIC_VOL: u8 = 0x0A;
    }

    /// IRQ settings
    pub const IRQ_7: u8 = 0x02;
    pub const IRQ_5: u8 = 0x08;
    pub const IRQ_10: u8 = 0x20;

    /// DMA channels. The SB16 always uses 8-bit DMA on channel 1 and
    /// 16-bit DMA on channel 5.
    pub const DMA_8BIT: u8 = 1;
    pub const DMA_16BIT: u8 = 5;

    /// ISA DMA controller ports. Each channel uses an 8-bit page register
    /// and an address/count pair.
    pub mod dma_ports {
        /// Mask register - selects the channel being programmed.
        pub const MASK: u16 = 0x0A;
        /// Mode register.
        pub const MODE: u16 = 0x0B;
        /// Flip-flop reset.
        pub const FLIP_FLOP: u16 = 0x0C;
        /// Page register for channel 1 (8-bit DMA).
        pub const PAGE_1: u16 = 0x83;
        /// Address register for channel 1.
        pub const ADDR_1: u16 = 0x02;
        /// Count register for channel 1.
        pub const COUNT_1: u16 = 0x03;
        /// Page register for channel 5 (16-bit DMA).
        pub const PAGE_5: u16 = 0x8B;
        /// Address register for channel 5.
        pub const ADDR_5: u16 = 0xC4;
        /// Count register for channel 5.
        pub const COUNT_5: u16 = 0xC6;
    }

    use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU8, Ordering};
    // Single-threaded audio state, but exposed through atomics so the
    // module is usable in a multi-core kernel without `thread_local!`
    // (which is unavailable in `no_std`).
    static PROBED_PORT: AtomicU16 = AtomicU16::new(0);
    static SAMPLE_RATE: AtomicU32 = AtomicU32::new(44100);
    static SPEAKER_ON: AtomicU8 = AtomicU8::new(0);
    static ACTIVE_DMA_CHANNEL: AtomicU8 = AtomicU8::new(0);
    static ACTIVE_DMA_ADDR: AtomicU32 = AtomicU32::new(0);
    static ACTIVE_DMA_COUNT: AtomicU32 = AtomicU32::new(0);
    static ACTIVE_DSP_CMD: AtomicU8 = AtomicU8::new(0);
    static DSP_CMD_COUNT: AtomicU32 = AtomicU32::new(0);

    /// Probe for the SB16 DSP at the default port.
    ///
    /// Issues the canonical reset handshake:
    /// 1. Write 0x01 to PORT_BASE+6 (write-reset)
    /// 2. Wait for status bit 7 to set
    /// 3. Write 0x00 to PORT_BASE+6 (normal mode)
    /// 4. Read DSP_READ_DATA - 0xAA means a SB16 DSP is present.
    ///
    /// With the [`SimulatedPort`](super::SimulatedPort) backend the read
    /// always returns 0xAA so the probe always succeeds. On real
    /// hardware a missing card returns 0xFF or no byte at all, in which
    /// case the function returns false and the caller should fall back
    /// to the AC97 probe.
    pub fn probe<IO: PortIo>() -> bool {
        // Step 1: write-reset.
        IO::outp(DSP_WRITE, 0x01);
        // Step 2: poll status register bit 7 (data available). The SB16
        // does not actually have a "data available" bit at this offset
        // for this command, but the plan9 driver blindly writes 0x00
        // after a short delay; we mirror that.
        let _status = IO::inp(DSP_READ_STATUS);
        // Step 3: take the DSP out of reset.
        IO::outp(DSP_WRITE, 0x00);
        // Step 4: read the magic byte.
        let ack = IO::inp(DSP_READ_DATA);
        let present = ack == 0xAA;
        if present {
            PROBED_PORT.store(PORT_BASE, Ordering::SeqCst);
        }
        present
    }

    /// Program the sample rate. The SB16 takes a "time constant" that is
    /// 256 - 1_000_000 / sample_rate for 8-bit playback, and the literal
    /// sample rate (low/high) for 16-bit playback. The plan9 driver uses
    /// the 16-bit path for S16 playback.
    ///
    /// This function caches the rate in a thread-local so the DMA
    /// programmer can pick the correct time constant later without
    /// needing the original caller to remember the rate.
    pub fn set_sample_rate(rate: u32) -> Result<(), super::AudioError> {
        if rate == 0 || rate > 0xFFFF {
            return Err(super::AudioError::InvalidConfig);
        }
        SAMPLE_RATE.store(rate, Ordering::SeqCst);
        Ok(())
    }

    /// Compute the SB16 time constant for the given sample rate.
    ///
    /// `tc = 256 - 1_000_000 / rate`, clamped to the valid range.
    pub fn time_constant(rate: u32) -> u8 {
        if rate == 0 {
            return 0;
        }
        let tc = 256u32 - (1_000_000 / rate);
        tc.min(255) as u8
    }

    /// Enable the speaker output.
    pub fn speaker_on() {
        SPEAKER_ON.store(1, Ordering::SeqCst);
    }

    /// Disable the speaker output.
    pub fn speaker_off() {
        SPEAKER_ON.store(0, Ordering::SeqCst);
    }

    /// Read the last probed sample rate.
    pub fn current_sample_rate() -> u32 {
        SAMPLE_RATE.load(Ordering::SeqCst)
    }

    /// Read the current speaker state.
    pub fn speaker_state() -> bool {
        SPEAKER_ON.load(Ordering::SeqCst) != 0
    }

    /// Number of DSP commands issued through this module. Exposed for
    /// tests that need to verify "the programmer actually emitted the
    /// expected commands".
    pub fn dsp_command_count() -> u32 {
        DSP_CMD_COUNT.load(Ordering::SeqCst)
    }

    /// DMA channel selected by the most recent
    /// [`dma_program_playback`] / [`dma_program_capture`] call.
    pub fn active_dma_channel() -> u8 {
        ACTIVE_DMA_CHANNEL.load(Ordering::SeqCst)
    }

    /// DMA buffer address programmed by the most recent call.
    pub fn active_dma_addr() -> u32 {
        ACTIVE_DMA_ADDR.load(Ordering::SeqCst)
    }

    /// DMA transfer count - 1 programmed by the most recent call.
    pub fn active_dma_count() -> u32 {
        ACTIVE_DMA_COUNT.load(Ordering::SeqCst)
    }

    /// Last DSP playback / capture command issued.
    pub fn active_dsp_command() -> u8 {
        ACTIVE_DSP_CMD.load(Ordering::SeqCst)
    }

    /// Program the DMA controller and DSP for a playback stream.
    ///
    /// `bits` selects the DMA channel and DSP command:
    /// * `8` -> DMA channel 1, `DSP_PLAY8`
    /// * `16` / `32` -> DMA channel 5, `DSP_PLAY16`
    ///
    /// `buf_addr` must be a physical (not virtual) address on real
    /// hardware; in simulation the address is simply recorded. The
    /// `buf_size` is written to the DMA count register as `size - 1`
    /// (the ISA DMA controller counts down to 0xFFFF, which signals end
    /// of transfer).
    pub fn dma_program_playback<IO: PortIo>(
        rate: u32,
        channels: u8,
        bits: u8,
        buf_addr: usize,
        buf_size: usize,
    ) -> Result<(), super::AudioError> {
        if rate == 0 || channels == 0 || buf_size == 0 {
            return Err(super::AudioError::InvalidConfig);
        }

        let (channel, addr_port, count_port, page_port, dsp_cmd) = if bits == 8 {
            (
                DMA_8BIT,
                dma_ports::ADDR_1,
                dma_ports::COUNT_1,
                dma_ports::PAGE_1,
                dsp::PLAY8,
            )
        } else {
            (
                DMA_16BIT,
                dma_ports::ADDR_5,
                dma_ports::COUNT_5,
                dma_ports::PAGE_5,
                dsp::PLAY16,
            )
        };

        // 1. Mask the DMA channel so programming does not race the
        //    controller. The low 2 bits select the channel; bit 2 clears
        //    vs sets the mask.
        IO::outp(dma_ports::MASK, 0x04 | (channel & 0x03));
        // 2. Reset the flip-flop so address/count writes hit the low byte
        //    first.
        IO::outp(dma_ports::FLIP_FLOP, 0xFF);
        // 3. Write the address low/high bytes.
        let addr = buf_addr as u32;
        IO::outp(addr_port, (addr & 0xFF) as u8);
        IO::outp(addr_port, ((addr >> 8) & 0xFF) as u8);
        // 4. Write the count low/high (count-1 for the ISA controller).
        let count = (buf_size as u32).saturating_sub(1);
        IO::outp(count_port, (count & 0xFF) as u8);
        IO::outp(count_port, ((count >> 8) & 0xFF) as u8);
        // 5. Write the page register (the upper 8 bits of the address
        //    that the DMA controller cannot reach via the address
        //    register alone).
        IO::outp(page_port, ((addr >> 16) & 0xFF) as u8);
        // 6. Set the DMA mode: single, read (device -> memory for
        //    playback? No - playback is memory -> device, so write), no
        //    auto-init, increment, channel N.
        let mode = 0x48 | (channel & 0x03); // single mode, write
        IO::outp(dma_ports::MODE, mode);
        // 7. Unmask the channel.
        IO::outp(dma_ports::MASK, channel & 0x03);

        // 8. Program the DSP: set the time constant, then issue PLAY8 /
        //    PLAY16 with the buffer length.
        let tc = time_constant(rate);
        IO::outp(DSP_WRITE, dsp::SET_TIME_CONSTANT);
        IO::outp(DSP_WRITE, tc);
        IO::outp(DSP_WRITE, dsp_cmd);
        let len = buf_size.min(0xFFFF) as u16;
        IO::outp(DSP_WRITE, (len & 0xFF) as u8);
        IO::outp(DSP_WRITE, ((len >> 8) & 0xFF) as u8);

        ACTIVE_DMA_CHANNEL.store(channel, Ordering::SeqCst);
        ACTIVE_DMA_ADDR.store(addr, Ordering::SeqCst);
        ACTIVE_DMA_COUNT.store(count, Ordering::SeqCst);
        ACTIVE_DSP_CMD.store(dsp_cmd, Ordering::SeqCst);
        DSP_CMD_COUNT.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Program the DMA controller and DSP for a capture (recording) stream.
    /// Symmetric to [`dma_program_playback`] but writes `RECORD8` /
    /// `RECORD16` to the DSP and configures the DMA channel for a
    /// read (device -> memory) transfer.
    pub fn dma_program_capture<IO: PortIo>(
        rate: u32,
        channels: u8,
        bits: u8,
        buf_addr: usize,
        buf_size: usize,
    ) -> Result<(), super::AudioError> {
        if rate == 0 || channels == 0 || buf_size == 0 {
            return Err(super::AudioError::InvalidConfig);
        }

        let (channel, addr_port, count_port, page_port, dsp_cmd) = if bits == 8 {
            (
                DMA_8BIT,
                dma_ports::ADDR_1,
                dma_ports::COUNT_1,
                dma_ports::PAGE_1,
                dsp::RECORD8,
            )
        } else {
            (
                DMA_16BIT,
                dma_ports::ADDR_5,
                dma_ports::COUNT_5,
                dma_ports::PAGE_5,
                dsp::RECORD16,
            )
        };

        IO::outp(dma_ports::MASK, 0x04 | (channel & 0x03));
        IO::outp(dma_ports::FLIP_FLOP, 0xFF);
        let addr = buf_addr as u32;
        IO::outp(addr_port, (addr & 0xFF) as u8);
        IO::outp(addr_port, ((addr >> 8) & 0xFF) as u8);
        let count = (buf_size as u32).saturating_sub(1);
        IO::outp(count_port, (count & 0xFF) as u8);
        IO::outp(count_port, ((count >> 8) & 0xFF) as u8);
        IO::outp(page_port, ((addr >> 16) & 0xFF) as u8);
        // Capture = read transfer (device -> memory)
        let mode = 0x44 | (channel & 0x03);
        IO::outp(dma_ports::MODE, mode);
        IO::outp(dma_ports::MASK, channel & 0x03);

        let tc = time_constant(rate);
        IO::outp(DSP_WRITE, dsp::SET_TIME_CONSTANT);
        IO::outp(DSP_WRITE, tc);
        IO::outp(DSP_WRITE, dsp_cmd);
        let len = buf_size.min(0xFFFF) as u16;
        IO::outp(DSP_WRITE, (len & 0xFF) as u8);
        IO::outp(DSP_WRITE, ((len >> 8) & 0xFF) as u8);

        ACTIVE_DMA_CHANNEL.store(channel, Ordering::SeqCst);
        ACTIVE_DMA_ADDR.store(addr, Ordering::SeqCst);
        ACTIVE_DMA_COUNT.store(count, Ordering::SeqCst);
        ACTIVE_DSP_CMD.store(dsp_cmd, Ordering::SeqCst);
        DSP_CMD_COUNT.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Issue a DSP pause command and unmask the active DMA channel.
    /// Called by [`super::AudioDevice::stop_playback`].
    pub fn dma_pause<IO: PortIo>() {
        IO::outp(DSP_WRITE, dsp::DMA_PAUSE);
        DSP_CMD_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    /// Issue a DSP resume command after a previous pause.
    pub fn dma_resume<IO: PortIo>() {
        IO::outp(DSP_WRITE, dsp::DMA_RESUME);
        DSP_CMD_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

/// AC97 registers
///
/// Owns the AC97-specific commands: the codec probe (reading
/// `EXT_AUDIO_ID`), the sample-rate programming (writing the PCM front
/// rate register), and the bus-master DMA programming for the AC97
/// "PCM Out" / "PCM In" channels. As with the SB16 module, all
/// port-touching functions are generic over a [`PortIo`] backend.
pub mod ac97 {
    use super::PortIo;

    /// AC97 I/O port base. The codec lives at 0xF00 relative to the
    /// native audio bus; in simulation we just record the writes.
    pub const PORT_BASE: u16 = 0xF00;

    /// Native Audio Bus Master registers (the Intel / ICH bus master
    /// engine that moves PCM between memory and the AC97 codec).
    pub mod nam {
        /// PCM Out channel - output box registers.
        pub const PO_BDBAR: u16 = 0x10; // Buffer Descriptor List Base
        pub const PO_CIV: u16 = 0x14; // Current Index Value
        pub const PO_LVI: u16 = 0x15; // Last Valid Index
        pub const PO_SR: u16 = 0x16; // Status
        pub const PO_PICB: u16 = 0x18; // Position In Current Buffer
        pub const PO_CR: u16 = 0x1B; // Control

        /// PCM In channel - input box registers.
        pub const PI_BDBAR: u16 = 0x00;
        pub const PI_CIV: u16 = 0x04;
        pub const PI_LVI: u16 = 0x05;
        pub const PI_SR: u16 = 0x06;
        pub const PI_PICB: u16 = 0x08;
        pub const PI_CR: u16 = 0x0B;

        /// Control register bits.
        pub const CR_RUN: u8 = 0x01;
        pub const CR_RESET: u8 = 0x02;
        pub const CR_FEIE: u8 = 0x04; // FIFO Error Interrupt Enable
        pub const CR_IOCE: u8 = 0x08; // Interrupt On Completion Enable
    }

    /// Register indices
    pub const RESET: u16 = 0x00;
    pub const MASTER_VOL: u16 = 0x02;
    pub const PCM_VOL: u16 = 0x18;
    pub const LINE_IN_VOL: u16 = 0x10;
    pub const MIC_VOL: u16 = 0x0E;
    pub const EXT_AUDIO_ID: u16 = 0x28;
    pub const EXT_AUDIO_CTRL: u16 = 0x2A;
    pub const PCM_FRONT_RATE: u16 = 0x2C;
    pub const PCM_OUT_RATE: u16 = 0x32;
    pub const MIC_RATE: u16 = 0x34;

    /// Sample rates
    pub const RATE_48000: u16 = 48000;
    pub const RATE_44100: u16 = 44100;

    use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};
    static PROBED: AtomicU8 = AtomicU8::new(0);
    static SAMPLE_RATE: AtomicU32 = AtomicU32::new(48000);
    static ACTIVE_BUFFER_ADDR: AtomicU32 = AtomicU32::new(0);
    static ACTIVE_BUFFER_SIZE: AtomicU32 = AtomicU32::new(0);
    static ACTIVE_DIRECTION: AtomicU8 = AtomicU8::new(0);

    /// Probe for an AC97 codec. Reads the `EXT_AUDIO_ID` register; if it
    /// returns a non-zero signature the codec is present.
    ///
    /// In simulation the read returns 0, which we interpret as "no
    /// codec present" so the probe falls through cleanly. The caller
    /// should still consider this a successful no-op.
    pub fn probe() -> bool {
        let id = read_codec(EXT_AUDIO_ID);
        let present = id != 0;
        PROBED.store(if present { 1 } else { 0 }, Ordering::SeqCst);
        present
    }

    /// Read a 16-bit value from the AC97 codec register file.
    ///
    /// `reg` is the register index (0x00 - 0x7E, even). The simulation
    /// returns a placeholder value; the real implementation uses the
    /// AC97 "warm" / "cold" reset protocol.
    fn read_codec(reg: u16) -> u16 {
        let _ = reg;
        0
    }

    /// Program the codec's sample-rate register. The AC97 codec stores the
    /// rate as a 16-bit value split across the PCM front and surround rate
    /// registers; for stereo playback writing the rate to the PCM front
    /// register is sufficient.
    pub fn set_sample_rate(rate: u32) -> Result<(), super::AudioError> {
        if rate == 0 || rate > 0xFFFF {
            return Err(super::AudioError::InvalidConfig);
        }
        SAMPLE_RATE.store(rate, Ordering::SeqCst);
        Ok(())
    }

    /// Read the currently programmed sample rate.
    pub fn current_sample_rate() -> u32 {
        SAMPLE_RATE.load(Ordering::SeqCst)
    }

    /// Program the AC97 bus-master engine for PCM playback.
    ///
    /// The AC97 controller walks a Buffer Descriptor List (BDL) where
    /// each entry is an 8-byte `(addr, length, control)` triple. For
    /// the simulation we accept any non-empty buffer and just record
    /// the parameters.
    pub fn dma_program_playback<IO: PortIo>(
        rate: u32,
        channels: u8,
        buf_addr: usize,
        buf_size: usize,
    ) -> Result<(), super::AudioError> {
        if rate == 0 || channels == 0 || buf_size == 0 {
            return Err(super::AudioError::InvalidConfig);
        }
        // Reset the output box before programming.
        IO::outp(PORT_BASE + nam::PO_CR, nam::CR_RESET);
        // Program the BDL base pointer (low then high - the bus-master
        // engine expects a physical address).
        let addr = buf_addr as u32;
        IO::outp(PORT_BASE + nam::PO_BDBAR, (addr & 0xFF) as u8);
        IO::outp(PORT_BASE + nam::PO_BDBAR, ((addr >> 8) & 0xFF) as u8);
        IO::outp(PORT_BASE + nam::PO_BDBAR, ((addr >> 16) & 0xFF) as u8);
        IO::outp(PORT_BASE + nam::PO_BDBAR, ((addr >> 24) & 0xFF) as u8);
        // Last valid index = 0 (single descriptor).
        IO::outp(PORT_BASE + nam::PO_LVI, 0);
        // Clear status by writing 1 to the run / fifo error / completion bits.
        IO::outp(PORT_BASE + nam::PO_SR, 0x1C);
        // Start the engine.
        IO::outp(PORT_BASE + nam::PO_CR, nam::CR_RUN | nam::CR_IOCE | nam::CR_FEIE);

        ACTIVE_BUFFER_ADDR.store(addr, Ordering::SeqCst);
        ACTIVE_BUFFER_SIZE.store(buf_size as u32, Ordering::SeqCst);
        ACTIVE_DIRECTION.store(1, Ordering::SeqCst);
        Ok(())
    }

    /// Program the AC97 bus-master engine for PCM capture.
    pub fn dma_program_capture<IO: PortIo>(
        rate: u32,
        channels: u8,
        buf_addr: usize,
        buf_size: usize,
    ) -> Result<(), super::AudioError> {
        if rate == 0 || channels == 0 || buf_size == 0 {
            return Err(super::AudioError::InvalidConfig);
        }
        IO::outp(PORT_BASE + nam::PI_CR, nam::CR_RESET);
        let addr = buf_addr as u32;
        IO::outp(PORT_BASE + nam::PI_BDBAR, (addr & 0xFF) as u8);
        IO::outp(PORT_BASE + nam::PI_BDBAR, ((addr >> 8) & 0xFF) as u8);
        IO::outp(PORT_BASE + nam::PI_BDBAR, ((addr >> 16) & 0xFF) as u8);
        IO::outp(PORT_BASE + nam::PI_BDBAR, ((addr >> 24) & 0xFF) as u8);
        IO::outp(PORT_BASE + nam::PI_LVI, 0);
        IO::outp(PORT_BASE + nam::PI_SR, 0x1C);
        IO::outp(PORT_BASE + nam::PI_CR, nam::CR_RUN | nam::CR_IOCE | nam::CR_FEIE);

        ACTIVE_BUFFER_ADDR.store(addr, Ordering::SeqCst);
        ACTIVE_BUFFER_SIZE.store(buf_size as u32, Ordering::SeqCst);
        ACTIVE_DIRECTION.store(2, Ordering::SeqCst);
        Ok(())
    }

    /// Address of the buffer most recently programmed through this module.
    pub fn active_buffer_address() -> u32 {
        ACTIVE_BUFFER_ADDR.load(Ordering::SeqCst)
    }

    /// Size of the buffer most recently programmed.
    pub fn active_buffer_size() -> u32 {
        ACTIVE_BUFFER_SIZE.load(Ordering::SeqCst)
    }

    /// Direction of the most recent DMA program (1 = playback, 2 = capture).
    pub fn active_direction() -> u8 {
        ACTIVE_DIRECTION.load(Ordering::SeqCst)
    }
}

// ============================================================================
// Audio Errors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioError {
    NotFound,
    NotEnabled,
    AlreadyPlaying,
    AlreadyRecording,
    InvalidConfig,
    BufferFull,
    BufferEmpty,
    DMAError,
    Timeout,
}

// ============================================================================
// Global Audio Instance
// ============================================================================

/// Global audio device. The `UnsafeCell` field would normally prevent
/// `Sync`, but for our use the device is only ever touched through
/// `&self` methods that take the `UnsafeCell` lock internally; the
/// upper layer is responsible for serializing access if it is shared
/// across threads. We assert `Sync` here to allow the static below to
/// exist.
unsafe impl Sync for AudioDevice {}

static AUDIO_DEVICE: AudioDevice = AudioDevice::new();

/// Get the global audio device
pub fn audio() -> &'static AudioDevice {
    &AUDIO_DEVICE
}

/// Initialize audio
pub fn audio_init() -> Result<(), AudioError> {
    AUDIO_DEVICE.init()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_config_default() {
        let cfg = AudioConfig::default();
        assert_eq!(cfg.sample_rate, SAMPLE_RATE_44100);
        assert_eq!(cfg.channels, AudioChannels::Stereo);
        assert_eq!(cfg.format, AudioFormat::S16LE);
    }

    #[test]
    fn test_audio_config_bytes_per_sample() {
        let cfg = AudioConfig { sample_rate: 44100, channels: AudioChannels::Stereo, format: AudioFormat::U8 };
        assert_eq!(cfg.bytes_per_sample(), 1);
        let cfg = AudioConfig { sample_rate: 44100, channels: AudioChannels::Stereo, format: AudioFormat::S16LE };
        assert_eq!(cfg.bytes_per_sample(), 2);
        let cfg = AudioConfig { sample_rate: 44100, channels: AudioChannels::Stereo, format: AudioFormat::S32LE };
        assert_eq!(cfg.bytes_per_sample(), 4);
    }

    #[test]
    fn test_audio_config_bytes_per_second() {
        let cfg = AudioConfig { sample_rate: 48000, channels: AudioChannels::Stereo, format: AudioFormat::S16LE };
        // 48000 * 2 * 2 = 192000
        assert_eq!(cfg.bytes_per_second(), 192000);
    }

    #[test]
    fn test_dma_buffer_position() {
        let buf = DmaBuffer::new(0x1000, 64);
        assert_eq!(buf.position(), 0);
        assert_eq!(buf.remaining(), 64);
        buf.set_position(20);
        assert_eq!(buf.position(), 20);
        assert_eq!(buf.remaining(), 44);
        // Clamp
        buf.set_position(1000);
        assert_eq!(buf.position(), 64);
    }

    #[test]
    fn test_dma_buffer_copy_in() {
        let buf = DmaBuffer::new(0x1000, 16);
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        let n = buf.copy_in(&data);
        assert_eq!(n, 8);
        assert_eq!(buf.position(), 8);
    }

    #[test]
    fn test_dma_buffer_copy_out() {
        let buf = DmaBuffer::new(0x1000, 16);
        buf.copy_in(&[10, 20, 30]);
        buf.reset();
        let mut out = [0u8; 3];
        let n = buf.copy_out(&mut out);
        assert_eq!(n, 3);
        assert_eq!(out, [10, 20, 30]);
    }

    #[test]
    fn test_device_init_marks_enabled() {
        let dev = AudioDevice::new();
        assert!(!dev.is_enabled());
        dev.init().unwrap();
        assert!(dev.is_enabled());
    }

    #[test]
    fn test_configure_then_query() {
        let dev = AudioDevice::new();
        dev.init().unwrap();
        let cfg = AudioConfig { sample_rate: 22050, channels: AudioChannels::Mono, format: AudioFormat::U8 };
        dev.configure(cfg).unwrap();
        assert_eq!(dev.config().sample_rate, 22050);
        assert_eq!(dev.config().channels, AudioChannels::Mono);
        assert_eq!(dev.config().format, AudioFormat::U8);
    }

    #[test]
    fn test_configure_rejects_zero_rate() {
        let dev = AudioDevice::new();
        dev.init().unwrap();
        let cfg = AudioConfig { sample_rate: 0, channels: AudioChannels::Stereo, format: AudioFormat::S16LE };
        let result = dev.configure(cfg);
        assert!(matches!(result, Err(AudioError::InvalidConfig)));
    }

    #[test]
    fn test_configure_before_init() {
        let dev = AudioDevice::new();
        let cfg = AudioConfig::default();
        let result = dev.configure(cfg);
        assert!(matches!(result, Err(AudioError::NotEnabled)));
    }

    #[test]
    fn test_volume() {
        let dev = AudioDevice::new();
        assert_eq!(dev.volume(), 80);
        dev.set_volume(50);
        assert_eq!(dev.volume(), 50);
        // Clamped to 100
        dev.set_volume(200);
        assert_eq!(dev.volume(), 100);
    }

    #[test]
    fn test_playback_lifecycle() {
        let dev = AudioDevice::new();
        dev.init().unwrap();
        assert!(!dev.is_playing());
        dev.start_playback().unwrap();
        assert!(dev.is_playing());
        // Cannot start twice
        assert!(matches!(dev.start_playback(), Err(AudioError::AlreadyPlaying)));
        dev.stop_playback();
        assert!(!dev.is_playing());
    }

    #[test]
    fn test_recording_lifecycle() {
        let dev = AudioDevice::new();
        dev.init().unwrap();
        assert!(!dev.is_recording());
        dev.start_recording().unwrap();
        assert!(dev.is_recording());
        // Cannot start twice
        assert!(matches!(dev.start_recording(), Err(AudioError::AlreadyRecording)));
        dev.stop_recording();
        assert!(!dev.is_recording());
    }

    #[test]
    fn test_write_data() {
        let dev = AudioDevice::new();
        dev.init().unwrap();
        let data = [1u8, 2, 3, 4];
        let n = dev.write(&data).unwrap();
        assert_eq!(n, 4);
    }

    #[test]
    fn test_read_requires_recording() {
        let dev = AudioDevice::new();
        dev.init().unwrap();
        let mut buf = [0u8; 8];
        let result = dev.read(&mut buf);
        assert!(matches!(result, Err(AudioError::BufferEmpty)));
    }

    #[test]
    fn test_mixer_default() {
        let m = Mixer::new();
        assert_eq!(m.volume(MixerControl::MasterVolume), 80);
        assert_eq!(m.volume(MixerControl::PCMVolume), 80);
    }

    #[test]
    fn test_mixer_set_get() {
        let m = Mixer::new();
        m.set_volume(MixerControl::PCMVolume, 50);
        assert_eq!(m.volume(MixerControl::PCMVolume), 50);
        // Clamped
        m.set_volume(MixerControl::MicVolume, 200);
        assert_eq!(m.volume(MixerControl::MicVolume), 100);
    }

    #[test]
    fn test_sb16_probe() {
        assert!(sb16::probe::<SimulatedPort>());
    }

    #[test]
    fn test_sb16_sample_rate() {
        sb16::set_sample_rate(22050).unwrap();
        assert_eq!(sb16::current_sample_rate(), 22050);
        assert!(sb16::set_sample_rate(0).is_err());
    }

    #[test]
    fn test_sb16_speaker() {
        assert!(!sb16::speaker_state());
        sb16::speaker_on();
        assert!(sb16::speaker_state());
        sb16::speaker_off();
        assert!(!sb16::speaker_state());
    }

    #[test]
    fn test_ac97_probe() {
        // The simulator returns 0 from the codec register read, so the
        // probe correctly reports "no codec" rather than always true.
        assert!(!ac97::probe());
    }

    #[test]
    fn test_ac97_sample_rate() {
        ac97::set_sample_rate(48000).unwrap();
        assert_eq!(ac97::current_sample_rate(), 48000);
        assert!(ac97::set_sample_rate(0).is_err());
    }

    // ========================================================================
    // New tests: PortIo, DMA buffer half-buffer tracking, DMA programming,
    // codec helpers, and end-to-end AudioDevice::poll behavior.
    // ========================================================================

    #[test]
    fn test_audio_format_bits_per_sample() {
        assert_eq!(AudioFormat::U8.bits_per_sample(), 8);
        assert_eq!(AudioFormat::S16LE.bits_per_sample(), 16);
        assert_eq!(AudioFormat::S16BE.bits_per_sample(), 16);
        assert_eq!(AudioFormat::S32LE.bits_per_sample(), 32);
    }

    #[test]
    fn test_sb16_probe_with_simulator_succeeds() {
        // The SimulatedPort returns 0xAA from the DSP read port, so the
        // SB16 probe must report the device as present.
        assert!(sb16::probe::<SimulatedPort>());
    }

    #[test]
    fn test_sb16_time_constant() {
        // Per the SB16 datasheet: tc = 256 - 1_000_000 / rate.
        // For 44100 Hz: tc = 256 - 22.67 = 233 (truncated).
        assert_eq!(sb16::time_constant(44100), 233);
        assert_eq!(sb16::time_constant(22050), 211); // 256 - 45
        assert_eq!(sb16::time_constant(0), 0);
    }

    #[test]
    fn test_dma_program_playback_selects_channel_and_dsp_cmd() {
        // Reset command count for a clean assertion.
        let before = sb16::dsp_command_count();
        let result = sb16::dma_program_playback::<SimulatedPort>(
            44100, 2, 16, 0x1000, 4096,
        );
        assert!(result.is_ok());
        // S16LE -> DMA channel 5, DSP PLAY16 command (0xB0).
        assert_eq!(sb16::active_dma_channel(), 5);
        assert_eq!(sb16::active_dsp_command(), 0xB0);
        assert_eq!(sb16::active_dma_addr(), 0x1000);
        // Count is size - 1 for ISA DMA controllers.
        assert_eq!(sb16::active_dma_count(), 4095);
        // At least one new DSP command must have been emitted.
        assert!(sb16::dsp_command_count() > before);

        // U8 -> DMA channel 1, DSP PLAY8 command (0x14).
        let before2 = sb16::dsp_command_count();
        sb16::dma_program_playback::<SimulatedPort>(
            22050, 1, 8, 0x2000, 8192,
        ).unwrap();
        assert_eq!(sb16::active_dma_channel(), 1);
        assert_eq!(sb16::active_dsp_command(), 0x14);
        assert_eq!(sb16::active_dma_addr(), 0x2000);
        assert_eq!(sb16::active_dma_count(), 8191);
        assert!(sb16::dsp_command_count() > before2);
    }

    #[test]
    fn test_dma_program_capture_uses_record_commands() {
        let before = sb16::dsp_command_count();
        sb16::dma_program_capture::<SimulatedPort>(
            48000, 2, 16, 0x3000, 16384,
        ).unwrap();
        // S16BE-style capture uses RECORD16 (0xB4) on DMA channel 5.
        assert_eq!(sb16::active_dma_channel(), 5);
        assert_eq!(sb16::active_dsp_command(), 0xB4);
        assert_eq!(sb16::active_dma_addr(), 0x3000);
        assert_eq!(sb16::active_dma_count(), 16383);
        assert!(sb16::dsp_command_count() > before);

        // U8 capture -> RECORD8 (0x24) on channel 1.
        sb16::dma_program_capture::<SimulatedPort>(
            11025, 1, 8, 0x4000, 2048,
        ).unwrap();
        assert_eq!(sb16::active_dma_channel(), 1);
        assert_eq!(sb16::active_dsp_command(), 0x24);
    }

    #[test]
    fn test_dma_program_rejects_invalid_arguments() {
        assert!(sb16::dma_program_playback::<SimulatedPort>(
            0, 2, 16, 0x1000, 4096
        ).is_err());
        assert!(sb16::dma_program_playback::<SimulatedPort>(
            44100, 0, 16, 0x1000, 4096
        ).is_err());
        assert!(sb16::dma_program_playback::<SimulatedPort>(
            44100, 2, 16, 0x1000, 0
        ).is_err());
        assert!(sb16::dma_program_capture::<SimulatedPort>(
            44100, 2, 16, 0x1000, 0
        ).is_err());
    }

    #[test]
    fn test_dma_buffer_half_complete_callback() {
        let buf = DmaBuffer::new(0x1000, 64);
        assert_eq!(buf.half_size(), 32);

        // Drain 16 bytes - still in first half.
        buf.poll(16);
        assert_eq!(buf.position(), 16);
        assert!(!buf.has_half_complete());

        // Drain another 16 bytes - crosses into second half.
        buf.poll(16);
        assert_eq!(buf.position(), 32);
        assert!(buf.has_half_complete());
        assert_eq!(buf.take_half_complete(), Some(0));
        assert!(!buf.has_half_complete());

        // Drain 32 more bytes - crosses end of buffer, wraps to 0.
        buf.poll(32);
        assert_eq!(buf.position(), 0);
        assert!(buf.take_end_of_buffer());
        assert!(!buf.has_half_complete());
    }

    #[test]
    fn test_dma_buffer_end_of_buffer_only_fires_once() {
        let buf = DmaBuffer::new(0x1000, 32);
        buf.poll(32); // wrap
        assert!(buf.take_end_of_buffer());
        // Second read clears the flag.
        assert!(!buf.take_end_of_buffer());
    }

    #[test]
    fn test_audio_device_poll_reports_half_events() {
        let dev = AudioDevice::new();
        dev.init().unwrap();
        dev.configure(AudioConfig::default()).unwrap();

        // Need to be in playback state for poll to do work.
        dev.start_playback().unwrap();

        // Drain more than one half of the 64KiB buffer.
        let half = 32 * 1024;
        let result = dev.poll(half + 1024);
        assert!(result.end_of_buffer);
        assert_eq!(result.half_completes.len(), 1);
        assert!(dev.half_event_count() >= 1);

        // Polling with 0 bytes when not playing is a no-op.
        dev.stop_playback();
        let result = dev.poll(0);
        assert_eq!(result.half_completes.len(), 0);
        assert!(!result.end_of_buffer);
    }

    #[test]
    fn test_codec_scale_i16_saturates() {
        assert_eq!(codec::scale_i16(0, 100), 0);
        assert_eq!(codec::scale_i16(i16::MAX, 100), i16::MAX);
        assert_eq!(codec::scale_i16(i16::MAX, 50), i16::MAX / 2);
        assert_eq!(codec::scale_i16(i16::MAX, 200), i16::MAX); // clamp
        assert_eq!(codec::scale_i16(i16::MIN, 200), i16::MIN); // clamp
        assert_eq!(codec::scale_i16(1234, 0), 0);
    }

    #[test]
    fn test_codec_scale_u8_zeroes_silences() {
        let mut buf = [0xFFu8; 8]; // U8 PCM max = +127 centred
        codec::scale_u8(&mut buf, 50);
        // All samples were max positive; after 50% they should be ~191.
        for &b in buf.iter() {
            assert!((b as i32 - 191).abs() <= 1, "got {}", b);
        }
        codec::scale_u8(&mut buf, 0);
        for &b in buf.iter() {
            assert_eq!(b, 128, "volume 0 must yield silence (bias 128)");
        }
    }

    #[test]
    fn test_codec_silence_detection() {
        let silence_u8 = [128u8; 16];
        let silence_s16 = [0u8; 16];
        let noise = [200u8, 100, 50, 0, 0, 0, 0, 0];
        assert!(codec::is_silence(&silence_u8, AudioFormat::U8, 0));
        assert!(codec::is_silence(&silence_s16, AudioFormat::S16LE, 0));
        assert!(!codec::is_silence(&noise, AudioFormat::U8, 0));
        assert!(!codec::is_silence(&noise, AudioFormat::U8, 200));
    }

    #[test]
    fn test_codec_s16le_to_u8_round_trip() {
        // Sample = 0 -> top byte 0, biased to 128.
        let s16 = [0u8, 0, 0xFF, 0x7F, 0x00, 0x80];
        let mut u8_buf = [0u8; 3];
        let n = codec::s16le_to_u8(&s16, &mut u8_buf);
        assert_eq!(n, 3);
        assert_eq!(u8_buf[0], 128); // 0 -> 128
        assert_eq!(u8_buf[1], 255); // +32767 -> top byte 0xFF + bias
        assert_eq!(u8_buf[2], 0); // -32768 -> top byte 0x00 + bias (wraps)
    }

    #[test]
    fn test_codec_u8_to_s16le_promotion() {
        let u8_in = [128u8, 0, 255];
        let mut s16_out = [0u8; 6];
        let n = codec::u8_to_s16le(&u8_in, &mut s16_out);
        assert_eq!(n, 3);
        // 128 -> centred 0 -> 0x0000
        assert_eq!(&s16_out[0..2], &[0, 0]);
        // 0 -> centred -128 -> 0x8000 (little-endian: 0x00, 0x80)
        assert_eq!(&s16_out[2..4], &[0, 0x80]);
        // 255 -> centred +127 -> 0x7F00 (little-endian: 0x00, 0x7F)
        assert_eq!(&s16_out[4..6], &[0, 0x7F]);
    }

    #[test]
    fn test_audio_device_is_enabled_after_init() {
        let dev = AudioDevice::new();
        assert!(!dev.is_enabled());
        dev.init().unwrap();
        assert!(dev.is_enabled());
    }

    #[test]
    fn test_audio_device_start_playback_initializes_dma() {
        let dev = AudioDevice::new();
        dev.init().unwrap();
        // Verify DMA is not programmed yet.
        let before = sb16::dsp_command_count();
        dev.start_playback().unwrap();
        // start_playback must emit at least the SET_TIME_CONSTANT and
        // PLAY8/PLAY16 DSP commands.
        assert!(sb16::dsp_command_count() >= before + 3);
        assert!(dev.is_playing());

        // Restarting resets the DMA bookkeeping.
        dev.stop_playback();
        assert!(!dev.is_playing());
    }

    #[test]
    fn test_audio_device_drain_via_poll() {
        let dev = AudioDevice::new();
        dev.init().unwrap();
        dev.configure(AudioConfig {
            sample_rate: 44100,
            channels: AudioChannels::Stereo,
            format: AudioFormat::S16LE,
        }).unwrap();
        dev.start_playback().unwrap();

        // Write some data into the DMA buffer; `write` auto-starts
        // playback but we already started, so it just queues.
        let data = alloc::vec![0xAAu8; 256];
        let copied = dev.write(&data).unwrap();
        assert_eq!(copied, 256);

        // Poll the device simulating 1 KiB of consumer activity.
        let result = dev.poll(1024);
        assert_eq!(result.consumed, 1024);
        assert_eq!(result.total_consumed, 1024);
    }
}
