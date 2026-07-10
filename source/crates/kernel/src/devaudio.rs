

//! Audio Device Implementation
//!
//! Implements the Plan 9 audio device (#a) for audio playback and recording.
//!
//! ## Overview
//!
//! The audio device provides access to audio playback and recording.
//!
//! ## Namespace Structure
//!
//! ```
//! /dev/
//! ├── audio           (playback/recording)
//! └── volume          (volume control)
//! ```


extern crate alloc;

use crate::dev::{self, Dev, Chan, Qid, DirEntry, Error as DevError};

use crate::plan9_common::sync::Spinlock;
use alloc::vec::Vec;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

/// Qid paths for audio device
mod audio_qid {
    pub const QAUDIO: u64 = 0;
    pub const QVOLUME: u64 = 1;
    pub const QCTL: u64 = 2;
}

/// Audio device structure
pub struct AudioDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Audio is enabled
    enabled: AtomicBool,
    /// Current configuration
    config: Spinlock<AudioConfig>,
}

/// Audio configuration for device interface
#[derive(Debug, Clone, Default)]
struct AudioConfig {
    /// Sample rate
    sample_rate: u32,
    /// Channels (1=mono, 2=stereo)
    channels: u8,
    /// Bits per sample
    bits: u8,
}

impl AudioDev {
    /// Create a new audio device
    pub fn new() -> Self {
        Self {
            name: "audio",
            dev_char: 'a',
            enabled: AtomicBool::new(false),
            config: Spinlock::new(AudioConfig::default()),
        }
    }
    
    /// Enable the audio device
    pub fn enable(&self) {
        if let Err(e) = crate::plan9_drivers::audio::audio_init() {
            let _ = e;
        }
        self.enabled.store(true, Ordering::SeqCst);
    }
    
    /// Disable the audio device
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }
}

impl Dev for AudioDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        Ok(Chan::new(
            dev::devtype::AUDIO,
            Qid::new(audio_qid::QAUDIO, 0, 0),
            0,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let qid = ch.qid.path;
        
        match name {
            "audio" | "" => {
                if qid == audio_qid::QAUDIO {
                    Ok(Some(ch.qid))
                } else {
                    ch.qid = Qid::new(audio_qid::QAUDIO, 0, 0);
                    Ok(Some(ch.qid))
                }
            }
            "volume" => {
                ch.qid = Qid::new(audio_qid::QVOLUME, 0, 0);
                Ok(Some(ch.qid))
            }
            "ctl" => {
                ch.qid = Qid::new(audio_qid::QCTL, 0, 0);
                Ok(Some(ch.qid))
            }
            _ => Err(DevError::Enoent),
        }
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        if !self.enabled.load(Ordering::SeqCst) {
            self.enable();
        }
        ch.mode = mode;
        Ok(())
    }

    fn create(&mut self, _ch: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn close(&mut self, _ch: &mut Chan) {
        // Stop playback/recording
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, DevError> {
        if !self.enabled.load(Ordering::SeqCst) {
            self.enable();
        }
        
        let qid = ch.qid.path;
        let audio = crate::plan9_drivers::audio::audio();
        
        match qid {
            audio_qid::QAUDIO => {
                // Read audio data (recording)
                if let Ok(data) = audio.read(buf) {
                    Ok(data)
                } else {
                    Ok(0)
                }
            }
            audio_qid::QVOLUME => {
                // Read volume information
                let vol = audio.volume();
                let master = audio.master_volume();
                let info = format!("volume {} master {}\n", vol, master);
                let len = info.len().min(buf.len());
                buf[..len].copy_from_slice(&info.as_bytes()[..len]);
                Ok(len)
            }
            audio_qid::QCTL => {
                // Read audio configuration
                let config = audio.config();
                let info = format!(
                    "rate {} channels {} format {:?}\n",
                    config.sample_rate,
                    config.channels as u8,
                    config.format
                );
                let len = info.len().min(buf.len());
                buf[..len].copy_from_slice(&info.as_bytes()[..len]);
                Ok(len)
            }
            _ => Err(DevError::Enoent),
        }
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, DevError> {
        if !self.enabled.load(Ordering::SeqCst) {
            self.enable();
        }
        
        let qid = ch.qid.path;
        let audio = crate::plan9_drivers::audio::audio();
        
        match qid {
            audio_qid::QAUDIO => {
                // Write audio data (playback)
                if let Ok(count) = audio.write(buf) {
                    Ok(count)
                } else {
                    Err(DevError::Eio)
                }
            }
            audio_qid::QVOLUME => {
                // Set volume
                let cmd = String::from_utf8_lossy(buf);
                let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
                
                if parts.is_empty() {
                    return Err(DevError::Einval);
                }
                
                match parts[0] {
                    "vol" | "volume" => {
                        if parts.len() >= 2 {
                            if let Ok(v) = parts[1].parse::<u32>() {
                                audio.set_volume(v);
                            }
                        }
                        if parts.len() >= 3 {
                            if let Ok(v) = parts[2].parse::<u32>() {
                                audio.set_master_volume(v);
                            }
                        }
                        Ok(buf.len())
                    }
                    _ => Err(DevError::Einval),
                }
            }
            audio_qid::QCTL => {
                // Configure audio
                let cmd = String::from_utf8_lossy(buf);
                let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
                
                if parts.is_empty() {
                    return Err(DevError::Einval);
                }
                
                match parts[0] {
                    "rate" => {
                        if parts.len() >= 2 {
                            if let Ok(rate) = parts[1].parse::<u32>() {
                                let config = audio.config();
                                crate::plan9_drivers::audio::AudioConfig {
                                    sample_rate: rate,
                                    channels: config.channels,
                                    format: config.format,
                                };
                            }
                        }
                        Ok(buf.len())
                    }
                    "start" => {
                        if parts.len() >= 2 {
                            match parts[1] {
                                "playback" | "play" => {
                                    let _ = audio.start_playback();
                                }
                                "record" | "rec" => {
                                    let _ = audio.start_recording();
                                }
                                _ => {}
                            }
                        }
                        Ok(buf.len())
                    }
                    "stop" => {
                        if parts.len() >= 2 {
                            match parts[1] {
                                "playback" | "play" => {
                                    audio.stop_playback();
                                }
                                "record" | "rec" => {
                                    audio.stop_recording();
                                }
                                _ => {}
                            }
                        }
                        Ok(buf.len())
                    }
                    _ => Err(DevError::Einval),
                }
            }
            _ => Err(DevError::Eperm),
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let qid = ch.qid.path;
        
        let (name, mode) = match qid {
            audio_qid::QAUDIO => (b"audio".to_vec(), 0o666),
            audio_qid::QVOLUME => (b"volume".to_vec(), 0o666),
            audio_qid::QCTL => (b"ctl".to_vec(), 0o666),
            _ => return Err(DevError::Enoent),
        };
        
        Ok(DirEntry {
            dev: dev::devtype::AUDIO,
            qid: ch.qid,
            mode: mode | 0o20000, // S_IFCHR
            atime: 0,
            mtime: 0,
            length: 0,
            name,
        })
    }

    fn wstat(&mut self, _ch: &mut Chan, _dir: &DirEntry) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn remove(&mut self, _ch: &mut Chan) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}
