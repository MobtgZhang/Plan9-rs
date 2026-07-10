//! Plumb Message Structure
//!
//! Implements the Plumbmsg structure for inter-application messaging.

use crate::attr::Plumbattr;

/// Plumb message
///
/// The plumb protocol sends messages between applications using a simple
/// text-based format with binary data at the end.
#[derive(Debug, Clone)]
pub struct Plumbmsg {
    /// Source port name (the sending application)
    pub src: alloc::string::String,
    /// Destination port name (the receiving application)
    pub dst: alloc::string::String,
    /// Working directory (optional)
    pub wdir: Option<alloc::string::String>,
    /// Message type (e.g., "text", "display", "sendfile")
    pub mtype: alloc::string::String,
    /// Attribute list
    pub attr: Option<alloc::boxed::Box<Plumbattr>>,
    /// Length of data
    pub ndata: usize,
    /// Message data
    pub data: alloc::vec::Vec<u8>,
}

impl Plumbmsg {
    /// Create a new message
    pub fn new(src: &str, dst: &str, mtype: &str) -> Self {
        Plumbmsg {
            src: alloc::string::String::from(src),
            dst: alloc::string::String::from(dst),
            wdir: None,
            mtype: alloc::string::String::from(mtype),
            attr: None,
            ndata: 0,
            data: alloc::vec::Vec::new(),
        }
    }

    /// Create a text message
    pub fn new_text(src: &str, dst: &str, text: &str) -> Self {
        let mut msg = Plumbmsg::new(src, dst, "text");
        msg.set_data(text.as_bytes());
        msg
    }

    /// Create a sendfile message
    pub fn new_sendfile(src: &str, dst: &str, path: &str) -> Self {
        let mut msg = Plumbmsg::new(src, dst, "sendfile");
        msg.set_data(path.as_bytes());
        msg
    }

    /// Set the working directory
    pub fn set_wdir(&mut self, wdir: &str) {
        self.wdir = Some(alloc::string::String::from(wdir));
    }

    /// Set the data
    pub fn set_data(&mut self, data: &[u8]) {
        self.data = data.to_vec();
        self.ndata = data.len();
    }

    /// Set the data from a string
    pub fn set_text(&mut self, text: &str) {
        self.set_data(text.as_bytes());
        if self.mtype.is_empty() || self.mtype == "text" {
            self.mtype = alloc::string::String::from("text");
        }
    }

    /// Add an attribute
    pub fn add_attr(&mut self, name: &str, value: &str) {
        if let Some(ref mut attr) = self.attr {
            attr.add(name, value);
        } else {
            self.attr = Some(alloc::boxed::Box::new(Plumbattr::new(name, value)));
        }
    }

    /// Get an attribute by name
    pub fn get_attr(&self, name: &str) -> Option<&str> {
        self.attr.as_ref().and_then(|attr| attr.find(name))
    }

    /// Check if message has data
    pub fn has_data(&self) -> bool {
        !self.data.is_empty()
    }

    /// Get data as a string (if valid UTF-8)
    pub fn data_as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.data).ok()
    }

    /// Get data as a mutable string (if valid UTF-8)
    ///
    /// Returns `Some(&mut str)` when the underlying byte buffer is valid
    /// UTF-8, otherwise `None`. The mutable borrow is safe because
    /// `data` is owned by the message and not aliased elsewhere.
    pub fn data_as_str_mut(&mut self) -> Option<&mut str> {
        core::str::from_utf8_mut(&mut self.data).ok()
    }
}

impl Default for Plumbmsg {
    fn default() -> Self {
        Plumbmsg::new("", "", "")
    }
}
