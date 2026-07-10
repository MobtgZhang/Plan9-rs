//! Plumb Attribute Handling
//!
//! Implements the Plumbattr linked list structure and operations.

use alloc::boxed::Box;
use alloc::string::ToString;

/// Plumb attribute (key-value pair)
#[derive(Debug, Clone)]
pub struct Plumbattr {
    /// Attribute name
    pub name: alloc::string::String,
    /// Attribute value
    pub value: alloc::string::String,
    /// Next attribute in the list
    pub next: Option<Box<Plumbattr>>,
}

impl Plumbattr {
    /// Create a new attribute
    pub fn new(name: &str, value: &str) -> Self {
        Plumbattr {
            name: name.to_string(),
            value: value.to_string(),
            next: None,
        }
    }

    /// Add an attribute to the end of the list
    pub fn add(&mut self, name: &str, value: &str) {
        let mut current = self;
        while current.next.is_some() {
            current = current.next.as_mut().unwrap();
        }
        current.next = Some(Box::new(Plumbattr::new(name, value)));
    }

    /// Find an attribute by name
    pub fn find(&self, name: &str) -> Option<&str> {
        if self.name == name {
            return Some(&self.value);
        }
        if let Some(ref next) = self.next {
            next.find(name)
        } else {
            None
        }
    }

    /// Find and get mutable reference to an attribute by name
    pub fn find_mut(&mut self, name: &str) -> Option<&mut str> {
        if self.name == name {
            return Some(&mut self.value);
        }
        if let Some(ref mut next) = self.next {
            next.find_mut(name)
        } else {
            None
        }
    }

    /// Delete an attribute by name
    pub fn delete(&mut self, name: &str) -> bool {
        // Check head
        if self.name == name {
            // Replace self with next
            if let Some(next) = self.next.take() {
                self.name = next.name;
                self.value = next.value;
                self.next = next.next;
            }
            return true;
        }

        // Check rest of list
        if let Some(ref mut current) = self.next {
            if current.name == name {
                self.next = current.next.take();
                return true;
            }
            return current.delete(name);
        }

        false
    }

    /// Get the number of attributes in the list
    pub fn len(&self) -> usize {
        let mut count = 1;
        let mut current = self;
        while let Some(ref next) = current.next {
            count += 1;
            current = next;
        }
        count
    }

    /// Check if the list has no real attributes.
    ///
    /// The head of a Plan 9 plumb attribute list always carries the
    /// attribute named `""` (empty string), so we treat the list as
    /// empty only when the head has no name AND no value AND no
    /// successor. This is useful for callers that want to know whether
    /// `add()` would actually append anything new.
    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && self.value.is_empty() && self.next.is_none()
    }

    /// Iterate over attribute names
    pub fn names<'a>(&'a self) -> impl Iterator<Item = &'a str> {
        PlumbattrNamesIter { attr: Some(self) }
    }

    /// Iterate over attribute values
    pub fn values<'a>(&'a self) -> impl Iterator<Item = &'a str> {
        PlumbattrValuesIter { attr: Some(self) }
    }
}

struct PlumbattrNamesIter<'a> {
    attr: Option<&'a Plumbattr>,
}

impl<'a> Iterator for PlumbattrNamesIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        match self.attr.take() {
            Some(attr) => {
                self.attr = attr.next.as_deref();
                Some(&attr.name)
            }
            None => None,
        }
    }
}

struct PlumbattrValuesIter<'a> {
    attr: Option<&'a Plumbattr>,
}

impl<'a> Iterator for PlumbattrValuesIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        match self.attr.take() {
            Some(attr) => {
                self.attr = attr.next.as_deref();
                Some(&attr.value)
            }
            None => None,
        }
    }
}

impl Default for Plumbattr {
    fn default() -> Self {
        Plumbattr::new("", "")
    }
}
