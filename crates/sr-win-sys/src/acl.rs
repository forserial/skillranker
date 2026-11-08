//! Access-control entries and security descriptors, parsed in safe code from
//! the bytes [`crate::windows`] copies out of Windows.
#![forbid(unsafe_code)]

use std::fmt;

use crate::sid::{Sid, SidError};

/// `OBJECT_INHERIT_ACE`.
pub const OBJECT_INHERIT: u8 = 0x01;
/// `CONTAINER_INHERIT_ACE`.
pub const CONTAINER_INHERIT: u8 = 0x02;
/// `NO_PROPAGATE_INHERIT_ACE`.
pub const NO_PROPAGATE_INHERIT: u8 = 0x04;
/// `INHERIT_ONLY_ACE`: the entry does not apply to the object that holds it.
pub const INHERIT_ONLY: u8 = 0x08;
/// `INHERITED_ACE`: the entry was inherited from a parent.
pub const INHERITED: u8 = 0x10;

/// `SE_DACL_PROTECTED` in a descriptor's control word.
pub const DACL_PROTECTED: u16 = 0x1000;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// The kind of an entry. Only the two plain kinds carry a parsed SID; every
/// other type (object, callback, audit, mandatory label…) is reported as
/// `Other` so a caller can refuse it instead of misreading it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AceKind {
    Allowed,
    Denied,
    Other(u8),
}

/// One access-control entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ace {
    pub kind: AceKind,
    pub flags: u8,
    /// The access mask, as stored (generic bits are not mapped).
    pub mask: u32,
    /// The trustee, for `Allowed` and `Denied` entries.
    pub sid: Option<Sid>,
}

impl Ace {
    /// Whether the entry applies to the object that holds it.
    pub fn applies_to_object(&self) -> bool {
        self.flags & INHERIT_ONLY == 0
    }

    pub fn is_inherited(&self) -> bool {
        self.flags & INHERITED != 0
    }

    /// Parses exactly one entry: `ACE_HEADER { type, flags, size }`, then for
    /// the plain kinds `mask` and the trustee SID.
    pub fn parse(bytes: &[u8]) -> Result<Self, AceError> {
        let [kind, flags, size_low, size_high, ..] = bytes else {
            return Err(AceError::Truncated);
        };
        let size = usize::from(u16::from_le_bytes([*size_low, *size_high]));
        if size != bytes.len() || size < 8 {
            return Err(AceError::Size(size));
        }
        let mask = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let (kind, sid) = match *kind {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE => {
                let (sid, length) = Sid::parse_prefix(&bytes[8..]).map_err(AceError::Sid)?;
                // ACEs are DWORD-aligned and a SID is a whole number of
                // DWORDs, so nothing may follow the SID.
                if 8 + length != size {
                    return Err(AceError::Size(size));
                }
                let kind = if *kind == ACCESS_ALLOWED_ACE_TYPE {
                    AceKind::Allowed
                } else {
                    AceKind::Denied
                };
                (kind, Some(sid))
            }
            other => (AceKind::Other(other), None),
        };
        Ok(Self {
            kind,
            flags: *flags,
            mask,
            sid,
        })
    }
}

/// Why bytes are not an entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AceError {
    Truncated,
    Size(usize),
    Sid(SidError),
}

impl fmt::Display for AceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("ACE bytes are truncated"),
            Self::Size(size) => write!(f, "ACE size {size} does not match its contents"),
            Self::Sid(error) => write!(f, "ACE trustee: {error}"),
        }
    }
}

impl std::error::Error for AceError {}

/// The owner and DACL of one object, read from its handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor {
    pub owner: Sid,
    /// The descriptor's control word.
    pub control: u16,
    /// `None` is a NULL DACL, which grants everyone full access.
    pub dacl: Option<Vec<Ace>>,
}

impl Descriptor {
    /// Whether the DACL is protected from inheriting its parent's entries.
    pub fn dacl_protected(&self) -> bool {
        self.control & DACL_PROTECTED != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ace(kind: u8, flags: u8, mask: u32, sid: &Sid) -> Vec<u8> {
        let body = sid.to_bytes();
        let size = (8 + body.len()) as u16;
        let mut bytes = vec![kind, flags];
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes
    }

    #[test]
    fn parses_allowed_and_denied_entries() {
        let users = Sid::new(5, &[32, 545]).unwrap();
        let allowed =
            Ace::parse(&ace(0, INHERITED | CONTAINER_INHERIT, 0x001F_01FF, &users)).unwrap();
        assert_eq!(allowed.kind, AceKind::Allowed);
        assert_eq!(allowed.mask, 0x001F_01FF);
        assert_eq!(allowed.sid.as_ref(), Some(&users));
        assert!(allowed.is_inherited());
        assert!(allowed.applies_to_object());

        let denied = Ace::parse(&ace(1, INHERIT_ONLY | OBJECT_INHERIT, 0x2, &users)).unwrap();
        assert_eq!(denied.kind, AceKind::Denied);
        assert!(!denied.applies_to_object());
        assert!(!denied.is_inherited());
    }

    #[test]
    fn other_entry_types_keep_no_trustee() {
        let users = Sid::new(5, &[32, 545]).unwrap();
        // ACCESS_ALLOWED_OBJECT_ACE_TYPE: its SID is not at offset 8.
        let parsed = Ace::parse(&ace(5, 0, 0x10, &users)).unwrap();
        assert_eq!(parsed.kind, AceKind::Other(5));
        assert_eq!(parsed.sid, None);
    }

    #[test]
    fn malformed_entries_are_refused() {
        let users = Sid::new(5, &[32, 545]).unwrap();
        assert_eq!(Ace::parse(&[0, 0, 8]), Err(AceError::Truncated));
        let mut bytes = ace(0, 0, 1, &users);
        // The header says 24 bytes but 25 are given.
        bytes.push(0);
        assert_eq!(Ace::parse(&bytes), Err(AceError::Size(24)));
        // Padding after the trustee SID, with a header that counts it.
        let mut bytes = ace(0, 0, 1, &users);
        bytes.extend_from_slice(&[0; 4]);
        bytes[2] = 28;
        assert_eq!(Ace::parse(&bytes), Err(AceError::Size(28)));
        let mut bytes = ace(0, 0, 1, &users);
        bytes[8] = 9;
        assert_eq!(
            Ace::parse(&bytes),
            Err(AceError::Sid(SidError::Revision(9)))
        );
        assert_eq!(Ace::parse(&[0, 0, 4, 0]), Err(AceError::Size(4)));
    }

    #[test]
    fn protected_bit_is_read_from_the_control_word() {
        let owner = Sid::new(5, &[18]).unwrap();
        let open = Descriptor {
            owner: owner.clone(),
            control: 0x8004,
            dacl: Some(Vec::new()),
        };
        assert!(!open.dacl_protected());
        let protected = Descriptor {
            owner,
            control: 0x9004,
            dacl: None,
        };
        assert!(protected.dacl_protected());
    }
}
