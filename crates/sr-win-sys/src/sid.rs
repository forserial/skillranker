//! Security identifiers, parsed from their binary form in safe code.
#![forbid(unsafe_code)]

use std::fmt;

/// The most sub-authorities a SID may carry (`SID_MAX_SUB_AUTHORITIES`).
pub const MAX_SUB_AUTHORITIES: usize = 15;

/// An owned security identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sid {
    authority: u64,
    sub_authorities: Vec<u32>,
}

/// Why bytes are not a SID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SidError {
    Truncated,
    Revision(u8),
    TooManySubAuthorities(u8),
}

impl fmt::Display for SidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("SID bytes are truncated"),
            Self::Revision(revision) => write!(f, "SID revision {revision} is not 1"),
            Self::TooManySubAuthorities(count) => {
                write!(f, "SID has {count} sub-authorities, more than 15")
            }
        }
    }
}

impl std::error::Error for SidError {}

const NT_AUTHORITY: u64 = 5;
const APP_PACKAGE_AUTHORITY: u64 = 15;

impl Sid {
    /// Builds a SID from its identifier authority and sub-authorities.
    pub fn new(authority: u64, sub_authorities: &[u32]) -> Option<Self> {
        (authority < 1 << 48 && sub_authorities.len() <= MAX_SUB_AUTHORITIES).then(|| Self {
            authority,
            sub_authorities: sub_authorities.to_vec(),
        })
    }

    /// Parses a SID at the start of `bytes` and returns it with the number of
    /// bytes it occupies (`8 + 4 * sub-authority count`).
    pub fn parse_prefix(bytes: &[u8]) -> Result<(Self, usize), SidError> {
        let [revision, count, rest @ ..] = bytes else {
            return Err(SidError::Truncated);
        };
        if *revision != 1 {
            return Err(SidError::Revision(*revision));
        }
        if usize::from(*count) > MAX_SUB_AUTHORITIES {
            return Err(SidError::TooManySubAuthorities(*count));
        }
        let length = 8 + 4 * usize::from(*count);
        if bytes.len() < length {
            return Err(SidError::Truncated);
        }
        let authority = rest[..6]
            .iter()
            .fold(0u64, |value, byte| value << 8 | u64::from(*byte));
        let (words, _) = bytes[8..length].as_chunks::<4>();
        let sub_authorities = words.iter().map(|word| u32::from_le_bytes(*word)).collect();
        Ok((
            Self {
                authority,
                sub_authorities,
            },
            length,
        ))
    }

    /// Parses bytes that hold exactly one SID.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SidError> {
        match Self::parse_prefix(bytes)? {
            (sid, length) if length == bytes.len() => Ok(sid),
            _ => Err(SidError::Truncated),
        }
    }

    /// The binary form, as Windows stores it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![1, self.sub_authorities.len() as u8];
        bytes.extend_from_slice(&self.authority.to_be_bytes()[2..]);
        for sub in &self.sub_authorities {
            bytes.extend_from_slice(&sub.to_le_bytes());
        }
        bytes
    }

    pub fn authority(&self) -> u64 {
        self.authority
    }

    pub fn sub_authorities(&self) -> &[u32] {
        &self.sub_authorities
    }

    fn is(&self, authority: u64, subs: &[u32]) -> bool {
        self.authority == authority && self.sub_authorities == subs
    }

    /// `S-1-5-18`, LocalSystem.
    pub fn is_local_system(&self) -> bool {
        self.is(NT_AUTHORITY, &[18])
    }

    /// `S-1-5-32-544`, BUILTIN\Administrators.
    pub fn is_builtin_administrators(&self) -> bool {
        self.is(NT_AUTHORITY, &[32, 544])
    }

    /// `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`,
    /// NT SERVICE\TrustedInstaller.
    pub fn is_trusted_installer(&self) -> bool {
        self.is(
            NT_AUTHORITY,
            &[
                80,
                956_008_885,
                3_418_522_649,
                1_831_038_044,
                1_853_292_631,
                2_271_478_464,
            ],
        )
    }

    /// `S-1-15-3-…`, an AppContainer capability.
    pub fn is_capability(&self) -> bool {
        self.authority == APP_PACKAGE_AUTHORITY && self.sub_authorities.first() == Some(&3)
    }
}

impl fmt::Display for Sid {
    /// The string form `ConvertSidToStringSidW` produces: decimal authority
    /// below 2^32, otherwise `0x` and twelve hex digits.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.authority < 1 << 32 {
            write!(f, "S-1-{}", self.authority)?;
        } else {
            write!(f, "S-1-0x{:012X}", self.authority)?;
        }
        for sub in &self.sub_authorities {
            write!(f, "-{sub}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system_bytes() -> Vec<u8> {
        vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
    }

    #[test]
    fn parses_and_formats_well_known_sids() {
        let system = Sid::from_bytes(&system_bytes()).unwrap();
        assert_eq!(system.to_string(), "S-1-5-18");
        assert!(system.is_local_system());
        assert_eq!(system.to_bytes(), system_bytes());

        let admins = Sid::new(5, &[32, 544]).unwrap();
        assert_eq!(admins.to_string(), "S-1-5-32-544");
        assert!(admins.is_builtin_administrators());
        assert_eq!(Sid::from_bytes(&admins.to_bytes()).unwrap(), admins);

        let installer = Sid::new(
            5,
            &[
                80,
                956_008_885,
                3_418_522_649,
                1_831_038_044,
                1_853_292_631,
                2_271_478_464,
            ],
        )
        .unwrap();
        assert!(installer.is_trusted_installer());
        assert!(!installer.is_local_system());

        let capability = Sid::new(15, &[3, 1024, 7]).unwrap();
        assert!(capability.is_capability());
        assert!(!Sid::new(15, &[2, 1]).unwrap().is_capability());
    }

    #[test]
    fn large_authorities_format_in_hex() {
        let sid = Sid::new(0x0000_1234_5678_9ABC, &[1]).unwrap();
        assert_eq!(sid.to_string(), "S-1-0x123456789ABC-1");
        assert_eq!(Sid::from_bytes(&sid.to_bytes()).unwrap(), sid);
        assert!(Sid::new(1 << 48, &[]).is_none());
        assert!(Sid::new(5, &[0; 16]).is_none());
    }

    #[test]
    fn malformed_bytes_are_refused() {
        assert_eq!(Sid::from_bytes(&[]), Err(SidError::Truncated));
        assert_eq!(Sid::from_bytes(&[1]), Err(SidError::Truncated));
        let mut bytes = system_bytes();
        bytes[0] = 2;
        assert_eq!(Sid::from_bytes(&bytes), Err(SidError::Revision(2)));
        let mut bytes = system_bytes();
        bytes[1] = 16;
        assert_eq!(
            Sid::from_bytes(&bytes),
            Err(SidError::TooManySubAuthorities(16))
        );
        let mut bytes = system_bytes();
        bytes[1] = 2;
        assert_eq!(Sid::from_bytes(&bytes), Err(SidError::Truncated));
        let mut bytes = system_bytes();
        bytes.push(0);
        assert_eq!(Sid::from_bytes(&bytes), Err(SidError::Truncated));
        assert_eq!(Sid::parse_prefix(&bytes).unwrap().1, 12);
    }
}
