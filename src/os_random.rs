//! The operating system's CSPRNG, for keys, tokens and sampling seeds.

/// Recorded as sampling provenance, so a report names what actually drew its seed.
#[cfg(unix)]
pub(crate) const ENTROPY_SOURCE: &str = "/dev/urandom";
#[cfg(windows)]
pub(crate) const ENTROPY_SOURCE: &str = "ProcessPrng";

#[cfg(unix)]
pub(crate) fn fill(bytes: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    std::fs::File::open(ENTROPY_SOURCE)?.read_exact(bytes)
}

#[cfg(windows)]
pub(crate) fn fill(bytes: &mut [u8]) -> std::io::Result<()> {
    getrandom::fill(bytes).map_err(|error| std::io::Error::other(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_differ_and_fill_every_byte_position() {
        let (mut first, mut second) = ([0_u8; 32], [0_u8; 32]);
        fill(&mut first).unwrap();
        fill(&mut second).unwrap();
        assert_ne!(first, second);
        assert_ne!(first, [0_u8; 32]);
    }
}
