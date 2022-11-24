#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[derive(Debug, PartialEq)]
pub enum SpongentResult {
    Success = 0,
    Fail = 1,
    BadHashBitLen = 2,
    BadTag = 3,
    Unknown = 4
}

impl std::fmt::Display for SpongentResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>)
        -> Result<(), std::fmt::Error> {
            write!(f, "{:?}", self)
        }
}

impl SpongentResult {
    fn from_u32(value: u32) -> SpongentResult {
        match value {
            0   => SpongentResult::Success,
            1   => SpongentResult::Fail,
            2   => SpongentResult::BadHashBitLen,
            3   => SpongentResult::BadTag,
            _   => SpongentResult::Unknown
        }
    }
}

pub fn spongent_wrap(
    key : &[u8],
    aad : &[u8],
    buf : &[u8],
    cipher : &mut [u8],
    tag : &mut [u8]
) -> SpongentResult {
    unsafe {
        let res = SpongentWrap(
            key.as_ptr(),
            aad.as_ptr(),
            aad.len() as u64 * 8,
            buf.as_ptr(),
            buf.len() as u64 * 8,
            cipher.as_mut_ptr(),
            tag.as_mut_ptr(),
            false
        );

        SpongentResult::from_u32(res)
    }
}

pub fn spongent_unwrap(
    key : &[u8],
    aad : &[u8],
    cipher : &[u8],
    plain : &mut [u8],
    tag : &[u8]
) -> SpongentResult {
    unsafe {
        let res = SpongentUnwrap(
            key.as_ptr(),
            aad.as_ptr(),
            aad.len() as u64 * 8,
            cipher.as_ptr(),
            cipher.len() as u64 * 8,
            plain.as_mut_ptr(),
            tag.as_ptr()
        );

        SpongentResult::from_u32(res)
    }
}

pub fn spongent_mac(
    key : &[u8],
    buf : &[u8],
    tag : &mut [u8]
) -> SpongentResult {
    unsafe {
        let res = SpongentMac(
            key.as_ptr(),
            buf.as_ptr(),
            buf.len() as u64 * 8,
            tag.as_mut_ptr()
        );

        SpongentResult::from_u32(res)
    }
}

#[cfg(test)]
mod tests {
    use super::{spongent_wrap, spongent_unwrap, SpongentResult};

    #[test]
    fn test() {
        let key = b"16-bytes sec key";
        let plaintext = b"Hello world!";
        let mut cipher = vec![0u8; plaintext.len()];
        let mut plain_dec = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        let data = [1u8, 2u8];

        let res = spongent_wrap(&key[..], &data, &plaintext[..], &mut cipher[..], &mut tag[..]);
        assert_eq!(res, SpongentResult::Success);

        let res = spongent_unwrap(&key[..], &data, &cipher[..], &mut plain_dec[..], &tag[..]);
        assert_eq!(res, SpongentResult::Success);

        assert_eq!(&plaintext[..], &plain_dec);
    }
}