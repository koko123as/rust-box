//! Just enough DER to find a certificate's SubjectPublicKeyInfo (what Go's
//! `x509.MarshalPKIXPublicKey` returns for the leaf's public key).

/// One TLV split off its input: (tag, whole element, content, rest).
type Element<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// Splits one TLV off `input`.
fn element(input: &[u8]) -> Option<Element<'_>> {
    let tag = *input.first()?;
    let first = *input.get(1)? as usize;
    let (length, header) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for byte in input.get(2..2 + count)? {
            length = (length << 8) | *byte as usize;
        }
        (length, 2 + count)
    };
    let end = header.checked_add(length)?;
    let whole = input.get(..end)?;
    Some((tag, whole, &whole[header..], &input[end..]))
}

const SEQUENCE: u8 = 0x30;

/// The DER SubjectPublicKeyInfo of a certificate.
pub fn subject_public_key_info(certificate: &[u8]) -> Option<&[u8]> {
    let (tag, _, certificate, _) = element(certificate)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, _, tbs, _) = element(certificate)?;
    if tag != SEQUENCE {
        return None;
    }
    let mut rest = tbs;
    // [0] EXPLICIT version, optional.
    if rest.first() == Some(&0xa0) {
        rest = element(rest)?.3;
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        rest = element(rest)?.3;
    }
    let (tag, spki, _, _) = element(rest)?;
    (tag == SEQUENCE).then_some(spki)
}
