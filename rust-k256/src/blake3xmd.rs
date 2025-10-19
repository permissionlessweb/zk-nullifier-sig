use std::io::stderr;

use k256::elliptic_curve;
use k256::elliptic_curve::hash2curve::{ExpandMsg, Expander};

pub const DST_BLAKE3: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:BLAKE-3_SSWU_RO_";

#[derive(Clone)]
pub struct Blake3Xmd {
    output: Vec<u8>,
    offset: usize,
}

impl<'a> ExpandMsg<'a> for Blake3Xmd {
    type Expander = Blake3Xmd;

    // defined in: https://www.rfc-editor.org/rfc/rfc9380.html#hashtofield-expand-xmd
    //     expand_message_xmd(msg, DST, len_in_bytes)

    // Parameters:
    // - H, a hash function (see requirements above).
    // - b_in_bytes, b / 8 for b the output size of H in bits.
    //   For example, for b = 256, b_in_bytes = 32.
    // - s_in_bytes, the input block size of H, measured in bytes (see
    //   discussion above). For example, for SHA-256, s_in_bytes = 64.

    // Input:
    // - msg, a byte string.
    // - DST, a byte string of at most 255 bytes.
    //   See below for information on using longer DSTs.
    // - len_in_bytes, the length of the requested output in bytes,
    //   not greater than the lesser of (255 * b_in_bytes) or 2^16-1.

    // Output:
    // - uniform_bytes, a byte string.

    // Steps:
    // 1.  ell = ceil(len_in_bytes / b_in_bytes)
    // 2.  ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
    // 3.  DST_prime = DST || I2OSP(len(DST), 1)
    // 4.  Z_pad = I2OSP(0, s_in_bytes)
    // 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
    // 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
    // 7.  b_0 = H(msg_prime)
    // 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    // 9.  for i in (2, ..., ell):
    // 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
    // 11. uniform_bytes = b_1 || ... || b_ell
    // 12. return substr(uniform_bytes, 0, len_in_bytes)
    fn expand_message(
        msgs: &[&[u8]],
        dsts: &[&[u8]],
        len_in_bytes: usize,
    ) -> Result<Self::Expander, elliptic_curve::Error> {
        // Constants for BLAKE3
        const B_IN_BYTES: usize = 32; // BLAKE3 output size (256 bits)
        const S_IN_BYTES: usize = 64; // BLAKE3 input block size (adjust if different)

        // Step 1: Compute ell
        let ell = (len_in_bytes + B_IN_BYTES - 1) / B_IN_BYTES; // ceil(len_in_bytes / b_in_bytes)

        // Step 2: Validation
        if ell > 255 || len_in_bytes > 65535 || dsts.first().map_or(0, |dst| dst.len()) > 255 {
            return Err(elliptic_curve::Error);
        }

        // Step 3: Build DST_prime = DST || I2OSP(len(DST), 1)
        let dst = dsts.first().copied().unwrap_or(DST_BLAKE3);
        let mut dst_prime = Vec::with_capacity(dst.len() + 1);
        dst_prime.extend_from_slice(dst);
        dst_prime.push(dst.len() as u8); // I2OSP(len(DST), 1)

        // Step 4: Z_pad = I2OSP(0, s_in_bytes)
        let z_pad = vec![0u8; S_IN_BYTES];

        // Step 5: l_i_b_str = I2OSP(len_in_bytes, 2)
        let l_i_b_str = (len_in_bytes as u16).to_be_bytes(); // 2-byte encoding

        // Step 6: msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
        let mut msg_prime = Vec::new();
        msg_prime.extend_from_slice(&z_pad);
        for msg in msgs {
            msg_prime.extend_from_slice(msg);
        }
        msg_prime.extend_from_slice(&l_i_b_str);
        msg_prime.push(0); // I2OSP(0, 1)
        msg_prime.extend_from_slice(&dst_prime);

        // Steps 7–11: Iterative hashing
        let mut uniform_bytes = Vec::new();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&msg_prime);
        let mut b_0 = [0u8; B_IN_BYTES];
        hasher.finalize_xof().fill(&mut b_0);

        let mut b_i = b_0;
        for i in 1..=ell {
            let mut hasher = blake3::Hasher::new();
            let xor_result: Vec<u8> = b_0.iter().zip(b_i.iter()).map(|(&x, &y)| x ^ y).collect();
            hasher.update(&xor_result);
            hasher.update(&[i as u8]); // I2OSP(i, 1)
            hasher.update(&dst_prime);
            b_i = [0u8; B_IN_BYTES];
            hasher.finalize_xof().fill(&mut b_i);
            uniform_bytes.extend_from_slice(&b_i);
        }

        // Step 12: Truncate to len_in_bytes
        Ok(Blake3Xmd {
            output: uniform_bytes[..len_in_bytes].to_vec(),
            offset: 0,
        })
    }
}

impl Expander for Blake3Xmd {
    fn fill_bytes(&mut self, okm: &mut [u8]) {
        let end = self.offset + okm.len();
        okm.copy_from_slice(&self.output[self.offset..end]);
        self.offset = end;
    }
}
