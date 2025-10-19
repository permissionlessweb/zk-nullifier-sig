use super::*;
use crate::blake3xmd::{Blake3Xmd, DST_BLAKE3};
use k256::{
    elliptic_curve::{
        hash2curve::{ExpandMsgXmd, GroupDigest},
        sec1::ToEncodedPoint,
    },
    ProjectivePoint, Secp256k1,
}; // requires 'getrandom' feature

// Hashes two values to the curve
pub(crate) fn hash_to_curve(
    m: &[u8],
    pk: &ProjectivePoint,
) -> Result<ProjectivePoint, k256::elliptic_curve::Error> {
    Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[[m, &encode_pt(pk)].concat().as_slice()],
        //b"CURVE_XMD:SHA-256_SSWU_RO_",
        &[DST],
    )
}

// Hashes two values to the curve using blake3
pub(crate) fn hash_to_curve_blake3(
    m: &[u8],
    pk: &ProjectivePoint,
) -> Result<ProjectivePoint, k256::elliptic_curve::Error> {
    Secp256k1::hash_from_bytes::<Blake3Xmd>(
        &[[m, &crate::utils::encode_pt(pk)].concat().as_slice()],
        //b"CURVE_XMD:SHA-256_SSWU_RO_",
        &[DST_BLAKE3],
    )
}

/// Encodes the point by compressing it to 33 bytes
pub(crate) fn encode_pt(point: &ProjectivePoint) -> Vec<u8> {
    point.to_encoded_point(true).to_bytes().to_vec()
}
