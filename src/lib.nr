mod curve25519;
mod secp256k1;
mod test_utils;

use crate::curve25519::verify_ecdh;

#[test]
fn test_ecdh1() {
    let shared: [u8; 32] = [
        66, 23, 22, 30, 60, 155, 240, 118, 51, 158, 209, 71, 201, 33, 126, 224, 37, 15, 53, 128, 244, 59, 142, 114, 225, 45, 206, 164, 91, 157, 93, 74
    ];

    let peer_pub: [u8; 32] = [
        79, 43, 136, 111, 20, 126, 252, 173, 77, 103, 120, 91, 200, 67, 131, 63, 55, 53, 228, 236, 194, 97, 91, 211, 180, 193, 125, 123, 125, 219, 158, 222
    ];

    let secret: [u8; 32] = [
        42, 44, 185, 29, 165, 251, 119, 177, 42, 153, 192, 235, 135, 47, 76, 223, 69, 102, 178, 81, 114, 193, 22, 60, 125, 165, 24, 115, 10, 109, 7, 119
    ];

    assert(verify_ecdh(secret, shared, 0 as u8, peer_pub, 0 as u8));
}

#[test]
fn test_ecdh2() {
    let shared: [u8; 32] = [
        49, 79, 96, 170, 9, 144, 245, 196, 100, 205, 117, 240, 139, 198, 250, 172, 82, 82, 222, 17, 251, 210, 76, 188, 96, 227, 87, 156, 66, 127, 42, 171
    ];

    let peer_pub: [u8; 32] = [
        116, 59, 203, 88, 95, 153, 144, 237, 194, 207, 196, 175, 132, 246, 255, 48, 7, 41, 187, 95, 172, 218, 40, 21, 67, 98, 205, 71, 163, 125, 229, 47
    ];

    let secret: [u8; 32] = [
        235, 224, 136, 255, 39, 139, 47, 28, 253, 182, 24, 38, 41, 177, 59, 111, 230, 14, 128, 131, 139, 127, 225, 121, 75, 138, 74, 98, 126, 8, 171, 93
    ];

    assert(verify_ecdh(secret, shared, 0 as u8, peer_pub, 0 as u8));
}

#[test]
fn test_ecdh3() {
    let secret: [u8; 32] = [
        107, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 168
    ];

    let peer_pub: [u8; 32] = [
        79, 43, 136, 111, 20, 126, 252, 173, 77, 103, 120, 91, 200, 67, 131, 63, 55, 53, 228, 236, 194, 97, 91, 211, 180, 193, 125, 123, 125, 219, 158, 222
    ];

    let shared: [u8; 32] = [
        25, 187, 189, 60, 141, 188, 189, 55, 201, 156, 56, 50, 6, 225, 178, 132, 137, 227, 60, 206, 148, 96, 246, 6, 215, 221, 148, 153, 240, 151, 163, 2
    ];

    assert(verify_ecdh(secret, shared, 0 as u8, peer_pub, 0 as u8));
}
