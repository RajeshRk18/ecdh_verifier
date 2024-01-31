mod ed25519;
mod secp256k1;
use crate::ed25519::{verify_ecdh, create_point_from_bytes};

#[test]
fn test_ecdh_works() {
    let public_key_x: [u8; 32] = [
        47, 100, 59, 232, 254, 161, 240, 156, 233, 143, 42, 9, 39, 195, 198, 125, 200, 165, 13, 27, 255, 19, 12, 104, 53, 29, 241, 107, 144, 145, 226, 81
    ];
    let public_key_y: [u8; 32] = [
        252, 153, 143, 11, 254, 159, 5, 44, 238, 235, 124, 218, 62, 41, 75, 15, 159, 133, 154, 122, 131, 25, 145, 7, 238, 39, 87, 115, 89, 198, 137, 98
    ];

    let pub_key_point = create_point_from_bytes(public_key_x, public_key_y);

    let secret_key: [u8; 32] = [
        21, 49, 109, 170, 194, 92, 80, 44, 139, 132, 17, 87, 22, 85, 67, 34, 167, 113, 232, 139, 52, 33, 64, 1, 151, 205, 182, 138, 31, 4, 38, 13
    ];

    let shared_key_x: [u8; 32] = [
        98, 48, 248, 130, 229, 224, 88, 25, 149, 88, 97, 117, 221, 222, 76, 94, 133, 194, 231, 56, 139, 250, 91, 248, 100, 17, 242, 251, 250, 52, 14, 78
    ];
    let shared_key_y: [u8; 32] = [
        193, 215, 255, 93, 148, 64, 81, 240, 245, 106, 69, 21, 193, 246, 220, 135, 73, 28, 50, 32, 49, 87, 245, 232, 88, 167, 63, 119, 7, 151, 229, 14
    ];

    let shared_key_point = create_point_from_bytes(shared_key_x, shared_key_y);

    assert(verify_ecdh(secret_key, shared_key_point, pub_key_point));
}
