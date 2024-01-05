use dep::noir_bigint_curves::ecdsa_secp256k1::{secp256k1, Secp256k1};
use dep::noir_bigint_curves::ecdsa_secp256k1::fp::PrimeField as Fp;
use dep::noir_bigint_curves::ecdsa_secp256k1::fq::PrimeField as Fq;
use dep::noir_bigint_curves::ecdsa_secp256k1::swcurve::Point;
use dep::noir_biguint::BigUint56;

fn verify_ecdh_decrypt(secret_key: [u8; 32], shared_key: ([u8; 32], [u8; 32]), pub_key: ([u8; 32], [u8; 32])) -> bool{
    let Secp256k1 { curve } = secp256k1();

    let secret_key: [u8] = secret_key;
    let pub_x: [u8] = pub_key.0;
    let pub_y: [u8] = pub_key.1;
    let shared_x: [u8] = shared_key.0;
    let shared_y: [u8] = shared_key.1;

    let pub_x = Fp::from_bytes(pub_x);
    let pub_y = Fp::from_bytes(pub_y);
    let shared_x = Fp::from_bytes(shared_x);
    let shared_y = Fp::from_bytes(shared_y);

    let pub_key_point = Point::from_affine(pub_x, pub_y);
    let shared_key_point = Point::from_affine(shared_x, shared_y);

    // membership check
    assert(curve.contains(pub_key_point));
    assert(curve.contains(shared_key_point));

    // range check implicitly performed here
    let secret_key = Fq::from_bytes(secret_key);

    let computed_shared_key_point = curve.mul(secret_key, pub_key_point);

    computed_shared_key_point.eq(shared_key_point)
}
