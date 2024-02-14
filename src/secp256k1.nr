use dep::curves::ecdsa_secp256k1::{secp256k1, Secp256k1};
use dep::curves::ecdsa_secp256k1::fp::PrimeField as Fp;
use dep::curves::ecdsa_secp256k1::fq::PrimeField as Fq;
use dep::curves::ecdsa_secp256k1::swcurve::{Point, Curve};
use dep::bigint::BigUint56;

pub fn verify_ecdh(secret_key: [u8; 32], shared_key: Point, pub_key: Point) -> bool {
    let Secp256k1 { curve } = secp256k1();

    // membership check
    assert(is_point_valid(curve, pub_key));
    assert(is_point_valid(curve, shared_key));

    // range check implicitly performed here
    let secret_key = Fq::from_bytes(secret_key.as_slice());

    // shared key is computed by multiplying secret key with counter party's public key
    let computed_shared_key_point = scalar_mul(curve, secret_key, pub_key);

    computed_shared_key_point.eq(shared_key)
}

fn is_point_valid(curve: Curve, point: Point) -> bool {
    curve.contains(point)
}

// curve mul api expects Fq as scalar. Should be changed to Fp.
fn scalar_mul(curve: Curve, scalar: Fq, point: Point) -> Point {
    curve.mul(scalar, point)
}

pub fn create_affine_point_from_bytes(x: [u8; 32], y: [u8; 32]) -> Point {
    Point::from_affine(Fp::from_bytes(x.as_slice()), Fp::from_bytes(y.as_slice()))
}
