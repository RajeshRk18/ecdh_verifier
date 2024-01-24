use dep::noir_bigint_curves::ed25519::{ed25519, Ed25519};
use dep::noir_bigint_curves::ed25519::fp::PrimeField as Fp;
use dep::noir_bigint_curves::ed25519::fq::PrimeField as Fq;
use dep::noir_bigint_curves::ed25519::tecurve::{Point, Curve};
use dep::noir_biguint::BigUint56;

pub fn verify_ecdh(
    secret_key: [u8; 32],
    shared_key: ([u8; 32], [u8; 32]),
    pub_key: ([u8; 32], [u8; 32])
) -> bool {
    let Ed25519 { curve, cofactor } = ed25519();

    let secret_key: [u8] = secret_key;

    let pub_key_point = create_affine_point_from_bytes(pub_key.0, pub_key.1);
    let shared_key_point = create_affine_point_from_bytes(shared_key.0, shared_key.1);

    // membership check
    assert(is_point_valid(curve, pub_key_point));
    assert(is_point_valid(curve, shared_key_point));

    // range check implicitly performed here
    let secret_key = Fq::from_bytes(secret_key);

    let computed_shared_key_point = scalar_mul(curve, secret_key, pub_key_point);

    computed_shared_key_point.eq(shared_key_point)
}

fn is_point_valid(curve: Curve, point: Point) -> bool {
    curve.contains(point)
}

fn scalar_mul(curve: Curve, scalar: Fq, point: Point) -> Point {
    curve.mul(scalar, point)
}

fn create_affine_point_from_bytes(x: [u8; 32], y: [u8; 32]) -> Point {
    let x: [u8] = x;
    let y: [u8] = y;

    Point::from_affine(Fp::from_bytes(x), Fp::from_bytes(y))
}
