use dep::curves::ed25519::{ed25519, Ed25519};
use dep::curves::ed25519::fp::PrimeField as Fp;
use dep::curves::ed25519::fq::PrimeField as Fq;
use dep::curves::ed25519::tecurve::{Point, Curve};
use dep::bigint::BigUint56;

pub fn verify_ecdh(secret_key: [u8; 32], shared_key: Point, pub_key: Point) -> bool {
    let Ed25519 { curve, cofactor } = ed25519();

    // membership check
    assert(is_point_valid(curve, pub_key));
    assert(is_point_valid(curve, shared_key));

    let secret_key: [u8] = secret_key;

    // range check implicitly performed here
    let secret_key = Fq::from_bytes(secret_key);
    let computed_shared_key_point = scalar_mul(curve, secret_key, pub_key);

    computed_shared_key_point.println();
    computed_shared_key_point.eq(shared_key)
}

fn is_point_valid(curve: Curve, point: Point) -> bool {
    curve.contains(point)
}

// curve mul api expects Fq as scalar. Should be changed to Fp.
fn scalar_mul(curve: Curve, scalar: Fq, point: Point) -> Point {
    curve.mul(scalar, point)
}

pub fn create_point_from_bytes(x: [u8; 32], y: [u8; 32]) -> Point {
    let x: [u8] = x;
    let y: [u8] = y;

    Point::from_affine(Fp::from_bytes(x), Fp::from_bytes(y))
}

