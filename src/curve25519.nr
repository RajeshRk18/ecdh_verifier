use dep::curves::ed25519::{ed25519, Ed25519};
use dep::curves::ed25519::fp::PrimeField as Fp;
use dep::curves::ed25519::tecurve::{Point, Curve};
use dep::bigint::BigUint56;
use crate::test_utils;

pub fn verify_ecdh(
    secret_key: [u8; 32],
    shared_key: [u8; 32],
    sign_shared: u8,
    pub_key: [u8; 32],
    sign_pub: u8
) -> bool {
    let Ed25519 { curve, cofactor: _cof } = ed25519();

    let mut assertion = false;

    // range check implicitly performed here
    let secret_key = Fp::from_bytes(secret_key.as_slice());

    // converting secret to bits representation to use in `bit_mul`
    let sec_key_bits = secret_key.to_bits();

    // montgomery -> edwards
    let pub_edw = montgomery_to_edwards(pub_key, sign_pub);
    let shared_edw = montgomery_to_edwards(shared_key, sign_shared);

    // `pub_edw` and `shared_edw` are safely unwrapped within this if statement.
    // Thus, panic is not possible. 
    if pub_edw.is_some() & shared_edw.is_some() {
        // scalar multiplication: s*P
        let computed_shared_key_point = curve.bit_mul(sec_key_bits, pub_edw.unwrap());

        // storing the assertion
        assertion = computed_shared_key_point.eq(shared_edw.unwrap());
    }

    assertion
}

// f: Mont(u) -> Edwards(X, Y, Z, T)
fn montgomery_to_edwards(point: [u8; 32], sign: u8) -> Option<Point> {
    let u = Fp::from_bytes(point.as_slice());
    let minus_one = minus_one();
    let mut res: Option<Point> = Option::none();
    if !u.eq(minus_one) {
        let u_minus_one = u.sub(Fp::one());
        let u_plus_one_invert = u.add(Fp::one()).invert();

        let y = u_minus_one.mul(u_plus_one_invert);

        let mut y_bytes = to_bytes32(y.to_bytes());
        y_bytes[31] ^= sign << 7;

        let y = Fp::from_bytes(y_bytes.as_slice());

        res = decompress_y(y);
    }

    res
}

// compresses the point and produce Y coordinate
// f: Edwards(X, Y, Z, T) -> Comp Edwards(Y)
pub(crate) fn compress(point: Point) -> Fp {
    let z_invert = point.z.invert();
    let x = point.x.mul(z_invert);
    let y = point.y.mul(z_invert);

    let mut s = to_bytes32(y.to_bytes());

    s[31] ^= is_negative(x) as u8 << 7;

    Fp::from_bytes(s.as_slice())
}

// decompresses the y coordinate and produces Edwards point.
// f: Comp Edwards(y) -> Edwards(X, Y, Z, T)
pub(crate) fn decompress_y(y: Fp) -> Option<Point> {
    let Ed25519 { curve, cofactor: _cof } = ed25519();

    let yy = y.square(); // y^2
    let z = Fp::one(); // z

    let u = yy.sub(z); // y^2 - 1
    let v = (yy.mul(curve.d)).add(z); // d * y^2 + 1

    let out = sqrt_ratio(u, v);

    let is_y_valid_coordinate = out.0;
    let mut x = out.1;

    let mut res: Option<Point> = Option::none();
    if is_y_valid_coordinate {
        let compressed_sign_bit = (to_bytes32(y.to_bytes())[31] >> 7) as bool;

        if compressed_sign_bit {
            x = x.neg();
        }

        res = Option::some(Point {
            x: x,
            y: y,
            z: z,
            t: x.mul(y)
        });
    }

    res
}

// computes sqrt(u/v)

// Returns
//
// - (true, sqrt(u/v))   if `v` is nonzero and `u/v` is square
// - (true, zero)   if `u` is zero
// - (false, zero)   if `v` is zero and `u` is nonzero
fn sqrt_ratio(u: Fp, v: Fp) -> (bool, Fp) {
    // having this as bigint to use in pow fn.
    // No need to range check as the value is 2^253 -3
    let two_253_minus_3 = BigUint56::from_bytes(
        [
        253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 31
    ]
    );
    let sqrt_m1 = sqrt_minus_one(); // sqrt(-1)
    let v3 = v.square().mul(v); // v^3
    let v7 = v3.square().mul(v); // v^7

    let uv3 = u.mul(v3); // u * v^3
    let uv7 = u.mul(v7); // u * v^7

    let mut r = uv3.mul(uv7.pow(two_253_minus_3)); // uv^3 * (uv^7)^(2^253) -3 
    let check = v.mul(r.square()); // v * r^2

    let correct_sign_sqrt = check.eq(u);
    let flipped_sign_sqrt = check.eq(u.neg());
    let flipped_sign_sqrt_i = check.eq(u.neg().mul(sqrt_m1));

    let r_prime = sqrt_m1.mul(r); // sqrt(-1) * r

    if flipped_sign_sqrt | flipped_sign_sqrt_i {
        r = r_prime;
    }

    let r_is_neg = is_negative(r);

    if r_is_neg {
        r = r.neg();
    }

    let was_nonzero_square = correct_sign_sqrt | flipped_sign_sqrt;
    (was_nonzero_square, r)
}

// checks whether the coordinate is negative
pub fn is_negative(fp: Fp) -> bool {
    let bytes = to_bytes32(fp.to_bytes());

    let is_neg = bytes[0] & 1;

    is_neg as bool
}

// sqrt(-1)
pub fn sqrt_minus_one() -> Fp {
    let bytes = [
        176, 160, 14, 74, 39, 27, 238, 196, 120, 228, 47, 173, 6, 24, 67, 47, 167, 215, 251, 61, 153, 0, 77, 43, 11, 223, 193, 79, 128, 36, 131, 43
    ];

    Fp::from_bytes(bytes)
}

// -1
fn minus_one() -> Fp {
    Fp::from_bytes(
        [
        236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127
    ]
    )
}

// to_bytes output `[u8; 32]`. As the curve25519 field element is atmost 255 bits,
// we can safely drop the last 3 registers. 
pub(crate) fn to_bytes32<N>(bytes: [u8; N]) -> [u8; 32] {
    let mut byt32: [u8; 32] = [0; 32];

    for i in 0..32 {
        byt32[i] = bytes[i];
    }

    byt32
}

#[test]
fn test_to_bytes32() {
    let bytes: [u8; 32] = [
        0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d, 0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8,
        0x26, 0x4d, 0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1, 0x58, 0x9e, 0x7b, 0x7f,
        0x23, 0x76, 0xef, 0x09
    ];

    let f = Fp::from_bytes(bytes.as_slice());

    let to_bytes32 = to_bytes32(f.to_bytes());

    assert(bytes == to_bytes32);
}

#[test]
fn test_decomp_comp() {
    let bp = decompress_y(test_utils::base_y_coordinate()).unwrap();

    // Check that decompression actually gives the correct X coordinate
    assert(test_utils::base_x_coordinate().eq(bp.x));
    assert(compress(bp).eq(test_utils::base_y_coordinate()));
}

#[test]
fn test_decomp_sign_handling() {
    // Manually set the high bit of the last byte to flip the sign
    let bp = test_utils::ed25519_basepoint();

    let mut minus_basepoint_bytes = to_bytes32(test_utils::base_y_coordinate().to_bytes());
    minus_basepoint_bytes[31] |= 1 << 7;
    let minus_basepoint = decompress_y(Fp::from_bytes(minus_basepoint_bytes.as_slice())).unwrap();

    assert(minus_basepoint.x.eq(bp.x.neg()));
    assert(minus_basepoint.y.eq(bp.y));
    assert(minus_basepoint.z.eq(bp.z));
    assert(minus_basepoint.t.eq(bp.t.neg()));
}

#[test]
fn basepoint_plus_basepoint_vs_basepoint2() {
    let Ed25519 { curve, cofactor: _cof } = ed25519();
    let bp = test_utils::ed25519_basepoint();
    let bp_added = curve.double(bp);
    assert(compress(bp_added).eq(test_utils::base2_compressed()));
}

