## About
ECDH Verifier written in Noir. Currently supports Curve25519 and Secp256k1.

### Usage

Nargo.toml
```
[dependencies]
ecdh_verifier = { tag = "v0.1.1", git = "https://github.com/RajeshRk18/ecdh_verifier.git" }
```
---

```rust
// This assumes that the keys are generated using Curve25519.
    use dep::ecdh_verifier::curve25519::verify_ecdh;

    fn main(secret_key: [u8; 32], shared_key: [u8; 32], sign_shared: u8, pub_key: [u8; 32], sign_pub: u8) {

        assert(verify_ecdh(secret_key, shared_key, pub_key));

    }
```

### Note

- As given points(Montgomery) have been converted to Edwards Point, it is expected to give the sign of the points.
- Support for Montgomery operations are currently wip. It is maintained in a separate branch.
- If montgomery native operations are implemented, we can avoid the `sign` parameter.

### Applications

- Every TLS session involves a handshake where the client(user) and the server agree on a shared secret key which can be later used to encrypt/decrypt messages exchanged between them. If an user can prove that he/she is either a client or a server, then the interaction can be authenticated onchain. This can be used for a lot use cases such as anonymous web authentication, access control systems, and so on.

- Assume an ideal communication protocol that is instantiated between person A and person B with the shared secret key. One of the parties can anonymously prove such communication onchain.

## Disclaimer
This is experimental software and is provided on an "as is" and "as available" basis. We do not give any warranties and will not be liable for any losses incurred through any use of this code base.