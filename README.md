## ECDH Verifier in Noir

### Usage

```rust
// This assumes that the keys are generated using Ed25519 curve
    use dep::ecdh_decryption_verifier::ed25519::verify_ecdh;

    fn main(secret_key: [u8; 32], shared_key: ([u8; 32], [u8; 32]), pub_key: ([u8; 32], [u8; 32])) {

        assert(verify_ecdh(secret_key, shared_key, pub_key));

    }
```

### Applications

- Every TLS session involves a handshake where the client(user) and the server agree on a shared secret key which can be later used to encrypt/decrypt messages exchanged between them. If an user can prove that he/she is either a client or a server, then the interaction can be authenticated onchain. This can be used for a lot use cases such as anonymous web authentication, access control systems, and so on.

- Lets assume an ideal communication protocol that is instantiated between two parties with the shared secret key. One of the parties can anonymously prove such communication onchain.