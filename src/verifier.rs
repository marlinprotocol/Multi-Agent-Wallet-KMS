use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

fn main() {
    // Expect: signature hex, sighash hex, optional expected pubkey hex.
    let mut args = std::env::args().skip(1);
    let signature_hex = args.next().expect("missing signature arg");
    let sighash_hex = args.next().expect("missing sighash arg");
    let expected_pubkey_hex = args.next();

    // Each withdraw response gives back a recoverable signature (r||s||v) and the message hash.
    let signature_bytes = hex::decode(strip_hex(&signature_hex)).expect("invalid signature hex");
    assert_eq!(
        signature_bytes.len(),
        65,
        "signature must be 65 bytes (r || s || v)"
    );
    let sighash_bytes = hex::decode(strip_hex(&sighash_hex)).expect("invalid sighash hex");
    assert_eq!(sighash_bytes.len(), 32, "sighash must be 32 bytes");

    // Ethereum returns v in {27,28}; k256 wants 0/1.
    let v = signature_bytes[64];
    let rec_id = if v >= 27 { v - 27 } else { v };
    let recovery_id = RecoveryId::from_byte(rec_id).expect("failed to parse recovery id");
    let signature = Signature::from_slice(&signature_bytes[..64]).expect("failed to parse sig");
    let verifying_key = VerifyingKey::recover_from_prehash(&sighash_bytes, &signature, recovery_id)
        .expect("failed to recover pubkey");
    let pubkey_bytes = verifying_key.to_encoded_point(false);
    let recovered_hex = hex::encode(&pubkey_bytes.as_bytes()[1..]);

    println!("Recovered pubkey: {recovered_hex}");

    // Comparing against the KMS-derived pubkey is optional but recommended.
    if let Some(expected) = expected_pubkey_hex {
        let expected_clean = strip_hex(&expected).to_lowercase();
        if expected_clean == recovered_hex {
            println!("✅ Matches expected KMS public key");
        } else {
            eprintln!("❌ Mismatch: expected {expected_clean}, recovered {recovered_hex}");
            std::process::exit(1);
        }
    }
}

fn strip_hex(value: &str) -> &str {
    value.strip_prefix("0x").unwrap_or(value)
}
