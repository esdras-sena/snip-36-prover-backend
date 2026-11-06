// One-off utility: derive the OZ account address from a private key in an .env file.
//
// Usage:
//   cargo run -p snip36-core --example derive_address -- .env.mainnet

use starknet_rust_crypto::{get_public_key, pedersen_hash, Felt};
use std::env;
use std::fs;
use std::path::Path;

const OZ_ACCOUNT_CLASS_HASH: &str =
    "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";

// Starknet `calculate_contract_address` (deployer = 0, as the OZ account
// deploy-account flow uses): pedersen chain over
// ['STARKNET_CONTRACT_ADDRESS', deployer, salt, class_hash, h(calldata)],
// reduced mod 2^251 - 256.
fn compute_hash_on_elements(data: &[Felt]) -> Felt {
    let h = data.iter().fold(Felt::ZERO, |acc, x| pedersen_hash(&acc, x));
    pedersen_hash(&h, &Felt::from(data.len() as u64))
}

fn get_contract_address(salt: Felt, class_hash: Felt, calldata: &[Felt], deployer: Felt) -> Felt {
    let prefix = Felt::from_bytes_be_slice(b"STARKNET_CONTRACT_ADDRESS");
    let raw = compute_hash_on_elements(&[
        prefix,
        deployer,
        salt,
        class_hash,
        compute_hash_on_elements(calldata),
    ]);
    // ADDR_BOUND = 2^251 - 256
    let bound = Felt::from_hex("0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00").unwrap();
    let (raw_u, bound_u) = (raw.to_biguint(), bound.to_biguint());
    Felt::from(raw_u % bound_u)
}

fn load_private_key(env_path: &Path) -> Option<String> {
    let content = fs::read_to_string(env_path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("STARKNET_PRIVATE_KEY=") {
            return Some(rest.trim().trim_matches('"').trim_matches('\'').to_string());
        }
    }
    None
}

fn main() {
    let arg = env::args().nth(1).unwrap_or_else(|| ".env".to_string());
    let path = Path::new(&arg);
    let priv_hex = load_private_key(path).unwrap_or_else(|| {
        eprintln!("STARKNET_PRIVATE_KEY not found in {}", path.display());
        std::process::exit(1);
    });

    let private_key = Felt::from_hex(&priv_hex).expect("invalid private key hex");
    let pub_core = get_public_key(&private_key);
    let class_hash = Felt::from_hex(OZ_ACCOUNT_CLASS_HASH).unwrap();

    let address = get_contract_address(pub_core, class_hash, &[pub_core], Felt::ZERO);

    println!("public_key:      {pub_core:#066x}");
    println!("account_address: {address:#066x}");
}
