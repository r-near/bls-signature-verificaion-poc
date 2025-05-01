use amcl::bls381::bls381::utils::serialize_uncompressed_g1;
use amcl::bls381::ecp::ECP;
use amcl::bls381::fp2::FP2;
use amcl::bls381::hash_to_curve::hash_to_field_fp2;
use near_sdk::near;

#[near(contract_state)]
#[derive(Default)]
pub struct BLSVerificationPOC {}

#[near]
impl BLSVerificationPOC {
    // WARNING: Before using this function, you must ensure the correctness of the public keys.
    // If the proof of possession (https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession)
    // has not been verified, a Rogue Key Attack may be applied.
    /// Verifies a BLS signature against aggregated public keys.
    /// Uses BLS12-381 curve with Ethereum's signature scheme.
    pub fn verify_bls_signature(msg: Vec<u8>, signature: Vec<u8>, pubkeys: Vec<Vec<u8>>) -> bool {
        // 1. HASH MESSAGE TO G2 POINT
        let hashed_msg_point = Self::hash_message_to_g2_point(msg);

        // 2. AGGREGATE PUBLIC KEYS
        let aggregated_pubkey = Self::aggregate_public_keys(pubkeys);

        // 3. GET NEGATED GENERATOR POINT
        let mut generator = ECP::generator();
        generator.neg();
        let negated_generator = serialize_uncompressed_g1(&generator);

        // 4. DECOMPRESS SIGNATURE
        let signature_decompressed = near_sdk::env::bls12381_p2_decompress(&signature);

        // 5. PERFORM PAIRING CHECK: e(PK, H(m)) * e(-G, S) == 1
        let pairing_input = [
            aggregated_pubkey,
            hashed_msg_point,
            negated_generator.to_vec(),
            signature_decompressed,
        ]
        .concat();

        near_sdk::env::bls12381_pairing_check(&pairing_input)
    }

    /// Hashes a message to a point on the G2 curve using Ethereum's BLS scheme
    fn hash_message_to_g2_point(msg: Vec<u8>) -> Vec<u8> {
        // Ethereum domain separation tag
        let dst: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

        // 1. Hash message to two field elements
        let msg_fp2 = hash_to_field_fp2(msg.as_slice(), 2, dst)
            .expect("hash to field should not fail for given parameters");

        // 2. Convert field elements to bytes format for NEAR runtime
        let mut msg_fp2_0: [u8; 96] = [0; 96];
        let mut msg_fp2_1: [u8; 96] = [0; 96];
        Self::fp2_to_u8(&msg_fp2[0], &mut msg_fp2_0);
        Self::fp2_to_u8(&msg_fp2[1], &mut msg_fp2_1);

        // 3. Map field elements to G2 points
        let msg_g2_0 = near_sdk::env::bls12381_map_fp2_to_g2(&msg_fp2_0);
        let msg_g2_1 = near_sdk::env::bls12381_map_fp2_to_g2(&msg_fp2_1);

        // 4. Sum the G2 points with sign bits
        let mut msg_g2_points = Vec::with_capacity(1 + msg_g2_0.len() + 1 + msg_g2_1.len());
        msg_g2_points.push(0); // Sign bit (positive)
        msg_g2_points.extend_from_slice(&msg_g2_0);
        msg_g2_points.push(0); // Sign bit (positive)
        msg_g2_points.extend_from_slice(&msg_g2_1);

        near_sdk::env::bls12381_p2_sum(&msg_g2_points)
    }

    /// Aggregates multiple public keys into a single public key
    fn aggregate_public_keys(pubkeys: Vec<Vec<u8>>) -> Vec<u8> {
        // 1. Concatenate all compressed public keys
        let pubkeys_serialized: Vec<u8> = pubkeys.concat();

        // 2. Decompress all public keys
        let pks_decompressed = near_sdk::env::bls12381_p1_decompress(&pubkeys_serialized);

        // 3. Prepare public keys with sign bits for summation
        let mut pks_with_sign =
            Vec::with_capacity(pks_decompressed.len() + pks_decompressed.len() / 96);
        for i in 0..pks_decompressed.len() / 96 {
            pks_with_sign.push(0); // Sign bit (positive)
            pks_with_sign.extend_from_slice(&pks_decompressed[i * 96..(i + 1) * 96]);
        }

        // 4. Sum all public keys to get the aggregated key
        near_sdk::env::bls12381_p1_sum(&pks_with_sign)
    }

    /// Converts an FP2 element to bytes in the format expected by NEAR runtime
    fn fp2_to_u8(u: &FP2, out: &mut [u8; 96]) {
        // FP2 element consists of two FP elements (a, b)
        // Write b first, then a (format expected by NEAR)
        u.getb().to_byte_array(&mut out[0..48], 0);
        u.geta().to_byte_array(&mut out[48..96], 0);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use bitvec::order::Lsb0;
    use bitvec::prelude::BitVec;
    use eth2_utility::consensus::compute_domain;
    use eth2_utility::consensus::compute_signing_root;
    use eth2_utility::consensus::DOMAIN_SYNC_COMMITTEE;
    use eth2_utility::consensus::{Network, NetworkConfig};
    use eth_types::eth2::{LightClientUpdate, PublicKeyBytes, SyncCommittee};
    use near_workspaces::{Account, Contract};
    use serde_json::json;
    use std::str::FromStr;
    use tree_hash::TreeHash;

    const WASM_FILEPATH: &str = "./target/wasm32-unknown-unknown/release/bls_verification_poc.wasm";

    #[macro_export]
    macro_rules! call {
        ($contract:ident, $method_name:literal) => {
            call_arg(&$contract, $method_name, &json!({}))
        };
        ($contract:ident, $method_name:literal, $args:expr) => {
            call_arg(&$contract, $method_name, $args)
        };
        ($account:expr, $contract:ident, $method_name:literal) => {
            call_by_with_arg($account, &$contract, $method_name, &json!({}))
        };
        ($account:expr, $contract:ident, $method_name:literal, $args:expr) => {
            call_by_with_arg($account, &$contract, $method_name, $args)
        };
    }

    #[tokio::test]
    async fn test_verify_bls_signature() {
        let wasm = near_workspaces::compile_project(".").await.unwrap();

        let worker = near_workspaces::sandbox().await.unwrap();
        let contract = worker.dev_deploy(&wasm).await.unwrap();

        let config = get_config();
        let light_client_updates: Vec<LightClientUpdate> = serde_json::from_str(
            &std::fs::read_to_string(config.path_to_light_client_updates)
                .expect("Unable to read file"),
        )
        .unwrap();
        let current_sync_committee: SyncCommittee = serde_json::from_str(
            &std::fs::read_to_string(config.path_to_current_sync_committee.clone())
                .expect("Unable to read file"),
        )
        .unwrap();
        let next_sync_committee: SyncCommittee = serde_json::from_str(
            &std::fs::read_to_string(config.path_to_next_sync_committee.clone())
                .expect("Unable to read file"),
        )
        .unwrap();

        let sync_committee_bits = BitVec::<u8, Lsb0>::from_slice(
            &light_client_updates[0].sync_aggregate.sync_committee_bits.0,
        );

        let participant_pubkeys =
            get_participant_pubkeys(&current_sync_committee.pubkeys.0, &sync_committee_bits);

        let mut pubks: Vec<Vec<u8>> = vec![];
        for pk in participant_pubkeys {
            pubks.push(pk.0.to_vec());
        }

        let ethereum_network = Network::from_str("goerli").unwrap();
        let network_config = NetworkConfig::new(&ethereum_network);

        let fork_version = network_config
            .compute_fork_version_by_slot(light_client_updates[0].signature_slot)
            .expect("Unsupported fork");

        let domain = compute_domain(
            DOMAIN_SYNC_COMMITTEE,
            fork_version,
            network_config.genesis_validators_root.into(),
        );

        let signing_root = compute_signing_root(
            eth_types::H256(
                light_client_updates[0]
                    .attested_beacon_header
                    .tree_hash_root(),
            ),
            domain,
        );

        let res = contract.call("verify_bls_signature").args_json(json!({"msg": signing_root.0.as_bytes(), "signature": light_client_updates[0].sync_aggregate.sync_committee_signature.0.to_vec(), "pubkeys": pubks})).max_gas().transact().await.unwrap();
        assert_eq!(res.clone().unwrap().json::<bool>().unwrap(), true);

        println!("Gas consumption: {:?}", res.unwrap().total_gas_burnt);

        pubks.pop();
        let res_false = contract.call("verify_bls_signature").args_json(json!({"msg": signing_root.0.as_bytes(), "signature": light_client_updates[0].sync_aggregate.sync_committee_signature.0.to_vec(), "pubkeys": pubks})).max_gas().transact().await.unwrap();
        assert_eq!(res_false.unwrap().json::<bool>().unwrap(), false);
    }

    #[derive(Debug, Clone)]
    pub struct ConfigForTests {
        pub path_to_current_sync_committee: String,
        pub path_to_next_sync_committee: String,
        pub path_to_light_client_updates: String,
        pub network_name: String,
    }

    fn get_config() -> ConfigForTests {
        ConfigForTests {
            path_to_current_sync_committee: "./data/next_sync_committee_goerli_period_473.json"
                .to_string(),
            path_to_next_sync_committee: "./data/next_sync_committee_goerli_period_474.json"
                .to_string(),
            path_to_light_client_updates:
                "./data/light_client_updates_goerli_slots_3885697_3886176.json".to_string(),
            network_name: "goerli".to_string(),
        }
    }

    pub async fn get_contract(wasm_path: &str) -> (Account, Contract) {
        let worker = near_workspaces::sandbox().await.unwrap();

        let owner = worker.root_account().unwrap();

        let wasm = std::fs::read(wasm_path).unwrap();
        let contract = owner.deploy(&wasm).await.unwrap().unwrap();

        (owner, contract)
    }

    pub async fn call_arg(
        contract: &Contract,
        method_name: &str,
        args: &serde_json::Value,
    ) -> bool {
        let res = contract
            .call(method_name)
            .args_json(args)
            .max_gas()
            .transact()
            .await
            .unwrap();

        res.is_success()
    }

    pub fn get_participant_pubkeys(
        public_keys: &[PublicKeyBytes],
        sync_committee_bits: &BitVec<u8, Lsb0>,
    ) -> Vec<PublicKeyBytes> {
        let mut result: Vec<PublicKeyBytes> = vec![];
        for (idx, bit) in sync_committee_bits.iter().by_vals().enumerate() {
            if bit {
                result.push(public_keys[idx].clone());
            }
        }

        result
    }
}
