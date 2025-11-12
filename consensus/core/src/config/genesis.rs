use crate::{block::Block, header::Header, subnets::SUBNETWORK_ID_COINBASE, tx::Transaction};
use vecno_hashes::{Hash, ZERO_HASH};
use vecno_muhash::EMPTY_MUHASH;

/// The constants uniquely representing the genesis block
#[derive(Clone, Debug)]
pub struct GenesisBlock {
    pub hash: Hash,
    pub version: u16,
    pub hash_merkle_root: Hash,
    pub utxo_commitment: Hash,
    pub timestamp: u64,
    pub bits: u32,
    pub nonce: u64,
    pub daa_score: u64,
    pub coinbase_payload: &'static [u8],
}

impl GenesisBlock {
    pub fn build_genesis_transactions(&self) -> Vec<Transaction> {
        vec![Transaction::new(0, Vec::new(), Vec::new(), 0, SUBNETWORK_ID_COINBASE, 0, self.coinbase_payload.to_vec())]
    }
}

impl From<&GenesisBlock> for Header {
    fn from(genesis: &GenesisBlock) -> Self {
        Header::new_finalized(
            genesis.version,
            Vec::new(),
            genesis.hash_merkle_root,
            ZERO_HASH,
            genesis.utxo_commitment,
            genesis.timestamp,
            genesis.bits,
            genesis.nonce,
            genesis.daa_score,
            0.into(),
            0,
            ZERO_HASH,
        )
    }
}

impl From<&GenesisBlock> for Block {
    fn from(genesis: &GenesisBlock) -> Self {
        Block::new(genesis.into(), genesis.build_genesis_transactions())
    }
}

impl From<(&Header, &'static [u8])> for GenesisBlock {
    fn from((header, payload): (&Header, &'static [u8])) -> Self {
        Self {
            hash: header.hash,
            version: header.version,
            hash_merkle_root: header.hash_merkle_root,
            utxo_commitment: header.utxo_commitment,
            timestamp: header.timestamp,
            bits: header.bits,
            nonce: header.nonce,
            daa_score: header.daa_score,
            coinbase_payload: payload,
        }
    }
}

/// The genesis block of the block-DAG which serves as the public transaction ledger for the main network.
pub const GENESIS: GenesisBlock = GenesisBlock {
    hash: Hash::from_bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    ]),
    version: 0,
    hash_merkle_root: Hash::from_bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    ]),
    utxo_commitment: EMPTY_MUHASH,
    timestamp: 0x0,
    bits: 0x0,
    nonce: 0x0,
    daa_score: 0,
    #[rustfmt::skip]
    coinbase_payload: &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blue score
        0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, // Subsidy
        0x00, 0x00, // Script version
        0x01, // Varint
        0x00, // OP-FALSE
        0x65, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x6c,  // eternally, for ever
        0x79, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x65,
        0x76, 0x65, 0x72,
    ],
};

pub const TESTNET_GENESIS: GenesisBlock = GenesisBlock {
    hash: Hash::from_bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    ]),
    version: 0,
    hash_merkle_root: Hash::from_bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    ]),
    utxo_commitment: EMPTY_MUHASH,
    timestamp: 0x0,
    bits: 0x0,
    nonce: 0x0,
    daa_score: 0,
    #[rustfmt::skip]
    coinbase_payload: &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blue score
        0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, // Subsidy
        0x00, 0x00, // Script version
        0x01,                                                                         // Varint
        0x00,                                                                         // OP-FALSE
        0x65, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x6c,  // eternally, for ever
        0x79, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x65,
        0x76, 0x65, 0x72,
    ],
};

pub const SIMNET_GENESIS: GenesisBlock = GenesisBlock {
    hash: Hash::from_bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    ]),
    version: 0,
    hash_merkle_root: Hash::from_bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    ]),
    utxo_commitment: EMPTY_MUHASH,
    timestamp: 0x0,
    bits: 0x0,
    nonce: 0x0,
    daa_score: 0,
    #[rustfmt::skip]
    coinbase_payload: &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blue score
        0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, // Subsidy
        0x00, 0x00, // Script version
        0x01,                                                                   // Varint
        0x00,                                                                   // OP-FALSE
        0x65, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x6c,  // eternally, for ever
        0x79, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x65,
        0x76, 0x65, 0x72,
    ],
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::bps::OneBps, merkle::calc_hash_merkle_root};

    pub fn calculate_genesis_hash() -> Hash {
        // create a temporary Block object
        let block = Block::from(&GENESIS);

        // compute genesis hash
        let hash = block.hash();

        // print new genesis hash
        println!("New genesis hash: {:?}", hash);

        hash
    }

    #[test]
    fn print_new_genesis_hash() {
        let hash = calculate_genesis_hash();
        println!("New genesis hash bytes:");
        print!("[");
        for byte in hash.as_bytes() {
            print!("0x{:02x}, ", byte);
        }
        println!("]");
    }

    #[test]
    fn test_genesis_hashes() {
        [GENESIS].into_iter().for_each(|genesis| {
            let block: Block = (&genesis).into();
            println!("genesis.bits: {}, genesis.hash: {:#04x?}", genesis.bits, genesis.hash.as_bytes());
            assert_hashes_eq(
                calc_hash_merkle_root(block.transactions.iter(), false),
                block.header.hash_merkle_root,
            );
            assert_hashes_eq(block.hash(), genesis.hash);
        });
    }

    #[test]
    fn gen_testnet_genesis() {
        let bps = OneBps::bps();
        let mut genesis = TESTNET_GENESIS;
        let target = vecno_math::Uint256::from_compact_target_bits(genesis.bits);
        let scaled_target = target * bps / 100;
        let scaled_bits = scaled_target.compact_target_bits();
        genesis.bits = scaled_bits;
        if genesis.bits != TESTNET_GENESIS.bits {
            panic!("Testnet: new bits: {}\nnew hash: {:#04x?}", scaled_bits, Block::from(&genesis).hash().as_bytes());
        }
    }

    #[test]
    fn print_all_new_genesis_hash() {
        let block = Block::from(&GENESIS);
        // compute hash_merkle_root
        let hash_merkle_root = calc_hash_merkle_root(block.transactions.iter(), false);
        // compute block hash
        let new_hash = block.hash();

        println!("New genesis hash: {}", new_hash);
        println!(
            "New genesis hash bytes:\n[{}]",
            new_hash.as_bytes().iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(", ")
        );

        println!("\nNew hash_merkle_root: {}", hash_merkle_root);
        println!(
            "New hash_merkle_root bytes:\n[{}]",
            hash_merkle_root.as_bytes().iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(", ")
        );
    }

    fn assert_hashes_eq(got: Hash, expected: Hash) {
        if got != expected {
            // Special hex print to ease changing the genesis hash according to the print if needed
            panic!("Got hash {:#04x?} while expecting {:#04x?}", got.as_bytes(), expected.as_bytes());
        }
    }

    /// Convert any string to bytes array format
    #[test]
    fn test_string_to_bytes() {
        // Test normal string
        let text = "eternally, for ever";
        println!("Converting text to bytes: {}", text);
        print_string_as_bytes(text);

        // Test hash string
        let hash_str = "000000000000000000024a78c271693813683c466bda32255055461667dcd942";
        println!("\nConverting hash to bytes: {}", hash_str);
        print_hex_string_as_bytes(hash_str);

        let genesis_hash = "0167572782d2471ca2d9f1ccb1b092e42322214966631dfcdef77c36280b8526";
        println!("\nConverting genesis hash to bytes: {}", genesis_hash);
        print_hex_string_as_bytes(genesis_hash);

        let market_hash = "9bad5c7001e22a4372449e61c0774078eff416d68bf3e99b81422bc7f46ba97b";
        println!("\nConverting market hash to bytes: {}", market_hash);
        print_hex_string_as_bytes(market_hash);
    }

    /// Convert bytes array to string
    #[test]
    fn test_bytes_to_string() {
        // Test bytes array of normal string
        let text_bytes =
            [0x65, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x6c, 0x79, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x65, 0x76, 0x65, 0x72];

        // Convert to UTF-8 string
        let text = String::from_utf8_lossy(&text_bytes);
        println!("Text from bytes: {}", text);

        // Convert to hex string
        let hex = text_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        println!("Hex string: 0x{}", hex);
    }

    /// Helper function: Convert normal string to bytes array format and print
    fn print_string_as_bytes(text: &str) {
        println!("Bytes array format:");
        println!("[");
        for chunk in text.as_bytes().chunks(8) {
            let bytes = chunk.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(", ");
            println!("    {},", bytes);
        }
        println!("]");
    }

    /// Helper function: Convert hex string to bytes array format and print
    fn print_hex_string_as_bytes(hex_str: &str) {
        let clean_hex = hex_str.trim_start_matches("0x");
        let bytes: Vec<String> = (0..clean_hex.len())
            .step_by(2)
            .map(|i| {
                let byte_str = &clean_hex[i..i + 2];
                format!("0x{}", byte_str)
            })
            .collect();

        println!("Bytes array format:");
        println!("[");
        for chunk in bytes.chunks(8) {
            println!("    {}", chunk.join(", ") + ",");
        }
        println!("]");
    }

    /// Parse value test function
    #[test]
    fn test_parse_ve_value() {
        let subsidy_bytes = [0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00];

        // Print each byte position and value
        println!("Byte positions (0-7): ");
        for (i, byte) in subsidy_bytes.iter().enumerate() {
            println!("Position {}: 0x{:02x}", i, byte);
        }

        // Try little endian
        let value_le = u64::from_le_bytes(subsidy_bytes);
        let ve_value_le = value_le as u64 / 100_000_000;
        println!("\nLittle Endian:");
        println!("Raw value (sats): {}", value_le);
        println!("VE value: {} VE", ve_value_le);

        // Test expected value of 1 VE
        let expected_value: u64 = 1 * 100_000_000;
        let expected_bytes = expected_value.to_le_bytes();
        println!("\nExpected bytes for 1 VE:");
        println!("Raw bytes: [{}]", expected_bytes.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(", "));
    }

    /// Generate value bytes
    #[test]
    fn test_generate_ve_bytes() {
        let ve_value: u64 = 1;
        let sats_value = ve_value * 100_000_000;
        let bytes = sats_value.to_le_bytes();

        println!("For {} VE:", ve_value);
        println!("Sats value: {}", sats_value);
        println!("Bytes (little endian): [{}]", bytes.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(", "));
    }

    /// Hexadecimal to decimal test function
    #[test]
    fn test_hex_to_decimal() {
        let bits = 0x1d02ca33;
        println!("Bits value:");
        println!("Hex: 0x{:x}", bits);
        println!("Decimal: {}", bits);
    }

    #[test]
    fn test_decimal_to_hex() {
        let bits = 536870913;
        println!("Bits value:");
        println!("Decimal: {}", bits);
        println!("Hex: 0x{:x}", bits);
    }
}