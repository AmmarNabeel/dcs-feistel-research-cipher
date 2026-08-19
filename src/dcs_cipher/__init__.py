"""Reference implementation of the Feistel research cipher with DCS."""

from .cipher import (
    BLOCK_BITS,
    BLOCK_BYTES,
    KEY_BYTES,
    MASK64,
    MASK128,
    ROUNDS,
    SBOX,
    TestVector,
    dcs_byte_positions,
    decrypt_block,
    decrypt_blocks,
    dynamic_cross_swap,
    encrypt_block,
    encrypt_blocks,
    generate_round_keys,
    make_test_vector,
    present_permutation64,
    rotl,
    round_function,
    substitute_nibbles64,
)

__all__ = [
    "BLOCK_BITS", "BLOCK_BYTES", "KEY_BYTES", "MASK64", "MASK128",
    "ROUNDS", "SBOX", "TestVector", "dcs_byte_positions",
    "decrypt_block", "decrypt_blocks", "dynamic_cross_swap",
    "encrypt_block", "encrypt_blocks", "generate_round_keys",
    "make_test_vector", "present_permutation64", "rotl",
    "round_function", "substitute_nibbles64",
]
