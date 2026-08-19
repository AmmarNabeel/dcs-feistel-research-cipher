"""Reference implementation of the minimal revised 128-bit research cipher.

This module defines the block primitive only.  The ECB-style helpers are for
reproducible laboratory measurements and must not be used as a file-security
mode in deployment.
"""

from __future__ import annotations

from dataclasses import dataclass

BLOCK_BYTES = 16
BLOCK_BITS = 128
KEY_BYTES = 16
ROUNDS = 7
MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1

# The published 4-bit PRESENT S-box is used as a known component.  It is not
# claimed as a contribution of the proposed design.
SBOX = (0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
        0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2)

SUB_BYTE = tuple(SBOX[value >> 4] << 4 | SBOX[value & 0xF] for value in range(256))


def _build_permutation_tables():
    tables = []
    for byte_position in range(8):
        table = []
        for byte_value in range(256):
            permuted = 0
            for bit_in_byte in range(8):
                source = byte_position * 8 + bit_in_byte
                destination = 63 if source == 63 else (16 * source) % 63
                permuted |= ((byte_value >> bit_in_byte) & 1) << destination
            table.append(permuted)
        tables.append(tuple(table))
    return tuple(tables)


PERMUTATION_TABLES = _build_permutation_tables()


def rotl(value: int, amount: int, width: int) -> int:
    amount %= width
    mask = (1 << width) - 1
    return ((value << amount) | (value >> (width - amount))) & mask


def substitute_nibbles64(value: int) -> int:
    return sum(SUB_BYTE[(value >> (8 * position)) & 0xFF] << (8 * position) for position in range(8))


def present_permutation64(value: int) -> int:
    """Apply the 64-bit PRESENT bit permutation."""
    return sum(
        PERMUTATION_TABLES[position][(value >> (8 * position)) & 0xFF]
        for position in range(8)
    )


def generate_round_keys(master_key: bytes, rounds: int = ROUNDS) -> tuple[int, ...]:
    """Generate 64-bit round keys from one 128-bit master key.

    The 128-bit state is rotated, its two most significant nibbles are passed
    through the known S-box, and a round constant is inserted before the next
    key is extracted.
    """
    if len(master_key) != KEY_BYTES:
        raise ValueError("The master key must contain exactly 16 bytes.")
    state = int.from_bytes(master_key, "big")
    keys = []
    for round_index in range(rounds):
        keys.append((state >> 64) & MASK64)
        if round_index == rounds - 1:
            break
        state = rotl(state, 19, 128)
        top0 = SBOX[(state >> 124) & 0xF]
        top1 = SBOX[(state >> 120) & 0xF]
        state = (state & ((1 << 120) - 1)) | (top0 << 124) | (top1 << 120)
        state ^= ((round_index + 1) & 0x1F) << 62
        state &= MASK128
    return tuple(keys)


def round_function(right: int, round_key: int, round_index: int) -> int:
    mixed = (right ^ round_key ^ ((round_index + 1) * 0x9E3779B97F4A7C15)) & MASK64
    substituted = substitute_nibbles64(mixed)
    permuted = present_permutation64(substituted)
    return (permuted ^ rotl(permuted, 17, 64) ^ rotl(permuted, 41, 64)) & MASK64


def dcs_byte_positions(round_key: int, round_index: int) -> tuple[int, int]:
    """Return the selected byte indices in the range 0..7 for both halves."""
    left_byte = ((round_key >> (8 * (round_index % 8))) + round_index) & 0x7
    right_byte = ((round_key >> (8 * ((round_index + 3) % 8))) + 3 * round_index + 1) & 0x7
    return left_byte, right_byte


def dynamic_cross_swap(left: int, right: int, round_key: int, round_index: int) -> tuple[int, int]:
    """Swap eight key-dependent bit pairs between the 64-bit halves.

    Applying this function twice with the same key and round index restores
    the two inputs, so the operation is its own inverse.
    """
    left_index, right_index = dcs_byte_positions(round_key, round_index)
    left_position, right_position = 8 * left_index, 8 * right_index
    left_byte = (left >> left_position) & 0xFF
    right_byte = (right >> right_position) & 0xFF
    left = (left & ~(0xFF << left_position)) | (right_byte << left_position)
    right = (right & ~(0xFF << right_position)) | (left_byte << right_position)
    return left & MASK64, right & MASK64


def encrypt_block(block: bytes, round_keys: tuple[int, ...], use_dcs: bool = True) -> bytes:
    if len(block) != BLOCK_BYTES:
        raise ValueError("A plaintext block must contain exactly 16 bytes.")
    left = int.from_bytes(block[:8], "big")
    right = int.from_bytes(block[8:], "big")
    for round_index, round_key in enumerate(round_keys):
        left, right = right, (left ^ round_function(right, round_key, round_index)) & MASK64
        if use_dcs:
            left, right = dynamic_cross_swap(left, right, round_key, round_index)
    return left.to_bytes(8, "big") + right.to_bytes(8, "big")


def decrypt_block(block: bytes, round_keys: tuple[int, ...], use_dcs: bool = True) -> bytes:
    if len(block) != BLOCK_BYTES:
        raise ValueError("A ciphertext block must contain exactly 16 bytes.")
    left = int.from_bytes(block[:8], "big")
    right = int.from_bytes(block[8:], "big")
    for round_index in range(len(round_keys) - 1, -1, -1):
        round_key = round_keys[round_index]
        if use_dcs:
            left, right = dynamic_cross_swap(left, right, round_key, round_index)
        left, right = (right ^ round_function(left, round_key, round_index)) & MASK64, left
    return left.to_bytes(8, "big") + right.to_bytes(8, "big")


def encrypt_blocks(data: bytes, round_keys: tuple[int, ...], use_dcs: bool = True) -> bytes:
    """Encrypt complete blocks for laboratory measurement only."""
    if len(data) % BLOCK_BYTES:
        raise ValueError("Benchmark input length must be a multiple of 16 bytes.")
    output = bytearray(len(data))
    for offset in range(0, len(data), BLOCK_BYTES):
        output[offset:offset + BLOCK_BYTES] = encrypt_block(
            data[offset:offset + BLOCK_BYTES], round_keys, use_dcs
        )
    return bytes(output)


def decrypt_blocks(data: bytes, round_keys: tuple[int, ...], use_dcs: bool = True) -> bytes:
    """Decrypt complete blocks for laboratory measurement only."""
    if len(data) % BLOCK_BYTES:
        raise ValueError("Benchmark input length must be a multiple of 16 bytes.")
    output = bytearray(len(data))
    for offset in range(0, len(data), BLOCK_BYTES):
        output[offset:offset + BLOCK_BYTES] = decrypt_block(
            data[offset:offset + BLOCK_BYTES], round_keys, use_dcs
        )
    return bytes(output)


@dataclass(frozen=True)
class TestVector:
    plaintext_hex: str
    key_hex: str
    ciphertext_hex: str


def make_test_vector(plaintext_hex: str, key_hex: str, use_dcs: bool = True) -> TestVector:
    plaintext = bytes.fromhex(plaintext_hex)
    key = bytes.fromhex(key_hex)
    ciphertext = encrypt_block(plaintext, generate_round_keys(key), use_dcs)
    return TestVector(plaintext_hex.upper(), key_hex.upper(), ciphertext.hex().upper())
