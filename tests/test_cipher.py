import random

import pytest

from dcs_cipher import (
    MASK64,
    ROUNDS,
    dcs_byte_positions,
    decrypt_block,
    dynamic_cross_swap,
    encrypt_block,
    generate_round_keys,
    make_test_vector,
)


KEY = bytes.fromhex("0102040506AABBCC44DDEE8809040506")
PLAINTEXT = bytes.fromhex("0A0B0C0D0F0102030405060708091A2B")
EXPECTED_CIPHERTEXT = "4ED6992E8811FAC957A2F31167C53D6D"


def test_published_vector():
    vector = make_test_vector(PLAINTEXT.hex(), KEY.hex(), use_dcs=True)
    assert vector.ciphertext_hex == EXPECTED_CIPHERTEXT


@pytest.mark.parametrize("use_dcs", [False, True])
def test_deterministic_round_trips(use_dcs):
    rng = random.Random(20260816)
    for _ in range(1000):
        key = rng.randbytes(16)
        plaintext = rng.randbytes(16)
        round_keys = generate_round_keys(key)
        ciphertext = encrypt_block(plaintext, round_keys, use_dcs)
        assert decrypt_block(ciphertext, round_keys, use_dcs) == plaintext


def test_dcs_is_an_involution_and_positions_are_valid():
    rng = random.Random(20260816)
    round_keys = generate_round_keys(KEY)
    assert len(round_keys) == ROUNDS
    for round_index, round_key in enumerate(round_keys):
        left_position, right_position = dcs_byte_positions(round_key, round_index)
        assert left_position in range(8)
        assert right_position in range(8)
        for _ in range(100):
            left, right = rng.getrandbits(64), rng.getrandbits(64)
            swapped = dynamic_cross_swap(left, right, round_key, round_index)
            restored = dynamic_cross_swap(*swapped, round_key, round_index)
            assert restored == (left & MASK64, right & MASK64)


def test_input_lengths_are_checked():
    round_keys = generate_round_keys(KEY)
    with pytest.raises(ValueError):
        encrypt_block(b"short", round_keys)
    with pytest.raises(ValueError):
        generate_round_keys(b"short")
