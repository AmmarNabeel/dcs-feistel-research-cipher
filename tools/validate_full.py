import secrets

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


def main():
    key = bytes.fromhex("0102040506AABBCC44DDEE8809040506")
    round_keys = generate_round_keys(key)
    assert len(round_keys) == ROUNDS
    assert len(set(round_keys)) == ROUNDS

    for round_index, round_key in enumerate(round_keys):
        left_position, right_position = dcs_byte_positions(round_key, round_index)
        assert left_position in range(8)
        assert right_position in range(8)
        left = secrets.randbits(64)
        right = secrets.randbits(64)
        swapped = dynamic_cross_swap(left, right, round_key, round_index)
        restored = dynamic_cross_swap(*swapped, round_key, round_index)
        assert restored == (left & MASK64, right & MASK64)

    for use_dcs in (False, True):
        for _ in range(100_000):
            plaintext = secrets.token_bytes(16)
            ciphertext = encrypt_block(plaintext, round_keys, use_dcs)
            recovered = decrypt_block(ciphertext, round_keys, use_dcs)
            assert recovered == plaintext

    vector = make_test_vector(
        "0A0B0C0D0F0102030405060708091A2B",
        "0102040506AABBCC44DDEE8809040506",
    )
    print(vector)
    print("100000 round-trip tests passed with DCS and 100000 without DCS")


if __name__ == "__main__":
    main()
