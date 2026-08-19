"""Minimal reproducible example for the fixed manuscript test vector."""

from dcs_cipher import decrypt_block, encrypt_block, generate_round_keys


def main():
    plaintext = bytes.fromhex("0A0B0C0D0F0102030405060708091A2B")
    key = bytes.fromhex("0102040506AABBCC44DDEE8809040506")
    round_keys = generate_round_keys(key)
    ciphertext = encrypt_block(plaintext, round_keys, use_dcs=True)
    recovered = decrypt_block(ciphertext, round_keys, use_dcs=True)
    print("Plaintext :", plaintext.hex().upper())
    print("Key       :", key.hex().upper())
    print("Ciphertext:", ciphertext.hex().upper())
    print("Recovered :", recovered.hex().upper())
    assert ciphertext.hex().upper() == "4ED6992E8811FAC957A2F31167C53D6D"
    assert recovered == plaintext


if __name__ == "__main__":
    main()
