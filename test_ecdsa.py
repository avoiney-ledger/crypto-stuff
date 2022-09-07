import pytest
from ecdsa import ECPublicKey, ECPrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

HEX_TEST_PRIVATE_KEY = (
    "a982fe009b4b4dd7764e6c122c5e014b33aad8d78bbb90f458d0ad561a0bdf76"
)
HEX_TEST_PUBLIC_KEY = "043922b4b842458e2e2316403ee118ad8b2d9b2be727354118cb96cad27ee6616a3295e2a354f6208fbd8f751828ef1f80f3b4268e52b334f7a4eb18d5bd530865"
BAD_HEX_PUBLIC_KEY = "048fc71e4805c03c1c06a971ed46243b5f59e00fbb3025cc9c9552e689f88d10e37e2a6e443c944285d2e9b8251a61537377009790d96efe13d7f493ecd2ef6c57"


def test_public_key_from_hex_and_private_key_match():
    from_hex = ECPublicKey(HEX_TEST_PUBLIC_KEY, ec.SECP256K1())
    from_priv_key = ECPrivateKey(HEX_TEST_PRIVATE_KEY, ec.SECP256K1())

    assert from_hex.to_hex() == from_priv_key.pubkey.to_hex()
    assert (
        from_hex.obj.public_numbers() == from_priv_key.obj.public_key().public_numbers()
    )


def test_signed_message_can_be_verified():
    privkey = ec.derive_private_key(int(HEX_TEST_PRIVATE_KEY, 16), ec.SECP256K1())
    hex_sig = privkey.sign(b"blob", ec.ECDSA(hashes.SHA256()))
    from_hex = ECPublicKey(HEX_TEST_PUBLIC_KEY, ec.SECP256K1())
    assert from_hex.verify(b"blob", hex_sig, hashes.SHA256()) is None


def test_signed_message_cant_be_verified_with_incorrect_public_key():
    privkey = ec.derive_private_key(int(HEX_TEST_PRIVATE_KEY, 16), ec.SECP256K1())
    sig = privkey.sign(b"blob", ec.ECDSA(hashes.SHA256()))
    from_hex = ECPublicKey(BAD_HEX_PUBLIC_KEY, ec.SECP256K1())
    with pytest.raises(InvalidSignature):
        from_hex.verify(b"blob", sig, hashes.SHA256())
