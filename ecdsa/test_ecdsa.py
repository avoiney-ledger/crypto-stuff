import pytest
from ecdsa import (
    ECPublicKey,
    ECPrivateKey,
    get_ec_public_key_from_hex,
    verify_ec_signed_message,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature

HEX_TEST_PRIVATE_KEY = (
    "a982fe009b4b4dd7764e6c122c5e014b33aad8d78bbb90f458d0ad561a0bdf76"
)
HEX_TEST_PUBLIC_KEY = "043922b4b842458e2e2316403ee118ad8b2d9b2be727354118cb96cad27ee6616a3295e2a354f6208fbd8f751828ef1f80f3b4268e52b334f7a4eb18d5bd530865"
BAD_HEX_PUBLIC_KEY = "048fc71e4805c03c1c06a971ed46243b5f59e00fbb3025cc9c9552e689f88d10e37e2a6e443c944285d2e9b8251a61537377009790d96efe13d7f493ecd2ef6c57"


@pytest.fixture
def signed_message():
    message = b"blob"
    privkey = ec.derive_private_key(int(HEX_TEST_PRIVATE_KEY, 16), ec.SECP256K1())
    return message, privkey.sign(message, ec.ECDSA(hashes.SHA256()))


# Class based


def test_public_key_from_hex_and_private_key_match():
    from_hex = ECPublicKey(HEX_TEST_PUBLIC_KEY, ec.SECP256K1())
    from_priv_key = ECPrivateKey(HEX_TEST_PRIVATE_KEY, ec.SECP256K1())

    assert from_hex.to_hex() == from_priv_key.pubkey.to_hex()
    assert (
        from_hex.obj.public_numbers() == from_priv_key.obj.public_key().public_numbers()
    )


def test_signed_message_can_be_verified(signed_message):
    message, sig = signed_message
    from_hex = ECPublicKey(HEX_TEST_PUBLIC_KEY, ec.SECP256K1())
    assert from_hex.verify(message, sig, hashes.SHA256()) is None


def test_signed_message_cant_be_verified_with_incorrect_public_key(signed_message):
    message, sig = signed_message
    from_hex = ECPublicKey(BAD_HEX_PUBLIC_KEY, ec.SECP256K1())
    with pytest.raises(InvalidSignature):
        from_hex.verify(message, sig, hashes.SHA256())


# Functions based


def test_public_key_from_hex_and_private_key_match_func():
    ec_pubk_key = get_ec_public_key_from_hex(HEX_TEST_PUBLIC_KEY, ec.SECP256K1())
    assert (
        ec_pubk_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
        == HEX_TEST_PUBLIC_KEY
    )


def test_signed_message_can_be_verified_func(signed_message):
    message, sig = signed_message
    ec_pubkey = get_ec_public_key_from_hex(HEX_TEST_PUBLIC_KEY, ec.SECP256K1())

    assert verify_ec_signed_message(ec_pubkey, sig, message, hashes.SHA256()) is None


def test_signed_message_cant_be_verified_with_incorrect_public_key_func(signed_message):
    message, sig = signed_message
    bad_ec_pubkey = get_ec_public_key_from_hex(BAD_HEX_PUBLIC_KEY, ec.SECP256K1())
    with pytest.raises(InvalidSignature):
        verify_ec_signed_message(bad_ec_pubkey, sig, message, hashes.SHA256())
