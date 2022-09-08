from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class ECPublicKey:
    def __init__(self, pubkey: str, curve_parameter: ec.EllipticCurve):
        b_pub = bytes.fromhex(pubkey)
        self.obj = ec.EllipticCurvePublicKey.from_encoded_point(curve_parameter, b_pub)

    @classmethod
    def from_ec_private_key(
        cls, private_key: ec.EllipticCurvePrivateKey
    ) -> "ECPublicKey":
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        return cls(public_bytes.hex(), ec.SECP256K1())

    def verify(self, data: bytes, sig: bytes, alg: hashes.HashAlgorithm) -> None:
        self.obj.verify(sig, data, ec.ECDSA(alg))

    def to_hex(self) -> str:
        """Return the hexadecimal representation of the public key"""
        return self.obj.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        ).hex()


class ECPrivateKey:
    def __init__(self, privkey: str, curve_parameter: ec.EllipticCurve):
        pk_i = int(privkey, 16)
        privkey_str = "{:064x}".format(pk_i)
        assert len(privkey_str) == 64

        self.obj = ec.derive_private_key(int(privkey_str, 16), curve_parameter)
        self.pubkey = ECPublicKey.from_ec_private_key(self.obj)

    def to_hex(self) -> str:
        """Return the hexadecimal representation of the private key"""
        return hex(self.obj.private_numbers().private_value).lstrip("0x")

    def sign(self, data: bytes, alg: hashes.HashAlgorithm) -> bytes:
        """Sign a message using the given algorythm"""
        return self.obj.sign(data, ec.ECDSA(alg))


# Only tools functions


def get_ec_public_key_from_hex(
    pubkey: str, curve_parameter: ec.EllipticCurve
) -> ec.EllipticCurvePublicKey:
    """Get an EllipticCurvePublicKey from its hex representation"""
    pkey_bytes = bytes.fromhex(pubkey)
    return ec.EllipticCurvePublicKey.from_encoded_point(curve_parameter, pkey_bytes)


def verify_ec_signed_message(
    ec_pubkey: ec.EllipticCurvePublicKey,
    sig: bytes,
    message: bytes,
    alg: hashes.HashAlgorithm,
) -> None:
    """
    Raise InvalidSignatureException
    if the message has not been signed by the
    provided signature else returns None.
    """
    ec_pubkey.verify(sig, message, ec.ECDSA(alg))
