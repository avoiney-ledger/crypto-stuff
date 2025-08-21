from solana.publickey import PublicKey
from spl import verify_token_account_is_ata

# Constants
SPL_ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID = PublicKey(
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
)
SPL_TOKEN_PROGRAM_ID = PublicKey(
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
)

# Inputs
WALLET_PUBKEY = "4yLsYnu5NaMepvV6LVGrz4nTWrNJtqbwmWvgCWb7Gukj"
MINT_PUBKEY = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

def test_valid_ata():
    ata_address, _ = PublicKey.find_program_address(
        [
            bytes(PublicKey(WALLET_PUBKEY)),
            bytes(SPL_TOKEN_PROGRAM_ID),
            bytes(PublicKey(MINT_PUBKEY)),
        ],
        SPL_ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID,
    )
    result = verify_token_account_is_ata(
        str(SPL_ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID),
        str(SPL_TOKEN_PROGRAM_ID),
        WALLET_PUBKEY,
        MINT_PUBKEY,
        str(ata_address),
    )
    assert result

def test_invalid_ata():
    wrong_ata = str(PublicKey("11111111111111111111111111111111"))
    result = verify_token_account_is_ata(
        str(SPL_ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID),
        str(SPL_TOKEN_PROGRAM_ID),
        WALLET_PUBKEY,
        MINT_PUBKEY,
        wrong_ata,
    )
    assert result is False
