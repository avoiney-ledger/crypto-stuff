from solana.publickey import PublicKey

# Utility for verifying Solana associated token accounts (ATA)


def verify_token_account_is_ata(
    token_account_program: str,
    token_program_id: str,
    wallet_pub_key: str,
    mint_pub_key: str,
    token_account_pub_key: str,
):
    """
    Verifies that the given token account public key is the correct
    Associated Token Account (ATA) for the specified wallet and mint.

    Args:
        token_account_program (str): The associated token account program ID.
        token_program_id (str): The SPL token program ID.
        wallet_pub_key (str): The wallet's public key (owner of the token account).
        mint_pub_key (str): The token mint's public key.
        token_account_pub_key (str): The token account public key to verify.

    Returns:
        bool: True if the token account public key matches the computed ATA address, False otherwise.
    """
    spl_associated_token_account_program_id = PublicKey(token_account_program)
    spl_token_program_id = PublicKey(token_program_id)

    # Inputs
    wallet_pubkey = PublicKey(wallet_pub_key)  # owner of the token account
    mint_pubkey = PublicKey(mint_pub_key)  # Token mint

    # Compute ATA address
    ata_address, bump_seed = PublicKey.find_program_address(
        [bytes(wallet_pubkey), bytes(spl_token_program_id), bytes(mint_pubkey)],
        spl_associated_token_account_program_id,
    )

    print("Computed ATA address:", ata_address)
    return str(ata_address) == token_account_pub_key
