from solders.transaction import VersionedTransaction
from base58 import b58decode


# Function to extract the recent blockhash from a base58-encoded Solana transaction.
def extract_blockhash(tx_param_b58: str):
    """
    Extracts the recent blockhash from a base58-encoded Solana transaction.

    Args:
        tx_param_b58 (str): The base58-encoded transaction string.

    Returns:
        str: The recent blockhash extracted from the transaction.
    """
    # Decode base58 into raw transaction bytes
    tx_bytes = b58decode(tx_param_b58)

    # Parse into a VersionedTransaction
    tx = VersionedTransaction.from_bytes(tx_bytes)

    # Extract blockhash (property, not method)
    blockhash = str(tx.message.recent_blockhash)

    print("Blockhash:", blockhash)
    return blockhash

