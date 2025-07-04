import asyncio
import logging
from config.settings import settings
from src.utils.crypto import BTCCrypto

# Configure basic logging for output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def sign_my_message():
    private_key = settings.get_btc_config().get('private_key')
    if not private_key:
        logging.error("Private key not found in config.json. Please ensure it's set.")
        return

    btc_crypto = BTCCrypto(network=settings.get_btc_config().get('network', 'testnet'))
    message_to_sign = "Please sign this message to confirm that you are the owner of the wallet. Signing is free of charge and does not entail any transactions."

    signature = btc_crypto.sign_message(private_key, message_to_sign)

    if signature:
        logging.info(f"Successfully signed message. Signature: {signature}")
    else:
        logging.error("Failed to sign the message.")

if __name__ == "__main__":
    asyncio.run(sign_my_message())