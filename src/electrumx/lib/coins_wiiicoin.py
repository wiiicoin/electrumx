# electrumx/lib/coins_wiiicoin.py
from electrumx.lib.coins import Bitcoin
from electrumx.lib.tx_wiiicoin import DeserializerWiiicoin

class Wiiicoin(Bitcoin):
    NAME = "Wiiicoin"
    SHORTNAME = "WIII"
    NET = "mainnet"  # change to "testnet" for testnet class if needed
    DESERIALIZER = DeserializerWiiicoin

    # Heuristics for mempool/throughput estimates; safe conservative defaults:
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1

    # If Wiiicoin has long reorg risk, adjust this:
    REORG_LIMIT = 200

    # If Wiiicoin differs from Bitcoin headers (e.g., AuxPoW), inherit from the right base
    # (e.g., AuxPowMixin, ScryptMixin, etc.) and/or override header methods.
