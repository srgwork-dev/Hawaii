import hashlib
import datetime
from ecc_crypto_operations import Sha256Point, PrivateKey, G

class Block:
    """
    Represents a block in the blockchain.
    """

    def __init__(self, previous_hash, transactions):
        self.timestamp = datetime.datetime.utcnow()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = None
        self.hash = None

    def hash_block(self):
        """
        Computes the hash of the block.
        """
        header = str(self.timestamp) + str(self.transactions) + str(self.previous_hash) + str(self.nonce)
        self.hash = hashlib.sha256(header.encode()).hexdigest()
        return self.hash

    def mine_block(self, difficulty=4):
        """
        Mines the block by finding a valid nonce that results in a hash with leading zeros.
        """
        prefix_str = '0' * difficulty
        self.nonce = 0
        while True:
            self.hash_block()
            if self.hash.startswith(prefix_str):
                break
            self.nonce += 1

    def __repr__(self):
        return f"Block(timestamp={self.timestamp}, transactions={self.transactions}, previous_hash={self.previous_hash}, hash={self.hash})"


class Blockchain:
    """
    Represents a blockchain with basic operations like adding blocks and validating the chain.
    """

    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """
        Creates the genesis block (the first block in the blockchain).
        """
        genesis_block = Block(previous_hash='0', transactions=[])
        genesis_block.mine_block()
        self.chain.append(genesis_block)

    def add_block(self, transactions):
        """
        Adds a new block to the blockchain.
        """
        previous_hash = self.chain[-1].hash
        new_block = Block(previous_hash, transactions)
        new_block.mine_block()
        self.chain.append(new_block)

    def validate_chain(self):
        """
        Validates the integrity of the blockchain by checking hashes and previous hashes.
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.hash_block():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def __repr__(self):
        return f"Blockchain(chain={self.chain})"


if __name__ == "__main__":
    # Example usage of the blockchain
    blockchain = Blockchain()
    print("Blockchain created.")

    # Add some transactions
    transactions1 = ['Andrew sends 1 BTC to Harrison', 'Harrison sends 2 BTC to Jim']
    blockchain.add_block(transactions1)
    print("Block 1 added to the blockchain.")

    transactions2 = ['Jim sends 0.5 BTC to Andrew', 'Andrew sends 0.7 BTC to Harrison']
    blockchain.add_block(transactions2)
    print("Block 2 added to the blockchain.")

    # Validate the blockchain
    print("Blockchain validation result:", blockchain.validate_chain())
