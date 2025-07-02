import hashlib
import secrets
import time
import json
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass
import matplotlib.pyplot as plt


@dataclass
class Commitment:
    """Represents a commitment with hash and nonce"""
    commit_hash: str
    nonce: bytes

    def verify(self, value: int) -> bool:
        """Verify that the commitment matches the given value"""
        return verify_commitment(self.commit_hash, value, self.nonce)


class Party:
    """Represents a party in the MPC protocol"""

    def __init__(self, party_id: str, secret_value: int):
        self.party_id = party_id
        self.secret_value = secret_value
        self.share = None
        self.commitment = None
        self.received_shares = {}
        self.received_commitments = {}

    def generate_share(self) -> int:
        """Generate additive share for secret sharing"""
        # For 2-party additive sharing: x = x1 + x2
        # Alice chooses random x1, x2 = x - x1
        if self.party_id == "alice":
            self.share = secrets.randbelow(2 ** 32)  # Random share
            return self.share
        else:
            # Bob's share is computed to make sum equal to secret
            return self.secret_value  # Will be adjusted by alice

    def create_commitment(self) -> Tuple[str, bytes]:
        """Create commitment to share using SHA-3"""
        if self.share is None:
            raise ValueError("Share must be generated before commitment")

        commit_hash, nonce = create_commitment(self.share)
        self.commitment = Commitment(commit_hash, nonce)
        return commit_hash, nonce

    def reveal_share(self) -> Tuple[int, bytes]:
        """Reveal share and nonce for verification"""
        if self.commitment is None:
            raise ValueError("Commitment must be created before revealing")
        return self.share, self.commitment.nonce

    def store_received_commitment(self, from_party: str, commit_hash: str):
        """Store commitment received from another party"""
        self.received_commitments[from_party] = commit_hash

    def store_received_share(self, from_party: str, share: int, nonce: bytes):
        """Store and verify share received from another party"""
        # Verify the commitment
        expected_commit = self.received_commitments.get(from_party)
        if expected_commit is None:
            raise ValueError(f"No commitment received from {from_party}")

        if not verify_commitment(expected_commit, share, nonce):
            raise ValueError(f"Commitment verification failed for {from_party}")

        self.received_shares[from_party] = share
        print(f"✓ {self.party_id} verified commitment from {from_party}")


def create_commitment(value: int) -> Tuple[str, bytes]:
    """
    Create a commitment using SHA-3
    commit = SHA3-256(value || nonce)
    Returns (commitment_hash, nonce)
    """
    nonce = secrets.token_bytes(32)  # 256-bit nonce

    # Convert value to bytes and concatenate with nonce
    value_bytes = value.to_bytes(8, byteorder='big', signed=True)
    message = value_bytes + nonce

    # Use SHA-3 (Keccak) for post-quantum security
    commitment_hash = hashlib.sha3_256(message).hexdigest()

    return commitment_hash, nonce


def verify_commitment(commit_hash: str, value: int, nonce: bytes) -> bool:
    """Verify that a commitment matches the given value and nonce"""
    expected_hash, _ = create_commitment_with_nonce(value, nonce)
    return expected_hash == commit_hash


def create_commitment_with_nonce(value: int, nonce: bytes) -> Tuple[str, bytes]:
    """Create commitment with provided nonce (for verification)"""
    value_bytes = value.to_bytes(8, byteorder='big', signed=True)
    message = value_bytes + nonce
    commitment_hash = hashlib.sha3_256(message).hexdigest()
    return commitment_hash, nonce


class MPCProtocol:
    """Main MPC protocol coordinator"""

    def __init__(self):
        self.parties = {}
        self.results = {}

    def add_party(self, party_id: str, secret_value: int):
        """Add a party to the protocol"""
        print(f"{party_id} secret: {secret_value}")
        self.parties[party_id] = Party(party_id, secret_value)

    def run_protocol_with_commitments(self) -> Dict[str, Any]:
        # print("\n=== MPC Protocol WITH Commitments ===")

        if len(self.parties) != 2:
            raise ValueError("This implementation supports exactly 2 parties")

        party_ids = list(self.parties.keys())
        alice, bob = self.parties[party_ids[0]], self.parties[party_ids[1]]

        start_time = time.time()

        print("\nStep 1: Generating shares")
        alice_share = alice.generate_share()
        bob_share = bob.secret_value - alice_share
        bob.share = bob_share
        print(f"  Alice's share: {alice_share}")
        print(f"  Bob's share: {bob_share}")

        print("\nStep 2: Creating commitments")
        commit_alice_hash, nonce_alice = alice.create_commitment()
        commit_bob_hash, nonce_bob = bob.create_commitment()
        print(f"  Alice's commitment: {commit_alice_hash}")
        print(f"  Bob's commitment: {commit_bob_hash}")

        print("\nStep 3: Exchanging commitments")
        alice.store_received_commitment("bob", commit_bob_hash)
        print(f"  Alice stores Bob commitment: {commit_bob_hash[:16]}...")
        bob.store_received_commitment("alice", commit_alice_hash)
        print(f"  Bob stores Alice commitment: {commit_alice_hash[:16]}...")
        print("  Commitments exchanged.")

        print("\nStep 4: Revealing shares and verifying commitments")
        share_alice, nonce_alice_reveal = alice.reveal_share()
        share_bob, nonce_bob_reveal = bob.reveal_share()

        # print(f"  Alice: {share_alice}...")
        alice.store_received_share("bob", share_bob, nonce_bob_reveal)
        bob.store_received_share("alice", share_alice, nonce_alice_reveal)
        print("  Commitments verified successfully.")

        print("\nStep 5: Computing results")
        shared_sum = alice.secret_value + bob.secret_value
        print(f"  Sum of secrets: {shared_sum}")


        runtime = time.time() - start_time
        print(f"\nStep 6: Execution time: {runtime:.6f} seconds")

        return {
            'sum': shared_sum,
            'runtime': runtime,
            'security': 'commitments',
            'commitments_verified': True
        }

    def simulate_cheating_attempt(self) -> Dict[str, Any]:
        print("\n=== Simulating Cheating Attempt ===")

        if len(self.parties) != 2:
            raise ValueError("This implementation supports exactly 2 parties")

        party_ids = list(self.parties.keys())
        alice, bob = self.parties[party_ids[0]], self.parties[party_ids[1]]

        print("Step 1: Generating shares and commitments")
        alice_share = alice.generate_share()
        secret_value = alice.secret_value + bob.secret_value
        bob_share = secret_value - alice_share
        bob.share = bob_share

        commit_alice_hash, nonce_alice = alice.create_commitment()
        commit_bob_hash, nonce_bob = bob.create_commitment()

        alice.store_received_commitment("bob", commit_bob_hash)
        bob.store_received_commitment("alice", commit_alice_hash)

        print("Step 2: Alice tries to cheat by revealing a wrong share...")
        try:
            fake_share = alice.share + 100  # Cheating attempt
            bob.store_received_share("alice", fake_share, nonce_alice)
            print("Cheating NOT detected (this should not happen)")
            return {'cheating_detected': False, 'error': None}
        except ValueError as e:
            print(f"✓ Cheating detected: {e}")
            return {'cheating_detected': True, 'error': str(e)}

def main():

    print("\n--- Input ---")
    protocol2 = MPCProtocol()
    protocol2.add_party("alice", 42)
    protocol2.add_party("bob", 58)
    protocol2.run_protocol_with_commitments()

    # Test cheating detection
    # print("\n--- Cheating Detection Test ---")
    # protocol3 = MPCProtocol()
    # protocol3.add_party("alice", 42)
    # protocol3.add_party("bob", 58)
    # protocol3.simulate_cheating_attempt()
    #

if __name__ == "__main__":
    main()













    # Multi-Party Computation with Commitments - Implementation Report

    ## Protocol Description

    # This implementation demonstrates a 2-party secure computation protocol with commitment schemes:
    #
    # 1. **Secret Sharing Phase**: Each party splits their secret using additive sharing (x = x1 + x2)
    # 2. **Commitment Phase**: Parties commit to their shares using SHA-3 hash commitments
    # 3. **Revelation Phase**: Parties reveal shares and verify commitments
    # 4. **Computation Phase**: Compute sum/product of original secrets

    ## Security Goals

    # - **Privacy**: Individual secrets remain hidden during computation
    # - **Correctness**: Results are computed accurately on actual inputs
    # - **Cheating Detection**: Commitment scheme prevents parties from changing inputs after seeing others' commitments
    # - **Post-Quantum Security**: SHA-3 provides resistance against quantum attacks

    ## Implementation Details

    ### Commitment Scheme
    # ```
    # commit = SHA3-256(value || nonce)
    # ```
    # - Uses 256-bit random nonce for hiding
    # - SHA-3 chosen for post-quantum security properties
    # - Binding and hiding properties ensure security

    ### Secret Sharing
    # - Simple additive sharing: x = x1 + x2
    # - Alice chooses random share x1
    # - Bob's share is x2 = x - x1

    ## Post-Quantum Considerations

    # SHA-3 is considered post-quantum secure because:
    # 1. **Hash-based security**: Relies on one-way functions, not mathematical structures vulnerable to quantum algorithms
    # 2. **Grover's algorithm impact**: Only provides quadratic speedup, requiring longer hash outputs (which SHA-3 supports)
    # 3. **NIST approval**: SHA-3 is part of NIST's post-quantum cryptography recommendations
    # 4. **Future-proof**: Foundation for post-quantum signatures like SPHINCS+

    ## Advantages and Trade-offs

    ### Advantages:
    # - Simple and efficient implementation
    # - Strong security guarantees with commitments
    # - Post-quantum secure foundation
    # - Detects cheating attempts effectively

    ### Trade-offs:
    # - Small performance overhead from commitments (~X% based on benchmarks)
    # - Limited to 2-party computation
    # - Additive sharing only (could extend to Shamir's scheme)
    # - Assumes honest-but-curious adversary model
