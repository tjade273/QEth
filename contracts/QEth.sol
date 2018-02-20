contract QEth {
  /*
   * Quantum-safe proxy contract, based on
   * Winternitz One-time Signatures
   * with 30 8-bit chunks
   * Gives 120 bit security
   *
   * Based on:
   * Ralph Merkle. "A certified digital signature". Ph.D. dissertation, Stanford University, 1979
   */
  bytes32 public pubkey_hash;

  function QEth(bytes32 _pubkey) public {
    // Initialize to first pubkey hash
    pubkey_hash = _pubkey;
  }

  function send_transaction(bytes32[32] sig, bytes32 next_key, uint g, address a, uint v, bytes data) external {

    uint s; // \sum_{i = 0}^30 message_i
    bytes32 phash; // phash_{i+1} = sha3(phash_i, pkey[i])

    bytes32 message = keccak256(next_key, g, a, v, data);
    for(uint i = 0; i < 30; i++){
      s += uint(message[i]);
    }

    // Append checksum: msg[30:] == 256*30 - sum(msg[:30])
    message &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000;
    message |= bytes32(256*30 - s);

    // H^(256-v)(H^v(priv)) == pub
    for(i = 0; i < 32; i++){
      bytes32 sig_chunk = sig[i];
      byte vi = message[i];
      for(uint j = 0; j < 256 - uint(vi); j++){
        sig_chunk = keccak256(sig_chunk);
      }
      phash = keccak256(phash, sig_chunk);
    }

    assert(phash == pubkey_hash);
    a.call.gas(g).value(v)(data);

    // Update public key (Don't reuse keys...)
    pubkey_hash = next_key;
  }

}
