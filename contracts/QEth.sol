contract QEth {
  /*
   * Quantum-safe proxy contract, based on 
   *         merkle tree depth = 16, hash length = 256
   *
   *
   */
  bytes32 public pubkey_hash;

  function QEth(bytes32 _pubkey) public {
    pubkey_hash = _pubkey;
  }

  function verify_chunk(byte v, bytes32 s) internal returns (bytes32 y) {
    for(uint i = 0; i < 255 - uint(v); i++){
      s = sha3(s);
    }
    return s;
  }

  function verify_message(bytes32 message, bytes32[32] sig) internal {
    uint s;
    bytes32 phash;
    for(uint i = 0; i < 32; i++){
      phash = keccak256(pubkey_hash, verify_chunk(message[i], sig[i]));
      if (i < 30){
        s += uint(message[i]);
      }
    }
    assert(256*30 - s == uint(message & 0xFFFF)); // Make sure checksum is valid
    assert(phash == pubkey_hash);
  }

  function send_transaction(bytes32[32] sig, bytes32 next_key, uint g, address a, uint v, bytes data) external {
    verify_message(keccak256(next_key, g, a, v, data), sig);
    a.call.gas(g).value(v)(data);
    pubkey_hash = next_key;
  }
}
