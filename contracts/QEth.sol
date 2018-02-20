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

  function send_transaction(bytes32[32] sig, bytes32 next_key, uint g, address a, uint v, bytes data) external {
    uint s;
    bytes32 phash;
    bytes32 message = keccak256(next_key, g, a, v, data);
    for(uint i = 0; i < 30; i++){
      s += uint(message[i]);
    }

    message &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000;
    message |= bytes32(256*30 - s);
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
    pubkey_hash = next_key;
  }

  function send_transaction2(bytes32[32] sig, bytes32 next_key, uint g, address a, uint v, bytes data) external {
    assembly {
      let m = mload(0x40)
        calldatacopy(m, 0x404, )
        let sum := 0
        let phash := 0
        for {let i := 0} lt(i, 30) {i := add(i, 1)} {
        sum := add(sum,)
        }
  }
}
