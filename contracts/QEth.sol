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

  // Naieve solidity version (~1.5 M gas)
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

  // Optimized assembly version (~600k gas)
  function send_asm(bytes32[32] sig, bytes32 next_key, uint g, address a, uint v, bytes data) external {
    assembly{
        let s := 0
        let m := mload(0x40) // Free memory pointer
        let l := calldataload(1188) // len(data)
        calldatacopy(m, 1028, 64) // Copy [next_key, g]
        calldatacopy(add(m, 64), 1104, 52) // Copy [a, v]
        calldatacopy(add(m, 116), 1220, l) // Copy [data]
        let message := keccak256(m, add(116, l))
        for {let i := 0} lt(i, 30) {i := add(i, 1)}
        {
            v := byte(i, message)
            s := add(v, s)
            mstore(32, calldataload(add(4, mul(i,32))))
            for {let j := 0} lt(j, sub(256, v)) {j := add(j, 1)}
            {
                mstore(32, keccak256(32,32))
            }
        mstore(0, keccak256(0, 64))
        }
        // Calculate pubkey for checksum chunks
        s := sub(7680, s)
        mstore(32, calldataload(964))
        for {let j := 0} lt(j, sub(256, div(s, 256))) {j := add(j, 1)}
        {
            mstore(32, keccak256(32, 32))
        }
        mstore(0, keccak256(0, 64))
        mstore(32, calldataload(996))
        for {let j := 0} lt(j, sub(256, and(s, 0xFF))) {j := add(j, 1)}
        {
            mstore(32, keccak256(32, 32))
        }
        let pubkey := keccak256(0, 64)
        if iszero(eq(pubkey, sload(pubkey_hash_slot))) {
            revert(0,0)
        }
        call(g, a, v, add(m, 1112), l, 0,0)
        pop
        sstore(0, next_key)
    }
  }
}
