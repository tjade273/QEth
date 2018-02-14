import pytest
from functools import reduce
from eth_utils import keccak
from os import urandom

def hash(x, n):
    for _ in range(n):
        x = keccak(x)
    return x

def keygen():
    privkey = [urandom(32) for _ in range(32)]
    pubkey = [hash(x, 256) for x in privkey]
    pubkey_hash = reduce(lambda x, y : keccak(x+y), pubkey, b'\x00'*32)
    return (pubkey_hash, privkey)

def sign(privkey, gas, addr, value, data):

    #var left_pad = require('left-pad')
    def left_pad(s):
        return b'\x00'*(32-len(s)) + s

    msg  = b''.join([left_pad(s) for s in [gas, addr, value]]) + data
    h = list(keccak(msg))[:-2]
    checksum = 256*30 - sum(h)
    msg_hash = h+[checksum >> 8, checksum & 0xFF]

    return [hash(privkey[i], msg_hash[i]) for i in range(32)]

init_key = keygen()

@pytest.fixture()
def qeth_contract(chain):
    QEthFactory = chain.get_contract_factory('QEth')
    deploy_txn_hash = QEthFactory.deploy(arguments=[init_key[0]])
    contract_address = chain.wait.for_contract_address(deploy_txn_hash)
    return QEthFactory(address=contract_address)


def test_deploy(qeth_contract):
    assert qeth_contract.call().pubkey_hash() == init_key[0]
