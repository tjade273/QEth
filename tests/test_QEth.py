import pytest
from functools import reduce
import eth_utils
from eth_utils import pad_left
from os import urandom

def hash(x, n):
    for _ in range(n):
        x = eth_utils.keccak(x)
    return x

def keygen():
    privkey = [urandom(32) for _ in range(32)]
    pubkey = [hash(x, 256) for x in privkey]
    pubkey_hash = reduce(lambda x, y : eth_utils.keccak(x+y), pubkey, b'\x00'*32)
    return (pubkey_hash, privkey)

def msg_hash(nextkey, gas, addr, value, data):
    msg  = b''.join([pad_left(nextkey, 32, b'\x00'), pad_left(gas, 32, b'\x00'), pad_left(addr, 20, b'\x00'), pad_left(value, 32, b'\x00')])+data
    #print('Expected: ',"0x"+msg.hex(), len("0x"+msg.hex()))
    return eth_utils.keccak(msg)

def sign(privkey, msghash):
    h = list(msghash)[:-2]
    checksum = 256*30 - sum(h)
    msg_hash = h+[checksum >> 8, checksum & 0xFF]
    return [hash(privkey[i], msg_hash[i]) for i in range(32)]

init_key = keygen()

@pytest.fixture()
def qeth_contract(chain):
    QEthFactory = chain.provider.get_contract_factory('QEth')
    deploy_txn_hash = QEthFactory.deploy(args=[init_key[0]])
    contract_address = chain.wait.for_contract_address(deploy_txn_hash)
    return QEthFactory(address=contract_address)


def test_deploy(qeth_contract):
    assert eth_utils.force_bytes(qeth_contract.call().pubkey_hash()) == init_key[0]

def test_sign(qeth_contract, web3, capsys):
    (pubkey_next, privkey_next) = keygen()
    msghash = msg_hash(pubkey_next, b'\x00', b'\x00', b'\x00', b'\x12\x34')
    sig = sign(init_key[1], msghash)
    tx_hash1 = qeth_contract.transact().send_asm(sig, pubkey_next, 0, "0x"+"0"*40, 0, b'\x12\x34')
    #tx_hash2 = qeth_contract.transact().send_transaction(sig, pubkey_next, 0, "0x"+"0"*40, 0, b'\x12\x34')
    #print("Logged msg: ",web3.eth.getTransactionReceipt(tx_hash)['logs'][0]['data'], len(web3.eth.getTransactionReceipt(tx_hash)['logs'][0]['data']))
    #assert (web3.eth.getTransactionReceipt(tx_hash1)['logs'][1]['data'] == "0x"+msghash.hex())
    #assert web3.eth.getTransactionReceipt(tx_hash1)['logs'][2]['data'] == web3.eth.getTransactionReceipt(tx_hash2)['logs'][0]['data'] 
    with capsys.disabled():
        print('\nGas used:'+str(+web3.eth.getTransactionReceipt(tx_hash1)['gasUsed'])+'\n')
    assert eth_utils.force_bytes(qeth_contract.call().pubkey_hash()) == pubkey_next



