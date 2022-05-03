#!/usr/bin/python3

from algosdk import mnemonic
from algosdk import account
from web3 import Web3
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

# generate ethereum
w3 = connect_to_eth()
w3.eth.account.enable_unaudited_hdwallet_features()
# acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()
# print(mnemonic_secret)
# print(acct)
acct = w3.eth.account.from_mnemonic("mimic option vacuum capital release pilot like improve wife mimic angle tone")
#acc1 = w3.eth.account.from_mnemonic("congress senior silk setup awful echo spray float crime risk wife index")
#print(acc == acc1)
eth_pk = acct._address
eth_sk = acct._private_key
# print(eth_pk)
# print(eth_sk)

#generate algorate
mnemonic_secret = mnemonic.from_private_key('b3DMveoWmzxnVb3vE4ao4k3aKF6jYhV1OxU6KMQ24xils1b6I8lxtZ3KeckIfhk7ySbaY76YAlAY+TXpGzN11A==')
sk = mnemonic.to_private_key(mnemonic_secret)
pk = mnemonic.to_public_key(mnemonic_secret)
# print(pk)
# print(sk)
