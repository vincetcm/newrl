import random
import string
import time
import requests

from setup import NODE_URL, WALLET, BLOCK_WAIT_TIME, TEST_ENV
from setup import generate_random_token_code
from test_add_wallet import add_wallet
from test_add_token import add_token


def test_transfer_unilateral():
    from_wallet = add_wallet()
    to_wallet = add_wallet()
    token = add_token(from_wallet['address'])
    transfer_unilateral(from_wallet, to_wallet, token, 100)
    

def transfer_unilateral(from_wallet, to_wallet, token, amount):
    token_code = token['tokencode']
    req ={
        "transfer_type": 5,
        "asset1_code": token_code,
        "asset2_code": "",
        "wallet1_address": from_wallet['address'],
        "wallet2_address": to_wallet['address'],
        "asset1_qty": amount,
        "description": "",
        "additional_data": {}
    }
    response = requests.post(NODE_URL + '/add-transfer', json=req)

    assert response.status_code == 200
    unsigned_transaction = response.json()
    
    response = requests.post(NODE_URL + '/sign-transaction', json={
    "wallet_data": from_wallet,
    "transaction_data": unsigned_transaction
    })
    signed_transaction = response.json()
    response = requests.post(NODE_URL + '/validate-transaction', json=signed_transaction)

    if TEST_ENV == 'local':
        response = requests.post(NODE_URL + '/run-updater?add_to_chain_before_consensus=true')
    else:
        print('Waiting to mine block')
        time.sleep(BLOCK_WAIT_TIME)
    
    response = requests.get(NODE_URL + f"/get-balances?balance_type=TOKEN_IN_WALLET&token_code={token_code}&wallet_address={to_wallet['address']}")
    assert response.status_code == 200
    balance = response.json()['balance']
    assert balance == amount


    print('Test passed.')

def test_transfer_bilateral():
    
    print('Test passed.')


if __name__ == '__main__':
    test_transfer_unilateral()
    test_transfer_bilateral()