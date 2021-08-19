from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback
from algosdk.v2client import indexer

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX, Log

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """


@app.before_request
def create_session():
    g.session = scoped_session(DBSession)


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True

    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()

    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True

    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True

    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()


""" End of pre-defined methods """

""" Helper Methods (skeleton code for you to implement) """


def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    g.session.add(Log(message=msg))
    g.session.commit()
    return


def get_algo_keys():
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    sk = 'RgO/pG23ZxM1mfTBNZR2NTqZpgoE2QPbLxCzingu8Ci5B5HfNq0i8DW1bspUi7opXxC+Q0kOOXXREopzczfsyg=='
    pk = 'XEDZDXZWVURPANNVN3FFJC52FFPRBPSDJEHDS5ORCKFHG4ZX5TFFWE46MA'
    return sk, pk


def get_eth_keys(filename="eth_mnemonic.txt"):
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    eth_sk = b'\xcc\xadGK,I@4A\xe1\x06\xfb,\xa7\xe0eHKMRer\x95\x16\xe8\xa6\xa7~\xb1\x93\xc3\x0b'
    eth_pk = '0x487035502D920Cf98fCaC17B5D260976F0c07676'

    return eth_sk, eth_pk


def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!

    # If your fill_order function is recursive, and you want to have fill_order return a list of transactions to be filled, 
    # Then you can use the "txes" argument to pass the current list of txes down the recursion
    # Note: your fill_order function is *not* required to be recursive, and it is *not* required that it return a list of transactions, 
    # but executing a group of transactions can be more efficient, and gets around the Ethereum nonce issue described in the instructions
    order.timestamp = datetime.now()
    g.session.add(order)
    g.session.commit()
    tx = {'amount': order.sell_amount,
          'platform': order.sell_currency,
          'receiver_pk': order.receiver_pk,
          'order_id': order.id,
          'tx_id': None}
    txes.append(tx)
    existing_orders = g.session.query(Order).filter(Order.filled == None).all()
    for o in existing_orders:
        if o.buy_currency == order.sell_currency and o.sell_currency == order.buy_currency and \
                o.sell_amount / o.buy_amount >= order.buy_amount / order.sell_amount:
            curr_time = datetime.now()
            o.filled = curr_time
            order.filled = curr_time
            order.counterparty_id = o.id
            o.counterparty_id = order.id
            order.counterparty = [o]
            o.counterparty = [order]
            g.session.commit()

            if order.buy_amount < o.sell_amount:
                p_order = o
                buy_amount = o.buy_amount - order.sell_amount
                sell_amount = o.sell_amount - order.buy_amount
            elif o.buy_amount < order.sell_amount:
                p_order = order
                buy_amount = order.buy_amount - o.sell_amount
                sell_amount = order.sell_amount - o.buy_amount
            elif o. buy_amount == order.sell_amount or o.sell_amount == order.buy_amount:
                return
            else:
                return

            orders = {}
            orders['buy_amount'] = buy_amount
            orders['sell_amount'] = sell_amount
            orders['buy_currency'] = p_order.buy_currency
            orders['sell_currency'] = p_order.sell_currency
            orders['creator_id'] = p_order.id
            orders['sender_pk'] = p_order.sender_pk
            orders['receiver_pk'] = p_order.receiver_pk
            n_order = Order(**{f: orders[f] for f in orders})
            fill_order(n_order, txes)
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print(f"Trying to execute {len(txes)} transactions")
    print(f"IDs = {[tx['order_id'] for tx in txes]}")
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()

    if not all(tx['platform'] in ["Algorand", "Ethereum"] for tx in txes):
        print("Error: execute_txes got an invalid platform!")
        print(tx['platform'] for tx in txes)

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand"]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum"]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table
    send_tokens_algo(g.acl, algo_sk, algo_txes)
    for tx in algo_txes:
        dic = {'platform': 'Algorand',
               'receiver_pk': tx['receiver_pk'],
               'order_id': tx['order_id'],
               'tx_id': tx['tx_id']}
        tx = TX(**{f: dic[f] for f in dic})
        g.session.add(tx)
        g.session.commit()

    send_tokens_eth(g.w3, eth_sk, eth_txes)
    for tx in eth_txes:
        dic = {'platform': 'Ethereum',
               'receiver_pk': tx['receiver_pk'],
               'order_id': tx['order_id'],
               'tx_id': tx['tx_id']}
        tx = TX(**{f: dic[f] for f in dic})
        g.session.add(tx)
        g.session.commit()


""" End of Helper methods"""


@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print(f"Error: no platform provided")
            return jsonify("Error: no platform provided")
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print(f"Error: {content['platform']} is an invalid platform")
            return jsonify(f"Error: invalid platform provided: {content['platform']}")

        if content['platform'] == "Ethereum":
            # Your code here
            eth_sk, eth_pk = get_eth_keys()
            return jsonify(eth_pk)
        if content['platform'] == "Algorand":
            # Your code here
            algo_sk, algo_pk = get_algo_keys()
            return jsonify(algo_pk)


@app.route('/trade', methods=['POST'])
def trade():
    print("In trade", file=sys.stderr)
    connect_to_blockchains()
    # get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        # Your code here
        payload = content['payload']
        if payload['platform'] == 'Algorand':
            valid = algosdk.util.verify_bytes(json.dumps(payload).encode('utf-8'), content['sig'], payload['sender_pk'])
        else:
            eth_msg = eth_account.messages.encode_defunct(text=json.dumps(payload))
            valid = eth_account.Account.recover_message(eth_msg, signature=content['sig']== content['sender_pk'])
        # 1. Check the signature
        if valid:
            del payload['platform']
            payload['signature'] = content['sig']
        # 2. Add the order to the table
            order = Order(**{f: payload[f] for f in payload})
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
            if order.sell_currency == "Ethereum":
                tx = g.w3.eth.get_transaction(payload['tx_id'])
                if tx is None or tx["value"] != order.sell_amount:
                    return jsonify(False)

            if order.sell_currency == "Algorand":
                tx = indexer.search_transaction(txid=payload['tx_id'])
                if tx is None or tx.amt != order.sell_amount:
                    return jsonify(False)

            # 3b. Fill the order (as in Exchange Server II) if the order is valid
            txes = []
            fill_order(order, txes)

            # 4. Execute the transactions
            execute_txes(txes)
            return jsonify(True)
        # If all goes well, return jsonify(True). else return jsonify(False)
        else:
            log_message(payload)
            return jsonify(False)

@app.route('/order_book')
def order_book():
    fields = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk"]

    # Same as before
    lst = []
    for o in g.session.query(Order).all():
        dct = {
            'sender_pk': o.sender_pk,
            'receiver_pk': o.receiver_pk,
            'buy_currency': o.buy_currency,
            'sell_currency': o.sell_currency,
            'buy_amount': o.buy_amount,
            'sell_amount': o.sell_amount,
            'signature': o.signature}
        lst.append(dct)
    return jsonify(data=lst)


if __name__ == '__main__':
    app.run(port='5002')
