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

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX
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
    log_obj = Log(message = msg)
    g.session.add(log_obj)
    g.session.commit()
    
    return

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys

    algo_pk = "SB5D3PBO5HOEW7R3ZDQGVP3JXQ6KPB4ZY67IXAVRUXFY7CETRA3YVATE3I"
    algo_sk = "z1AfF4d0433psWNAS+b0acQDbmknKuFOePUGAudY3AqQej28LuncS347yOBqv2m8PKeHmce+i4KxpcuPiJOINw=="
    
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    w3 = Web3()
    w3.eth.account.enable_unaudited_hdwallet_features()
    print("ok2")
    acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()
    print("ok3")
    print(mnemonic_secret)
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)

    eth_pk = acct._address
    eth_sk = acct._private_key
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
    g.session.add(order)
    g.session.commit();
    
    buy_curr = order.buy_currency
    sell_curr = order.sell_currency
    buy_am = order.buy_amount
    sell_am = order.sell_amount
    send_pk = order.sender_pk
    receive_pk = order.receiver_pk
    exchange_rate = buy_am/sell_am
    
    existing = g.session.query(Order).filter(Order.filled == None, Order.buy_currency == order.sell_currency,Order.sell_currency == order.buy_currency, Order.sell_amount/Order.buy_amount >= exchange_rate).first()
    g.session.commit()
    if existing == None:
      return
    #filled
    curr_time = datetime.now()
    order.filled = curr_time
    existing.filled = curr_time
    #counterparty id
    g.session.commit()
    existing.counterparty_id = order.id
    order.counterparty_id = existing.id
    g.session.commit()



    #order can buy more
    if(existing.sell_amount <= buy_am):
      new_buy = buy_am - existing.sell_amount
      new_sell = new_buy / exchange_rate
      #Insert the order
      order_obj = Order( sender_pk=order.sender_pk,receiver_pk=order.receiver_pk, buy_currency=order.buy_currency, sell_currency=order.sell_currency, buy_amount=new_buy, sell_amount=new_sell, creator_id = order.id)
      fill_order(order_obj, txes)
    elif(existing.sell_amount>buy_am):
      new_sell = existing.sell_amount - buy_am
      new_buy = new_sell * existing.buy_amount/existing.sell_amount
      #Insert the order
      order_obj = Order( sender_pk=existing.sender_pk,receiver_pk=existing.receiver_pk, buy_currency=existing.buy_currency, sell_currency=existing.sell_currency, buy_amount=new_buy, sell_amount=new_sell, creator_id = existing.id)
      fill_order(order_obj, txes)
    
    return
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table
    
    send_tokens_algo(g.acl, algo_sk, algo_txes)
    for tx in algo_txes:
        dict = {'platform': 'Algorand','receiver_pk': tx['receiver_pk'],'order_id': tx['order_id'],'tx_id': tx['tx_id']}
        tx = TX(**{f: dic[f] for f in dict})
        g.session.add(tx)
        g.session.commit()
    send_tokens_eth(g.w3, eth_sk, eth_txes)
    for tx in eth_txes:
        dict = {'platform': 'Ethereum','receiver_pk': tx['receiver_pk'],'order_id': tx['order_id'],'tx_id': tx['tx_id']}
        tx = TX(**{f: dic[f] for f in dict})
        g.session.add(tx)
        g.session.commit()
    return

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    #print("start address")
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print(f"Error: no platform provided" )
            return jsonify("Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print(f"Error: {content['platform']} is an invalid platform" )
            return jsonify(f"Error: invalid platform provided: {content['platform']}"  )
        #print("success until here")
        # The endpoint should return a (JSON formatted) response with the exchange server’s public-key on the specified platform (either ‘Ethereum’ or ‘Algorand’).
        if content['platform'] == "Ethereum":
            #Your code here
            eth_sk,eth_pk = get_eth_keys()
            
            return jsonify(eth_pk)
        if content['platform'] == "Algorand":
            #Your code here
            algo_sk, algo_pk = get_algo_keys()
            return jsonify(algo_pk)

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
    
        

        platform = content['payload']['platform']
        msg_dict = content['payload']
        message = json.dumps(msg_dict)
        pk = content['payload']['sender_pk']
        sig = content["sig"]
        verify = False
        
        if platform == "Ethereum":
          eth_encoded_msg = eth_account.messages.encode_defunct(text=message)
          pk2 = eth_account.Account.recover_message(eth_encoded_msg,signature=sig)
          if pk == pk2:
            print( "Eth sig verifies!" )
            verify = True
          else:
            print( "Eth sig fails verification!" )
            verify = False
        elif platform == "Algorand":
          if algosdk.util.verify_bytes(message.encode('utf-8'),sig,pk):
            print( "Algo sig verifies!" )
            verify = True
          else:
            print( "Algo sig verification failed!" )
            verify = False
  
        if verify == True:
          # 1. Check the signature
          msg_dict['signature'] = sig
            # 2. Add the order to the table   
          order = Order( sender_pk=msg_dict['sender_pk'],receiver_pk=msg_dict['receiver_pk'], buy_currency=msg_dict['buy_currency'], sell_currency=msg_dict['sell_currency'], buy_amount=msg_dict['buy_amount'], sell_amount=msg_dict['sell_amount'], signature = content['sig'] )
         # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
          if order.sell_currency == "Ethereum":
            tx = g.w3.eth.get_transaction(msg_dict['tx_id'])
            if tx is None or tx["value"] != order.sell_amount:
                    return jsonify(False)

          if order.sell_currency == "Algorand":
              tx = indexer.search_transaction(txid=payload['tx_id'])
              if tx is None or tx.amt != order.sell_amount:
                  return jsonify(False)
        # 3b. Fill the order (as in Exchange Server II) if the order is valid
          txes = []
          fill_order(order, txes)
                  
                  
          execute_txes(txes)
          return jsonify(True)
        else:
          log_message(payload)
          return jsonify(False)
          

        
        
        
        
        

@app.route('/order_book')
def order_book():
    #fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk" ]
    
    existing = g.session.query(Order).all()
    result = {"data": []}

    for row in existing:
        # timestamp_str = str(row.timestamp)
        result['data'].append({'tx_id':row.tx_id ,'sender_pk': row.sender_pk,'receiver_pk': row.receiver_pk, 'buy_currency': row.buy_currency, 'sell_currency': row.sell_currency, 'buy_amount': row.buy_amount, 'sell_amount': row.sell_amount,'signature': row.signature})

    return jsonify(result)

if __name__ == '__main__':
    app.run(port='5002')
