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
import time
import math
import sys
import traceback
from models import Base, Order, Log
import gen_keys

#  make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
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
        print(g.icl)#added


    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True

    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = gen_keys.w3
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()

""" End of pre-defined methods """

""" Helper Methods (skeleton code for you to implement) """
def check_sig(payload,sig):
    #The signature should be on the entire payload dictionary not just the single “message” field.
    #json.dump convert python dic to json string(while message)
    message_payLoad = json.dumps(payload)
    result = False

    if payload.get('sell_currency') == 'Ethereum':
        #encode the payLoad message
        eth_encoded_msg =  eth_account.messages.encode_defunct(text = message_payLoad)
        #if the signature verifies, the recover func will return the pk so we can Check
        #if the result of the func equal to pk
        if eth_account.Account.recover_message(eth_encoded_msg,signature = sig) == payload.get('sender_pk'):
            result = True #Should only be true if signature validates
    if payload.get('sell_currency')  == 'Algorand':
        # verify func to veryfy Algorand signature
        if algosdk.util.verify_bytes(message_payLoad.encode('utf-8'),sig,payload.get('sender_pk')):
            result = True #Should only be true if signature validates
    return result

def log_message(message_dict):
    msg = json.dumps(message_dict)

    # Add message to the Log table
    log = Log(message = msg)
    g.session.add(log)
    g.session.commit()
    return

def get_algo_keys():

    # Generate or read (using the mnemonic secret)
    # the algorand public/private keys
    algo_sk = gen_keys.sk
    algo_pk = gen_keys.pk
    return algo_sk, algo_pk


def get_eth_keys():
    #w3 = Web3()

    #  Generate or read (using the mnemonic secret)
    # the ethereum public/private keys
    eth_sk = gen_keys.eth_sk
    eth_pk = gen_keys.eth_pk

    return eth_sk, eth_pk

def fill_order(order,txes=[]):#,
    # 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    #fill the order by matching it with an existing order/orders in the databse
    #get all unfilled existing orders in query
    #create object new_order
    new_order = Order(buy_currency= order.get('buy_currency'),
                    sell_currency= order.get('sell_currency'),
                    buy_amount= order.get('buy_amount'),
                    sell_amount= order.get('sell_amount'),
                    sender_pk= order.get('sender_pk'),
                    receiver_pk= order.get('receiver_pk'),
                    creator_id = order.get('creator_id'),
                    tx_id = order.get('tx_id'))
    g.session.add(new_order)
    g.session.commit()

    query = g.session.query(Order).filter(Order.filled == None).all()
    print(type(query))
    print("Unfilled order query#:", len(query))
    i = 0
    for existing_order in query:
        #existing_order_validation = False
        i=i+1
        print("query #:", i)
        condition1 = existing_order.buy_currency == new_order.sell_currency
        condition2 = existing_order.sell_currency == new_order.buy_currency
        condition3 = existing_order.sell_amount* new_order.sell_amount >= new_order.buy_amount * existing_order.buy_amount
        #left buy amount > right sell amount
        condition4 = new_order.buy_amount > existing_order.sell_amount
        #left sell amount < right buy amount
        condition5 = new_order.sell_amount < existing_order.buy_amount
        #matching requirments for exchange
        if condition1 and condition2  and condition3:
            print("check condition 1,2,3 for query #:", i)
            existing_order.filled = new_order.filled = datetime.now()
            existing_order.counterparty_id = new_order.id
            new_order.counterparty_id = existing_order.id

   
            if condition4:
                print("check condition 4 for query #:", i)
                child_order = {'buy_currency': new_order.buy_currency,
                                'sell_currency': new_order.sell_currency,
                                'buy_amount': new_order.buy_amount - existing_order.sell_amount,
                                'sell_amount': new_order.sell_amount * (new_order.buy_amount - existing_order.sell_amount)/new_order.buy_amount,
                                'sender_pk': new_order.sender_pk,
                                'receiver_pk' : new_order.receiver_pk,
                                'creator_id': new_order.id}
                #try to fill the child order
                #create two transactions for a matched pair of orders
                new_tx1 = {"platform": new_order.buy_currency,
                            "receiver_pk": new_order.receiver_pk,
                            "order_id": new_order.id,
                            "tx_id": new_order.tx_id,
                            "amount":existing_order.sell_amount

                            }

                new_tx2 = {"platform": existing_order.buy_currency,
                            "receiver_pk": existing_order.receiver_pk,
                            "order_id": existing_order.id,
                            "tx_id": existing_order.tx_id,
                            "amount":existing_order.buy_amount

                            }
                txes.append(new_tx1)
                txes.append(new_tx2)

                print("try to fill child_order in C4:")
                fill_order(child_order, txes)

                #one existing order is not fully satisfied
            elif condition5:
                print("check condition 5 for query #:", i)
                child_order = Order(buy_currency= existing_order.buy_currency,
                                    sell_currency= existing_order.sell_currency,
                                    buy_amount= existing_order.buy_amount - new_order.sell_amount,
                                    sell_amount= existing_order.sell_amount * (existing_order.buy_amount - new_order.sell_amount)/existing_order.buy_amount,
                                    sender_pk= existing_order.sender_pk,
                                    receiver_pk = existing_order.receiver_pk,
                                    creator_id= existing_order.id)
                #add child-order to the database
                print("add child_order to DB in C5:")
                g.session.add(child_order)
                print("add child_order to DB in C5 complete!:")
                g.session.commit()
                #create two transactions for a matched pair of orders
                new_tx1 = {"platform": new_order.buy_currency,
                            "receiver_pk": new_order.receiver_pk,
                            "order_id": new_order.id,
                            "tx_id": new_order.tx_id,
                            "amount":new_order.buy_amount

                    }

                new_tx2 = {"platform": existing_order.buy_currency,
                            "receiver_pk": existing_order.receiver_pk,
                            "order_id": existing_order.id,
                            "tx_id": existing_order.tx_id,
                            "amount":new_order.sell_amount

                    }
                txes.append(new_tx1)
                txes.append(new_tx2)

            else:
                print("order is filled:", i)
                    #two orders are match and no child order need to be created
                    #create two transactions for a matched pair of orders
                new_tx1 = {"platform": new_order.buy_currency,
                            "receiver_pk": new_order.receiver_pk,
                            "order_id": new_order.id,
                            "tx_id": new_order.tx_id,
                            "amount":new_order.buy_amount

                    }

                new_tx2 = {"platform": existing_order.buy_currency,
                            "receiver_pk": existing_order.receiver_pk,
                            "order_id": existing_order.id,
                            "tx_id": existing_order.tx_id,
                            "amount":existing_order.buy_amount

                    }

                txes.append(new_tx1)
                txes.append(new_tx2)


            #only fill one time
            print("An original order is finally filled!")
            break
    return txes

    #pass

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

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]#sublist of txes
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    print("before call send_tokens_eth")
    try:
        tx_id_eth = send_tokens_eth(g.w3, eth_sk, eth_txes)
    except Exception as e:
        import traceback
        print(e)

    print("before call send_tokens_algo")
    try:
        tx_id_algo = send_tokens_algo(g.acl, algo_sk, algo_txes)
    except Exception as e:
        import traceback
        print(e)
    print("before add tx to TX table")
    #add all transactions to TX table
    for tx in txes:
        new_TX = TX(platform = tx.get("platform"),
                    receiver_pk = tx.get("receiver_pk"),
                    order_id = tx.get("order_id"),
                    tx_id = tx.get("tx_id"))
        g.session.add(new_TX)
        g.session.commit()


    pass

""" End of Helper methods"""

@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )

        if content['platform'] == "Ethereum":
            #
            eth_pk = gen_keys.eth_pk
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            #
            algo_pk = gen_keys.pk
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    txes = []
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    #get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount","platform","sell_amount", "sender_pk", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]

        #retrieve data from json fille
        payLoad = content.get('payload')
        s_pk = payLoad.get('sender_pk')
        r_pk = payLoad.get('receiver_pk')
        #base16Int = int(payLoad.get('tx_id'), 16)
        #s = .encode('utf-8')
        tx_id = payLoad.get('tx_id')
        sell_curr = payLoad.get('sell_currency')
        buy_curr = payLoad.get('buy_currency')
        buy_amt = payLoad.get('buy_amount')
        sell_amt = payLoad.get('sell_amount')
        platform = payLoad.get('platform')
        sig = content.get('sig')
        message_payLoad = json.dumps(payLoad)

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

        # 

        # 1. Check the signature
        if check_sig(payLoad, sig):
        #create new order (dict)based on post json file
            new_order = {"buy_currency": buy_curr,
                    "sell_currency": sell_curr,
                    "buy_amount": buy_amt,
                    "sell_amount": sell_amt,
                    "sender_pk": s_pk,
                    "receiver_pk": r_pk,
                    "signature" : sig,
                    "tx_id": tx_id}
        # 2. Add the order to the table
            print(new_order)
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
            if sell_curr == "Ethereum":
                try:
                    # base16Int = int(tx_id,16)
                    # hash_id = hex(base16Int)
                    tx = g.w3.eth.get_transaction(tx_id)
                except Exception as e:
                    import traceback
                    print(e)
                    #return jsonify(False)
                print(tx)
                if tx["value"] == sell_amt and tx["to"] == gen_keys.eth_pk and tx["from"] == s_pk:
                    #fill
                    print("eth backed payment")
                    returned_txes_list = fill_order(new_order,txes)
                    #print(jsonify(returned_txes_list))
                        #execute
                    if len(returned_txes_list) != 0:
                        execute_txes(returned_txes_list)
                        return jsonify(True)

            elif sell_curr == "Algorand":
                # base16Int = int(tx_id,16)
                # hash_id = hex(base16Int)
                #time.sleep(5)
                try:
                    response = g.icl.search_transactions(txid = tx_id)
                except Exception as e:
                    import traceback
                    print(e)
                    #return jsonify(False)

                #print(type(response))
                print(json.dumps(response))
                if len(response["transactions"]) != 0:
                    tx = response["transactions"][0]
                    if tx["payment-transaction"]["amount"] == sell_amt and tx["payment-transaction"]["receiver"] == gen_keys.pk and tx["sender"] == s_pk:
                    #fill
                        print("algorand backed payment")
                        returned_txes_list = fill_order(new_order,txes)
                        #print(jsonify(returned_txes_list))
                        #execute
                        if len(returned_txes_list) != 0:
                            execute_txes(returned_txes_list)
                            return jsonify(True)
                    # else:
                    #     return jsonify(False)
        else:
        #add data to Log
            new_log = Log(message = message_payLoad)
            g.session.add(new_log)
            g.session.commit()
            return jsonify( True )
     
    return jsonify(False)

@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk", "sender_pk" ]

    # Same as before
    values = []
    data = {'data': values}
    query = g.session.query(Order).all()
    for exit_order in query:
        value = {'sender_pk': exit_order.sender_pk,
                 'receiver_pk':exit_order.receiver_pk,
                 'buy_currency':exit_order.buy_currency,
                 'sell_currency':exit_order.sell_currency,
                 'buy_amount':exit_order.buy_amount,
                 'sell_amount':exit_order.sell_amount,
                 'signature': exit_order.signature,
                 'tx_id': exit_order.tx_id
                }
        values.append(value)

    jsonfied_data = json.dumps(data)
    return jsonfied_data
    pass

if __name__ == '__main__':
    #debug = True
    app.run(port='5002')
