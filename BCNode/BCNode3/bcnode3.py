###-----インポート-----##
import cefpyco
import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
# cefpyco(ネットワーク)のインポート
import cefpyco
# jsonやhashlibなどデータフォーマット関連のインポート
import json
import hashlib
# タイムスタンプ,小待機用
import time

#関数構造のインポート(libs.pyから)
from lib.libs import (receive_interest,datasend,send_block_and_receive_result,
                  verify_block,
                  bytes_to_json,
                  get_key,keysend)
# クラス構造のインポート
from lib.libs import RegisterRequest,Transaction,Block,Cert

#ブロックチェーン
blockchain = []

##---関数---##
## 動作関係 ##

def create_block(transaction,sk):
    index = len(blockchain)
    timestamp = time.time()
    if len(blockchain) > 0:
        previous_hash = blockchain[-1].hash
    else:
        previous_hash = 0
    #ブロックインスタンス生成。
    #ハッシュ値はインスタンス生成時に自動生成。
    block = Block(index,timestamp,transaction,previous_hash)
    #ブロックに署名
    block.sign(sk)

    return block

##リクエストを受信した際の動作
def process_request(handle,interest):
    ##---自分の鍵を取り出す---##
    sk = get_key("BCNode3","sk")

    ## ---byte列(msg_org)をJSON化---###
    register_req_json = bytes_to_json(interest.msg_org)

    register_req = RegisterRequest(**register_req_json)
    ##---リクエスト検証---##
    register_req_ok = register_req.verify()
    print(f"JSON:\n{register_req_json}\n")

    #リクエスト承認時
    if(register_req_ok):
        ##---トランザクション形成---##
        transaction = Transaction(register_req.namespace,register_req.pubkey)
        transaction.sign(sk)
        transaction_json = transaction.to_json()
        print(f"transaction_json: \n {transaction_json} \n")

        ##---ブロックの生成---###
        new_block = create_block(transaction_json,sk)
        new_block_json = new_block.to_json()
        print(f"new_block_json:\n{new_block_json}\n")
		##---ブロックの送信,結果受信---##
        names = ["ccnx:/BC/Block/BCNode1/BCNode3","ccnx:/BC/Block/BCNode2/BCNode3"]
        results = send_block_and_receive_result(handle,names,new_block_json)
        print(results)

        #半数以上が賛成の場合、ブロックを正当とする。
        if(sum(results) >= len(results) * 0.5):
            blockchain.append(new_block)
            ##---トランザクションから証明書の生成,送信---##
            cert = Cert(transaction.namespace,transaction.pubkey,"ccnx:/BC/key/BCNode3")
            cert.sign(sk)
            cert_json = cert.to_json()
            datasend(handle,interest.name,cert_json,"Cert")
        else:
            datasend(handle,interest.name,"Fail : Block Voting Failed")
        
    #リクエスト否認時
    else:
        datasend(handle,interest.name,"Fail : Register Request Is Invalid")

##-----ブロックを受信時の動作------##

##受信したブロックの処理全般##
def process_block(handle,interest):
    print("Process Block\n")
    #受信したブロックデータを元にブロックインスタンス生成。この時トランザクションはJSONのまま
    block_json = bytes_to_json(interest.msg_org)
    new_block = Block(**block_json)
    print(f"recved_block_obj : \n {new_block} \n")

    #検証用の鍵を取り出す
    if("BCNode1" in interest.name):
        block_creator = "BCNode1"
    elif("BCNode2" in interest.name):
        block_creator = "BCNode2"

    bc_pk = get_key(block_creator,"pk")

    #受信したブロックを検証
    block_is_valid = verify_block(new_block,blockchain,bc_pk)
    
    if(block_is_valid):
        datasend(handle,interest.name,"Valid")
        blockchain.append(new_block)
    else:
        datasend(handle,interest.name,"Invalid")

def main():
    with cefpyco.create_handle() as handle:
        while True:## ----Interest 受信----##
            interest = receive_interest(handle,"ccnx:/BC")
            parts = interest.name.split("/")

            ## --リクエストの処理--##
            if parts[2] == "Register":
                process_request(handle,interest)
            ## --ブロックの処理--##
            elif parts[2] == "Block":
                process_block(handle,interest)
            ## --鍵要求の処理--##
            elif parts[2] == "key":
                keysend(handle,interest,parts[3])
            
            print(blockchain)

# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()