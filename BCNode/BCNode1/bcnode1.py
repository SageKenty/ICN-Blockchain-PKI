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

##----グローバル変数---##

##------クラス構造-------###

#ブロックチェーン
blockchain = []

# トランザクションを表すクラス。
class Transaction: 
    def __init__(self,namespace,pubkey,txid = None,bcsig=None):
        self.namespace = namespace
        self.pubkey = pubkey
        self.txid = txid if txid else self.calculate_txid()
        self.bcsig = bcsig

    def calculate_txid(self):
        request_info = {
            "namespace" : self.namespace,
            "pubkey": self.pubkey
        }
        # フォーマットを取り揃えてハッシュ化
        request_info_string = json.dumps(request_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(request_info_string).hexdigest()
    
    def sign(self,sk):
        tx_info ={
            "txid":self.txid,
            "namespace" : self.namespace,
            #こちらはそのまま文字列をJSONから取得しているため。
            "pubkey": self.pubkey
        }
        # フォーマットを固定してutf-8ストリング化
        tx_info_string = json.dumps(tx_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        # 名前,公開鍵に署名。
        self.bcsig = sk.sign(tx_info_string)
    
    def verify_sign(self,pk):
        # 署名検証
        tx_info ={
            "txid":self.txid,
            "namespace" : self.namespace,
            #こちらはそのまま文字列をJSONから取得しているため。
            "pubkey": self.pubkey
        }
        # 署名をチェック
        return signature_check(tx_info,self.bcsig,pk)


    def to_json(self):
        return{
            "txid":self.txid,
            "namespace":self.namespace,
            "pubkey":self.pubkey,
            "bcsig": self.bcsig.hex()
        }
        
# ブロックを表すクラス。
class Block:
    def __init__(self,index,timestamp,transaction,previous_hash,hash=None,bcblocksig=None):
        self.index = int(index)
        self.timestamp = float(timestamp)
        self.previous_hash = previous_hash
        #transactionはあらかじめJSON形式で渡す。
        self.transaction = transaction
        #hash値が渡されていればそのまま入れる、なければ計算。
        self.hash = hash if hash else self.calculate_hash()
        self.bcblocksig = bcblocksig

    def calculate_hash(self):
        block_info = {
            "index": self.index,
            "timestamp": str(self.timestamp),
            "transaction": self.transaction,
            "previous_hash": self.previous_hash
        }
        # フォーマットを取り揃えてハッシュ化
        block_info_string = json.dumps(block_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(block_info_string).hexdigest()
    
    def sign(self,sk):
        block_info = {
            "index": self.index,
            "timestamp": str(self.timestamp),
            "transaction": self.transaction,
            "previous_hash": self.previous_hash,
            "hash":self.hash
        }
        print(f"sig_info:\n{block_info}\n")
        #フォーマットを固定してutf-8ストリング化
        block_info_string = json.dumps(block_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        # 名前,公開鍵に署名。
        self.bcblocksig = sk.sign(block_info_string)
        print(f"bcblocksig:\n{self.bcblocksig.hex()}\n")
    
    def verify_sign(self,pk):
        block_info = {
            "index": self.index,
            "timestamp": str(self.timestamp),
            "transaction": self.transaction,
            "previous_hash": self.previous_hash,
            "hash":self.hash
        }
        #署名チェック
        return signature_check(block_info,self.bcblocksig,pk)

    
    def to_json(self):
        return{
            "index": self.index,
            "timestamp": str(self.timestamp),
            "transaction": self.transaction,
            "previous_hash": self.previous_hash,
            "hash":self.hash,
            "bcblocksig":self.bcblocksig.hex()
        }
    
class Cert:
    def __init__(self,namespace,pubkey,keylocator,bcsig=None):
        self.namespace = namespace
        self.pubkey = pubkey
        self.keylocator = keylocator
        self.bcsig = bcsig
    
    def sign(self,sk):
        cert_info ={
            "namespace":self.namespace,
            "pubkey" : self.pubkey,
            "keylocator": self.keylocator
        }
        # フォーマットを固定してutf-8ストリング化
        cert_info_string = json.dumps(cert_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        # 名前,公開鍵に署名。
        self.bcsig = sk.sign(cert_info_string)
    
    def to_json(self):
        return{
            "namespace":self.namespace,
            "pubkey" : self.pubkey,
            "keylocator": self.keylocator,
            "bcsig":self.bcsig.hex()
        }


##---関数---##
##---Interestを送信して受信する--##
## Cefpyco関係 ##

def send_block_and_receive_result(handle,names,block_json):
    results = []
    for name in names:
        print(f"Send Block Interest \n name: {name}:\n message:{block_json} \n")
        handle.send_interest(name,0,msg_org = json.dumps(block_json).encode("utf-8"))
    while len(results) < len(names):
        info = handle.receive()
        if info.is_succeeded:
            print(info)
            if(info.payload.decode('utf-8') == "Valid"):
                results.append(True)
            elif(info.payload.decode('utf-8') == "Invalid"):
                results.append(False)
            else:
                raise ValueError("Invalid Result Responce")
    
    return results
                
        

def datasend(handle,name,message,option = None):
    print(message)
    if isinstance(message,dict):
        message = json.dumps(message).encode("utf-8")
    if(option):
        #データの種類を示すため。データが失敗通知か証明書かをコンテンツのmsg_orgを使って識別したいから。
        #これはInterestのmsg_orgとは別物。
        handle.send_data(name,message,0,msg_org=option)
    else:
        handle.send_data(name,message,0)

def receive_interest(handle):
    handle.register("ccnx:/BC")
    while True:
        info = handle.receive() 
        if info.is_succeeded:
            print(f"Receive Interest :\n Name:{info.name}\n msg_org:{info.msg_org}\n")
            return info
            #handle.send_data("ccnx:/request", f"msgorg:{info.msg_org} \n",0)

## 署名関係 ##
def get_key(Nodename,key_type):
    # 自由なファイル名で保存していてOK
    if (key_type == "sk"):
        filename = "./keys/ed25519_BCNode_sk.pem"
        filename = filename.replace("BCNode",Nodename)
        with open(filename, "rb") as f:
            sk = serialization.load_pem_private_key(f.read(), password=None)
            return sk
    
    if (key_type == "pk"):
        filename = "./keys/ed25519_BCNode_pk.pem"
        filename = filename.replace("BCNode",Nodename)
        with open(filename, "rb") as f:
            pk = serialization.load_pem_public_key(f.read())
            return pk
    
    else:
        raise ValueError("Invalid Key Type")

def signature_check(info,signature,pk):
    #フォーマットを固定してutf-8ストリング化
    info_string = json.dumps(info, sort_keys=True, separators=(",", ":")).encode("utf-8")
    #Hex形式の署名を検証可能なバイト列形式に変換
    sig_bytes = bytes.fromhex(signature)
    try:
        pk.verify(sig_bytes,info_string)
        return True
    except:
        return False

##データフォーマット関係 ##
            
def bytes_to_json(bytes):
    #utf-8形式のバイト列を普通のUTF-8文字列としてデコード
    str = bytes.decode('utf-8')
    #JSONとしてパース
    jsondata = json.loads(str)

    return jsondata

## 動作関係 ##

def verify_request(requestdata):
    ##----公開鍵復元----##
    #JSONから公開鍵を取り出す
    content_pubkey_hex = requestdata['pubkey']
    content_pubkey_bytes = bytes.fromhex(content_pubkey_hex)
    #公開鍵をcontent_pkとしてbyte列から復元
    pk = ed25519.Ed25519PublicKey.from_public_bytes(content_pubkey_bytes)
    #確認用
    #print(f"pubkey(Cryptography Object):\n{pk}\n")

    ##----署名検証----##
    # データを取り出し、検証用にフォーマット
    request_info = {
        "namespace":requestdata['namespace'],
        "pubkey":requestdata['pubkey']
    }

    #署名検証
    return signature_check(request_info,requestdata['signature'],pk)

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
    #テスト用に改変してみる
    #block.hash = "aaaa"
    #block.sign(seqlet key)
    block.sign(sk)

    return block

##リクエストを受信した際の動作
def process_request(handle,interest):
    ##---自分の鍵を取り出す---##
        sk = get_key("BCNode1","sk")
        ## ---byte列(msg_org)をJSON化---###
        #print(interest)
        register_req_json = bytes_to_json(interest.msg_org)
        ##---リクエスト検証---##
        register_req_ok = verify_request(register_req_json)

        print(f"JSON:\n{register_req_json}\n")

        #リクエスト承認時
        if(register_req_ok):
            ##---トランザクション形成---##
            transaction = Transaction(register_req_json['namespace'],register_req_json['pubkey'])
            transaction.sign(sk)
            transaction_json = transaction.to_json()
            print(f"transaction_json: \n {transaction_json} \n")

            ##---ブロックの生成---###
            new_block = create_block(transaction_json,sk)
            new_block_json = new_block.to_json()
            print(f"new_block_json:\n{new_block_json}\n")

            ##---ブロックの送信,結果受信---##
            names = ["ccnx:/BC/Block/BCNode2/BCNode1","ccnx:/BC/Block/BCNode3/BCNode1"]
            results = send_block_and_receive_result(handle,names,new_block_json)
            print(results)

            #半数以上が賛成の場合、ブロックを正当とする。
            if(sum(results) >= len(results) * 0.5):
                blockchain.append(new_block)

                ##---トランザクションから証明書の生成,送信---##
                cert = Cert(transaction.namespace,transaction.pubkey,"ccnx:/BC/key/BCNode1")
                cert.sign(sk)
                cert_json = cert.to_json()
                datasend(handle,interest.name,cert_json,"Cert")
            else:
                datasend(handle,interest.name,"Fail : Block Voting Failed")

        #リクエスト否認時
        else:
            datasend(handle,interest.name,"Fail : Register Request Is Invalid")

##-----ブロックを受信時の動作------##

#ブロックの検証
def verify_block(block,bc_pk):
    print("Verify Block\n")
    #インデックスを検証
    if ((len(blockchain) == 0 and block.index == 0) or
    (len(blockchain) > 0 and blockchain[-1].index + 1 == block.index)):
        print("Index Valid")
    else:
        print("Index Invalid")
        return False

    #Blockのハッシュを検証
    print(f"Calculated_Blockhash:\n{block.calculate_hash()}\n vs. \n BlockHash:\n{block.hash}\n")
    if(block.calculate_hash() == block.hash):
        print("Block Hash is Valid")
    else:
        print("Block Hash is Invalid")
        return False
    
    #タイムスタンプを検証
    now_time = time.time()
    print(f"NOW(UNIX TIME):\n{now_time} \n Block timestamp:\n{block.timestamp}\n")
    #未来過ぎないか。 
    if(now_time > block.timestamp):
        print("Timestamp is Valid\n")
    else:
        print("Timestamp is Invalid\n")
        return False
    
    #ブロック内トランザクションの検証
    #トランザクションオブジェクトを受信したブロック内のJSONのトランザクションから取り出す
    transaction = Transaction(**block.transaction)

    #TxIDの検証
    print(f"Calculated_txid:\n{transaction.calculate_txid()} \n vs. \nBlock txid:\n{transaction.txid}\n")
    #Txidが一致するか
    if(transaction.calculate_txid() == transaction.txid):
        print("txid is Valid\n")
    else:
        print("txid is Invalid\n")
        return False
    
    ###----署名検証----###\
    #トランザクション署名の検証
    print("Verify Tx Signature")
    if(transaction.verify_sign(bc_pk)):
        print("Transaction Sign Valid")
    else:
        print("Transaction Sign Invalid")
        return False
    
    #ブロック署名の検証
    print("Verify Block Signature")
    if(block.verify_sign(bc_pk)):
        print("Block Sign Valid")
    else:
        print("Block Sign Invalid")
        return False
    
    return True

##受信したブロックの処理全般##
def process_block(handle,interest):
    print("Process Block\n")
    #受信したブロックデータを元にブロックインスタンス生成。この時トランザクションはJSONのまま
    block_json = bytes_to_json(interest.msg_org)
    new_block = Block(**block_json)
    print(f"recved_block_obj : \n {new_block} \n")

    #検証用の鍵を取り出す
    if("BCNode2" in interest.name):
        block_creator = "BCNode2"
    elif("BCNode3" in interest.name):
        block_creator = "BCNode3"

    bc_pk = get_key(block_creator,"pk")

    #受信したブロックを検証
    block_is_valid = verify_block(new_block,bc_pk)
    
    if(block_is_valid):
        datasend(handle,interest.name,"Valid")
        blockchain.append(new_block)
    else:
        datasend(handle,interest.name,"Invalid")

def keysend(handle,interest,nodename):
    print("Key Request Received\n")
    pk = get_key(nodename,"pk")
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pk_string = pk_bytes.hex()
    datasend(handle,interest.name,pk_string,"Pubkey")

def main():
    with cefpyco.create_handle() as handle:
        while True:## ----Interest 受信----##
            interest = receive_interest(handle)
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