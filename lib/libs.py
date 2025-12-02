# 共通処理の記述のため、libs.pyに関数を記述。
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

### --- クラス構造 --- ###

# 全ノードで共通に使うモデル群。
#　証明書を表すクラス。
class Cert:
    def __init__(self,namespace,pubkey,keylocator,bcsig=None):
        self.namespace = namespace
        self.pubkey = pubkey
        self.keylocator = keylocator
        self.bcsig = bcsig
    
    def sign(self,sk):
        print("Sign Cert with BCNode sk")
        cert_info ={
            "namespace":self.namespace,
            "pubkey" : self.pubkey,
            "keylocator": self.keylocator
        }
        # フォーマットを固定してutf-8ストリング化
        cert_info_string = json.dumps(cert_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        # 名前,公開鍵に署名。
        self.bcsig = sk.sign(cert_info_string)

    def verify(self,pk):
        print("Verify Cert")
        cert_info = {
            "namespace":self.namespace,
            "pubkey":self.pubkey,
            "keylocator": self.keylocator
        }
        #署名検証
        return signature_check(cert_info,self.bcsig,pk)
    
    def to_json(self):
        return{
            "namespace":self.namespace,
            "pubkey" : self.pubkey,
            "keylocator": self.keylocator,
            "bcsig":self.bcsig.hex() if isinstance(self.bcsig, bytes) else self.bcsig
        }

# Producer-Client間のモデル群
class Content:
    def __init__(self,data,keylocator=None,signature=None):
        self.data = data
        self.keylocator = keylocator
        self.signature = signature
    
    def sign(self,sk):
        print("Sign Content with Content sk")
        content_info = {
            "data":self.data,
            "keylocator":self.keylocator
        }
        # フォーマットを固定してutf-8ストリング化
        content_info_string = json.dumps(content_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        # 名前,公開鍵に署名。
        self.signature = sk.sign(content_info_string)

    def verify(self,pk):
        print("Verify Content")
        content_info = {
            "data":self.data,
            "keylocator":self.keylocator
        }
        #署名検証
        return signature_check(content_info,self.signature,pk)

    def to_json(self):
        return{
            "data":self.data,
            "keylocator":self.keylocator,
            "signature":self.signature.hex()
        }

##-- Producer-BCNode間のモデル群 --##
#登録リクエストを表すクラス。
class RegisterRequest:
    def __init__(self,namespace,pubkey,signature=None):
        self.namespace = namespace
        self.pubkey = pubkey
        self.signature = signature
    
    def sign(self,sk):
        print("Sign Register Request with Content sk")
        #署名対象データを作成。
        request_info = {
            "namespace":self.namespace,
            "pubkey": self.pubkey.hex() if isinstance(self.pubkey, bytes) else self.pubkey
        }
        # フォーマットを固定してutf-8ストリング化
        request_info_string = json.dumps(request_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        # 名前,公開鍵に署名。
        self.signature = sk.sign(request_info_string)

    def verify(self):
        print("Verify Register request")
        request_info = {
            "namespace":self.namespace,
            "pubkey": self.pubkey.hex() if isinstance(self.pubkey, bytes) else self.pubkey
        }

        pk_bytes = bytes.fromhex(self.pubkey)
        pk = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)

        return signature_check(request_info,self.signature,pk)

    def to_json(self):
        return {
            # ← コロンはここ！
            "namespace": self.namespace,
            # 渡されたものがbytes型ならhexに変換して返す
            "pubkey": self.pubkey.hex() if isinstance(self.pubkey, bytes) else self.pubkey,
            "signature": self.signature.hex() if isinstance(self.signature, bytes) else self.signature
        }


## BCNode用のモデル群 ##
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
        print("Sign Transaction with BC sk")
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
        print("Verify Transaction")
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
            "pubkey":self.pubkey.hex() if isinstance(self.pubkey,bytes) else self.pubkey,
            "bcsig": self.bcsig.hex() if isinstance(self.bcsig,bytes) else self.bcsig
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
        print("Sign Block with BCNode sk")
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
        print("Verify Block Sign")
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

###-----関数群-----###
## ---通信関係--- ##
# Interest受信関数 ##
def receive_interest(handle,name):
    
    if isinstance(name,list):
        names = name
        for name in names:
            handle.register(name)
    else:
        handle.register(name)

    while True:
        info = handle.receive() 
        if info.is_succeeded and info.is_interest:
            print("\n----------------\n")
            print(f"Receive Interest :\n Name:{info.name}\n msg_org:{info.msg_org}\n")
            print("\n----------------\n")

            return info
            #handle.send_data("ccnx:/request", f"msgorg:{info.msg_org} \n",0)

## Interest送信、データ受信関数 ##
def request_and_receive(handle,name,message = None):
    if message:
        if isinstance(message, dict):
            message = json.dumps(message).encode("utf-8")
        handle.send_interest(name,0,msg_org = message)
    else:
        handle.send_interest(name,0)

    print("\n---------------\n")
    print(f"Send Interest \n name: {name}:\n message:{message} \n")
    print("\n---------------\n")

    while True:
        # ccnxにしないと失敗する。理由は不明。 
        info = handle.receive()
        print("waiting Data")
        if info.is_succeeded and info.is_data:
            print("Success")
            print(info)
            return info

## データ送信関数 ##    
def datasend(handle,name,message,option = None):

    print("\n---------------\n")
    print(f"Sending This Data:Name:{name},\nMessage:{message}\nOption:{option}\n")
    print("\n---------------\n")

    if isinstance(message,dict):
        message = json.dumps(message).encode("utf-8")
    if(option):
        #データの種類を示すため。データが失敗通知か証明書かをコンテンツのmsg_orgを使って識別したいから。
        #これはInterestのmsg_orgとは別物。
        handle.send_data(name,message,0,msg_org=option)
    else:
        handle.send_data(name,message,0)

## BCNode限定、Block送信と結果受信関数 ##
def send_block_and_receive_result(handle,names,block_json):
    results = []
    for name in names:

        print("\n---------------\n")
        print(f"Send Block Interest \n name: {name}:\n message:{block_json} \n")
        print("\n---------------\n")

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

## ---署名、検証関係--- ##
# BCNode鍵取得関数
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
    

def keysend(handle,interest,nodename):
    print("Key Request Received\n")
    pk = get_key(nodename,"pk")
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pk_string = pk_bytes.hex()

    datasend(handle,interest.name,pk_string,"Pubkey")

# 署名検証関数
def signature_check(info,signature,pk):
    check_result = None
    # ログを視覚的にわかりやすくするため公開鍵はrawで表示
    print(f"\n-----Signature Check -----\n")

    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pk_string = pk_bytes.hex()
    print(f"pk:{pk_string}\nSignature:{signature} ")

    #フォーマットを固定してutf-8ストリング化
    info_string = json.dumps(info, sort_keys=True, separators=(",", ":")).encode("utf-8")
    #Hex形式の署名を検証可能なバイト列形式に変換
    sig_bytes = bytes.fromhex(signature)
    try:
        pk.verify(sig_bytes,info_string)
        print("Signature Check Succeeded \n")
        check_result = True
    except:
        print("Signature Check Failed \n")
        check_result = False

    print("---------------------------")

    return check_result
    
## ---データフォーマット関係 --- ##
def bytes_to_json(bytes):
    #utf-8形式のバイト列を普通のUTF-8文字列としてデコード
    str = bytes.decode('utf-8')
    #JSONとしてパース
    jsondata = json.loads(str)

    return jsondata

##--------実動作部分--------##
##---BCNode限定関数---##

# ブロック検証関数 ##
def verify_block(block,blockchain,bc_pk):
    print("----------Verify Block--------------\n")


    #インデックスを検証
    print("\n--------------------")
    print(f" NEW block Index:{block.index} \n Recent Block Index: {None if len(blockchain) == 0 else blockchain[-1].index}\n")
    if ((len(blockchain) == 0 and block.index == 0) or
    (len(blockchain) > 0 and blockchain[-1].index + 1 == block.index)):
        print("Index Valid")
    else:
        print("Index Invalid")
        return False

    #タイムスタンプを検証
    print("\n--------------------")
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
    print("\n--------------------")
    print(f"Calculated_txid:\n{transaction.calculate_txid()}\nBlock txid:\n{transaction.txid}\n")
    #Txidが一致するか
    if(transaction.calculate_txid() == transaction.txid):
        print("txid is Valid\n")
    else:
        print("txid is Invalid\n")
        return False
    
    ###----署名検証----###\
    #トランザクション署名の検証
    print("\n-------------------")
    print("Verify Tx Signature")
    if(transaction.verify_sign(bc_pk)):
        print("Transaction Sign Valid")
    else:
        print("Transaction Sign Invalid")
        return False
    
    #Blockのハッシュを検証
    print(f"Calculated_Blockhash:\n{block.calculate_hash()} \n BlockHash:\n{block.hash}\n")
    if(block.calculate_hash() == block.hash):
        print("Block Hash is Valid")
    else:
        print("Block Hash is Invalid")
        return False
    
    #ブロック署名の検証
    print("\n ---------------")
    print("Verify Block Signature")
    if(block.verify_sign(bc_pk)):
        print("Block Sign Valid")
    else:
        print("Block Sign Invalid")
        return False
    
    print("-------------------------------")
    
    return True