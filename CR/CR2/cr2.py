import argparse
#cefpyco(ネットワーク)のインポート
import cefpyco
# jsonやhashlibなどデータフォーマット関連のインポート
import json
#乱数生成
import random
# タイムスタンプ,小待機用
import time
# 暗号化関連
import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import hashlib


'''
0:そのまま 
[リクエスト関係]1:名前改ざん 2:不正署名 3:公開鍵改ざん
[ブロックチェーン関係] 4:index改ざん 5:Timestamp
'''

# ---引数処理--- #
parser = argparse.ArgumentParser()

parser.add_argument("forge",nargs='?',type=int,default=0,help="Forge mode (Request: 0: no forge, 1: name forge, 2: bad signature, 3: bad pubkey \n " \
"Block: 4: index forge)")
args = parser.parse_args()
print(f"Forge mode: {args.forge}")

# ---データ構造--- #
# 登録リクエストを表すクラス。
class RegisterRequest:
    def __init__(self,namespace,pubkey,signature=None):
        self.namespace = namespace
        self.pubkey = pubkey
        self.signature = signature
    
    def sign(self,sk):
        #署名対象データを作成。
        request_info = {
            "namespace":self.namespace,
            "pubkey": self.pubkey.hex() if isinstance(self.pubkey, bytes) else self.pubkey
        }
        # フォーマットを固定してutf-8ストリング化
        request_info_string = json.dumps(request_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        # 名前,公開鍵に署名。
        self.signature = sk.sign(request_info_string)

    def to_json(self):
        return {
            # ← コロンはここ！
            "namespace": self.namespace,
            # 渡されたものがbytes型ならhexに変換して返す
            "pubkey": self.pubkey.hex() if isinstance(self.pubkey, bytes) else self.pubkey,
            "signature": self.signature.hex() if isinstance(self.signature, bytes) else self.signature
        }
    
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
            "bcblocksig":self.bcblocksig.hex() if isinstance(self.bcblocksig,bytes) else self.bcblocksig
        }

# --- 署名部分 --- #
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

# --- 通信部分 --- #
def receive_interest(handle,name):
    handle.register(name)
    while True:
        info = handle.receive() 
        if info.is_succeeded and info.is_interest:
            print(f"Receive Interest :\n Name:{info.name}\n msg_org:{info.msg_org}\n")
            return info
            #handle.send_data("ccnx:/request", f"msgorg:{info.msg_org} \n",0)

def request_and_receive(handle,interest):
    name = interest.name
    message = interest.msg_org

    handle.send_interest(name,0,msg_org = message)
    print(f"Send Interest \n name: {name}:\n message:{message} \n")
    while True:
        # ccnxにしないと失敗する。理由は不明。 
        info = handle.receive()
        print("waiting Data")
        if info.is_succeeded and info.is_data:
            print("Success")
            print(info)
            return info
        
def datasend(handle,name,message,option = None):
    print(f"Sending This Data:Name:{name},\nMessage:{message}\nOption:{option}\n")
    print(message)
    if isinstance(message,dict):
        message = json.dumps(message).encode("utf-8")
    if(option):
        #データの種類を示すため。データが失敗通知か証明書かをコンテンツのmsg_orgを使って識別したいから。
        #これはInterestのmsg_orgとは別物。
        handle.send_data(name,message,0,msg_org=option)
    else:
        handle.send_data(name,message,0)

# データ変換関係 #
def bytes_to_json(byte_data):
    str_data = byte_data.decode("utf-8")
    json_data = json.loads(str_data)
    return json_data

# ---動作関係 ---#

def forge_interest(interest,forge):
    # 0の時はそのまま返す。
    if not forge:
        return interest
    
    # interest名を改ざんしますよ
    interest.name = interest.name + "/forged"
    # メッセージを取り出す
    message = bytes_to_json(interest.msg_org)
    # インタレスト名を分割
    parts = interest.name.split("/")

    #偽公開鍵、偽秘密鍵を生成
    fake_sk = ed25519.Ed25519PrivateKey.generate()
    fake_pk = fake_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    # メッセージ内部のオブジェクト
    message_object = None
    if parts[2] == "Register":
        #　登録リクエストオブジェクト生成
        register_request = RegisterRequest(**message)
        if forge == 1:
            print("Forging name")
            register_request.namespace = "/ccnx:/Content/FAKE"
        if forge == 2:
            print("Forging signature")
            register_request.sign(fake_sk)
        if forge == 3:
            print("Forging pubkey")
            register_request.pubkey = fake_pk
        
        message_object = register_request

    if parts[2] == "Block":
        block = Block(**message)
        if forge == 4:
            print("Forge index")
            block.index = 1600
        if forge == 5:
            print("Forge Timestamp")
            block.timestamp = 9999999999
        message_object = block

    message_str = json.dumps(message_object.to_json()).encode("utf-8")
    # 改ざんしたメッセージをセットし直す
    interest.msg_org = message_str

    return interest

def main():
    with cefpyco.create_handle() as handle:
        while True:
            #改ざん番号によってアプリ側で受け取るInterestを調整
            interests = []
            if(args.forge > 3):
                #ノードが二つあるため。テスト用の仮コードのため一旦シンプルに。
                for _ in range(2):
                    interests.append(receive_interest(handle,"ccnx:/BC/Block"))
            elif(args.forge > 0):
                interests.append(receive_interest(handle,"ccnx:/BC/Register"))
            else:
                return

            for interest in interests:
                interest = forge_interest(interest,args.forge)
                info = request_and_receive(handle,interest)
                true_name = info.name.replace("/forged","")
                datasend(handle,true_name,info.payload,info.msg_org)            
            
# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()