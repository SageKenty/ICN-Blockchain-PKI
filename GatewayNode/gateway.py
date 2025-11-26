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


# ---引数処理--- #
parser = argparse.ArgumentParser()

parser.add_argument("forge",nargs='?',type=int,default=0,help="Forge mode (0: no forge, 1: name forge, 2: bad signature, 3: bad pubkey)")
parser.add_argument("node",nargs='?',type=int,default=random.randint(1,3),help="Node number (1-3)")
args = parser.parse_args()
print(f"Forge mode: {args.forge} Node number: {args.node}")

#---データ構造---#
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

## Cefpyco関係 ##
def request_and_receive(handle,name,message = None):
    # インスタンスを定義
    print(f"Send Interest \n name: {name}:\n message:{message} \n")
    handle.send_interest(name,0,msg_org = message)
    while True:
        # ccnxにしないと失敗する。理由は不明。 
        info = handle.receive()
        if info.is_succeeded:
            print("Success")
            print(info)
            return info

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
    handle.register("ccnx:/BC/Register")
    while True:
        info = handle.receive() 
        if info.is_succeeded and info.name == "ccnx:/BC/Register":
            print(f"Receive Interest :\n Name:{info.name}\n msg_org:{info.msg_org}\n")
            return info
            #handle.send_data("ccnx:/request", f"msgorg:{info.msg_org} \n",0)

# データ変換関係 #
def bytes_to_json(byte_data):
    str_data = byte_data.decode("utf-8")
    json_data = json.loads(str_data)
    return json_data

# 処理関係 #

def forge_interest(interest,forge):
    # 0の時はそのまま返す。
    if not forge:
        return interest
    
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

    if parts[2] == "Register":
        #　登録リクエストオブジェクト生成
        register_request = RegisterRequest(**message)
        if forge == 1:
            print("Forging name")
            register_request.namespace = "/ccnx:/BC/Register/FAKE"
        elif forge == 2:
            print("Forging signature")
            register_request.sign(fake_sk)
        elif forge == 3:
            print("Forging pubkey")
            register_request.pubkey = fake_pk
        
    message_str = json.dumps(register_request.to_json()).encode("utf-8")
    # 改ざんしたメッセージをセットし直す
    interest.msg_org = message_str

    return interest
    
##--------実動作部分--------##

def main():
    with cefpyco.create_handle() as handle:
        while True:
            #Interestを受信、(登録要求のみアプリケーション側にて取り扱う。)
            interest = receive_interest(handle)
            # Broadcast用の名前
            broadcast_name = "ccnx:/BC/Register/BCNode<n>"
            # ランダムに送り先を決める
            broadcast_name = broadcast_name.replace("<n>",str(args.node))
            #テスト用にInterestを加工する。
            '''
            0:そのまま 
            [リクエスト関係]1:名前改ざん 2:不正署名 3:公開鍵改ざん
            [ブロックチェーン関係]
            '''

            interest = forge_interest(interest,args.forge) 
            # リクエストを送信し、結果を待つ
            info = request_and_receive(handle,broadcast_name,interest.msg_org)
            # 得られた結果を転送する。
            print(info.msg_org)
            datasend(handle,interest.name,info.payload,info.msg_org)

# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()