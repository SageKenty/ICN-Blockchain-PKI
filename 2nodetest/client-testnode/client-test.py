# Cryptographライブラリのインyポート
import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
# cefpyco(ネットワーク)のインポート
import cefpyco
# jsonやhashlibなどデータフォーマット関連のインポート
import json
import hashlib
import base64
# タイムスタンプ用
import time

#---Data Structures---#
# 登録リクエストを表すクラス。
class RegisterRequest:
    def __init__(self):
        self.namespace = None
        self.pubkey = None
        self.signature = None
    
    def to_json(self):
        return {
            "namespace": self.namespace,
            #jsonのためにbase64形式で送信。
            "pubkey": base64.b64encode(self.pubkey).decode(),
            "signature":  base64.b64encode(self.signature).decode()
        }

## --本来はBC Nodeの仕事だが、今回はInterestにブロックが載るかのテストのためここで定義。　--##

# トランザクションを表すクラス。
class Transaction: 
    def __init__(self,namespace,pubkey):
        self.namespace = namespace
        self.pubkey = pubkey
        self.txid = self.calculate_txid()
        self.bcnode_sig = None

    def calculate_txid(self):
        tx_data = {
            "namespace" : self.namespace,
            "pubkey": base64.b64encode(self.pubkey).decode()
        }
        # ハッシュ化
        tx_data_string = json.dumps(tx_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(tx_data_string).hexdigest()
    def to_json(self):
        return{
            "txid":self.txid,
            "namespace":self.namespace,
            "pubkey":base64.b64encode(self.pubkey).decode(),
            "bcnode_sig": base64.b64encode(self.bcnode_sig).decode()
        }

# ブロックを表すクラス。
class Block:
    def __init__(self, index, previous_hash, timestamp, transaction, bcnode_sig):
        self.index = index
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.transaction = transaction
        self.selfhash = self.calculate_hash()
        self.bcnode_sig = bcnode_sig

## --- Functions --- ##
# 署名を生成する関数

# テスト用の送受信関数
def send_and_receive(message):
    # Cefpycoを利用するためのハンドルを定義。
    with cefpyco.create_handle() as handle:
        handle.send_interest("ccnx:/test",0)
        handle.send_interest("ccnx:/request",0,msg_org = json.dumps(message).encode("utf-8"))
        while True:
            # ccnxにしないと失敗する。理由は不明。 
            info = handle.receive()
            if info.is_succeeded:
                print("Success")
                print(info)
            time.sleep(1)

##---main関数。主にここで動かす---##

def main():
    #登録リクエストを作る
    register_request = RegisterRequest()
    #　名前空間情報
    register_request.namespace = "ccnx:/request"
    #----鍵情報生成----#
    # 鍵ペア生成
    content_sk = ed25519.Ed25519PrivateKey.generate()
    #pkはraw形式で生成。(Interest容量節約のため　Raw形式)
    content_pk = content_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    # pkを表示。
    print(f"pubkey_raw:{content_pk} \n")
    # 生成した公開鍵を登録リクエストにセット(クラスにセット)
    register_request.pubkey = content_pk

    ###----署名生成----###
    # 署名対象データを作成(UTF-8)
    sign_data = {
        "namespace":register_request.namespace,
        # 公開鍵(jsonフォーマットに整形するためにpythonで扱えるストリングにする。)
        "pubkey":base64.b64encode(register_request.pubkey).decode("utf-8")
    }
    # フォーマットを固定してutf-8ストリング化
    sign_data_string = json.dumps(sign_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    # 名前,公開鍵に署名。
    register_request.signature = content_sk.sign(sign_data_string)
    
    ### ---変換---###
    # 登録リクエストオブジェクトをJSON文字列に変換
    register_request_json = register_request.to_json()
    # JSON文字列を表示
    print(f"Register Request JSON:\n{register_request_json}\n")
    ## Interestを送信し、受信する。
    #send_and_receive(register_request_json)

    ## --ここからはBC Nodeの仕事だが、テストのために擬似的に再現-- ##
    #このファイルでは実験用にトランザクションをリクエストから生成
    transaction = Transaction(register_request.namespace,register_request.pubkey)
    ### --BC Node署名(本当はBC Nodeの仕事) -- ##
    #BC Nodeの公開鍵と秘密鍵生成(このファイルではテスト用にそうしてる)
    bcnode_sk = ed25519.Ed25519PrivateKey.generate()

    bcsign_data = {
        "txid": transaction.txid,
        "namespace": transaction.namespace,
        "pubkey":base64.b64encode(transaction.pubkey).decode()
    }
    bcsign_data_string = json.dumps(bcsign_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    transaction.bcnode_sig = bcnode_sk.sign(bcsign_data_string)
    #トランザクションオブジェクト表示
    # 登録リクエストオブジェクトをJSON文字列に変換
    transaction_json = transaction.to_json()
    # JSON文字列を表示
    print(f"Register Request JSON:\n{transaction_json}\n")
    send_and_receive(transaction_json)

# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()