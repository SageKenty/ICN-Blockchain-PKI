# Cryptographyライブラリのインポート
import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
# cefpyco(ネットワーク)のインポート
import cefpyco
# jsonやhashlibなどデータフォーマット関連のインポート
import json
# タイムスタンプ,小待機用
import time

#---Data Structures---#
# 登録リクエストを表すクラス。
class RegisterRequest:
    def __init__(self,namespace,pubkey):
        self.namespace = namespace
        self.pubkey = pubkey
        self.signature = None
    
    def sign(self,sk):
        #署名対象データを作成。
        request_info = {
            "namespace":self.namespace,
            "pubkey":self.pubkey.hex()
        }
        # フォーマットを固定してutf-8ストリング化
        request_info_string = json.dumps(request_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        # 名前,公開鍵に署名。
        self.signature = sk.sign(request_info_string)

    def to_json(self):
        return {
            # ← コロンはここ！
            "namespace": self.namespace,
            # jsonのためにHex文字形式で送信
            "pubkey": self.pubkey.hex(),
            "signature": self.signature.hex()
        }

# 送信用データを表すクラス
class Content:
    def __init__(content_data,keylocator):
        content_data = None
        keylocator = None
        signature = None
    
    def sign(self,sk):
        content_info = {
            "content_data":self.content_data,
            "keylocator":self.keylocator
        }
        # フォーマットを固定してutf-8ストリング化
        content_info_string = json.dumps(content_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        # 名前,公開鍵に署名。
        self.signature = sk.sign(content_info_string)

    def to_json(self):
        return{
            "data":self.data,
            "keylocator":self.keylocator,
            "signature":self.signature
        }

class Cert:
    def __init__(self,namespace,pubkey,keylocator,bcsig=None):
        self.namespace = namespace
        self.pubkey = pubkey
        self.keylocator = keylocator
        self.bcsig = bcsig
    
    def to_json(self):
        return{
            "namespace":self.namespace,
            "pubkey" : self.pubkey,
            "keylocator": self.keylocator,
            "bcsig":self.bcsig.hex()
        }


# 送受信関数
def request_and_receive(handle,name,message = None):
    # インスタンスを定義
    print(f"Send Interest \n name: {name}:\n message:{message} \n")
    handle.send_interest(name,0,msg_org = json.dumps(message).encode("utf-8"))
    while True:
        # ccnxにしないと失敗する。理由は不明。 
        info = handle.receive()
        if info.is_succeeded:
            print("Success")
            print(info)
            return info


# データフォーマット

def bytes_to_json(bytes):
    #utf-8形式のバイト列を普通のUTF-8文字列としてデコード
    str = bytes.decode('utf-8')
    #JSONとしてパース
    jsondata = json.loads(str)

    return jsondata
##--------実動作部分--------##

def main():
    with cefpyco.create_handle() as handle:
        #　名前空間情報
        namespace = "ccnx:/t"
        #----鍵情報生成----#
        # 鍵ペア生成
        content_sk = ed25519.Ed25519PrivateKey.generate()
        #pkはraw形式で生成。(Interest容量節約のため　Raw形式)
        content_pk = content_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        #登録リクエストの生成
        register_request = RegisterRequest(namespace,content_pk)

        ###----署名生成----###
        register_request.sign(content_sk)
        ### ---変換---###
        # 登録リクエストオブジェクトをJSON文字列に変換
        register_request_json = register_request.to_json()
        #登録リクエスト送信。
        result = request_and_receive(handle,"ccnx:/BC/Register",register_request_json)
        print(result)
        #リクエストに成功したら
        print(f"result.msg_org:{result.msg_org}")
        if(result.msg_org.decode('utf-8') == "Cert"):
            cert_json = bytes_to_json(result.payload)
            cert = Cert(**cert_json)
            print(f"Cert:{cert_json}")
            print(cert)

        ##失敗したらエラーにする。
        else:
            raise Exception("Request Rejected")



# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()