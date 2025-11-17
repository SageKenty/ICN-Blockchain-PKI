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
# os関連。モックデータ作成用にurandomを使用したいから。別用途にも利用する可能性あり
import os

#---グローバル変数---#
cert = None #証明書


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
    def __init__(self,content_data):
        self.content_data = content_data
        self.keylocator = None
        self.signature = None
    
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
            "data":self.content_data,
            "keylocator":self.keylocator,
            "signature":self.signature.hex()
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

##-----関数-----##

# 送受信関数
def request_and_receive(handle,name,message = None):
    print(f"Send Interest \n name: {name}:\n message:{message} \n")
    handle.send_interest(name,0,msg_org = json.dumps(message).encode("utf-8"))
    while True:
        # ccnxにしないと失敗する。理由は不明。 
        info = handle.receive()
        if info.is_succeeded:
            print("Success")
            print(info)
            return info

#Interest受信
def receive_interest(handle):
    handle.register("ccnx:/Content")
    handle.register("ccnx:/Cert")
    print("waiting for Interest...")
    while True:
        info = handle.receive() 
        if info.is_succeeded:
            print(f"Receive Interest :\n Name:{info.name}\n msg_org:{info.msg_org}\n")
            return info

#データ送信
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

# データフォーマット

def bytes_to_json(bytes):
    #utf-8形式のバイト列を普通のUTF-8文字列としてデコード
    str = bytes.decode('utf-8')
    #JSONとしてパース
    jsondata = json.loads(str)

    return jsondata
##--------実動作部分--------##

def request_register(handle,namespace,content_pk,content_sk):
    #登録リクエストの生成
        register_request = RegisterRequest(namespace,content_pk)

        ###----署名生成----###
        register_request.sign(content_sk)
        ### ---変換---###
        # 登録リクエストオブジェクトをJSON文字列に変換
        register_request_json = register_request.to_json()
        #登録リクエスト送信。
        result = request_and_receive(handle,"ccnx:/BC/Register",register_request_json)
        #リクエストに成功したら
        print(f"result.msg_org:{result.msg_org}")
        if(result.msg_org.decode('utf-8') == "Cert"):
            cert_json = bytes_to_json(result.payload)
            return cert_json

        ##失敗したらエラーにする。
        else:
            print(result.payload)
            raise Exception("Request Rejected")

def process_client(handle,content,cert):
    #ここではcontent,certはjsonとして渡されている
    print("process_client called\n")
    interest = receive_interest(handle)
    parts = interest.name.split("/")
    if parts[1] == "Content":
        datasend(handle,interest.name,content)
    elif parts[1] == "Cert":
        datasend(handle,interest.name,cert)
    else:
        datasend(handle,interest.name,"Invalid Request")
    
def main():
    with cefpyco.create_handle() as handle:
        #　名前空間情報
        namespace = "ccnx:/Content/1"
        #コンテンツデータ(1KBのバイト列を生成し、2KBのhexdigestにしてJSONで扱えるように。)
        content_data = os.urandom(1024).hex()
        #Contentインスタンス生成
        content = Content(content_data)

        #----鍵情報生成----#
        # 鍵ペア生成
        content_sk = ed25519.Ed25519PrivateKey.generate()
        #pkはraw形式で生成。(Interest容量節約のため　Raw形式)
        content_pk = content_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        #登録をリクエスト,証明書取得.
        cert_json = request_register(handle,namespace,content_pk,content_sk)
        
        #証明書の場所を記録する
        content.keylocator = "ccnx:/Cert/1"
        #contentに署名
        content.sign(content_sk)

        #contentと証明書をjson化
        content_json = content.to_json()

        while True:
            #リクエストを受け付ける
            process_client(handle,content_json,cert_json)

# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()