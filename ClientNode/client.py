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

# 送信用データを表すクラス
class Content:
    def __init__(self,content_data):
        self.content_data = content_data
        self.keylocator = None
        self.signature = None
\
    def verify(self,pk):
        content_info = {
            "content_data":self.content_data,
            "keylocator":self.keylocator
        }
        # フォーマットを固定してutf-8ストリング化
        content_info_string = json.dumps(content_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        # 名前,公開鍵に署名。
        self.signature = sk.sign(content_info_string)

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
# 署名検証関数
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
        content = request_and_receive(handle,"ccnx:/Content/1")
        content_json = bytes_to_json(content.payload)
        print("Received Content:")
        print(content_json)

# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()