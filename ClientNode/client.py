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
bckeytable = {} #BCノードの公開鍵表

#---Data Structures---#

# 送信用データを表すクラス
class Content:
    def __init__(self,data,keylocator=None,signature=None):
        self.data = data
        self.keylocator = keylocator
        self.signature = signature

    def verify(self,pk):
        content_info = {
            "data":self.data,
            "keylocator":self.keylocator
        }
        #署名検証
        return signature_check(content_info,self.signature,pk)

class Cert:
    def __init__(self,namespace,pubkey,keylocator,bcsig=None):
        self.namespace = namespace
        self.pubkey = pubkey
        self.keylocator = keylocator
        self.bcsig = bcsig

    def verify(self,pk):
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
        ##----コンテンツの取得----##å
        content = request_and_receive(handle,"ccnx:/Content/1")
        content_json = bytes_to_json(content.payload)
        content = Content(**content_json)
        
        ##----証明書の取得と検証----##
        cert_data = request_and_receive(handle,content_json['keylocator'])
        cert_json = bytes_to_json(cert_data.payload)
        cert = Cert(**cert_json)

        #BCノードの公開鍵を取得
        bckeylocator = cert_json['keylocator']
        bc_pk = bckeytable.get(bckeylocator,None)
        if bc_pk is None:
            # BCノード公開鍵が未登録の場合は、公開鍵をBCNodeから取得
            print("Requesting BC Public Key...")
            bckey_info = request_and_receive(handle,bckeylocator)
            bckey_str = bckey_info.payload.decode('utf-8')

            # 公開鍵をhex形式からバイト列形式に変換
            bc_pk_bytes = bytes.fromhex(bckey_str)
            # バイト列形式の公開鍵を検証可能な公開鍵オブジェクトに変換
            bc_pk = ed25519.Ed25519PublicKey.from_public_bytes(bc_pk_bytes)
            # 公開鍵をBCノード公開鍵表に登録
            bckeytable[bckeylocator] = bc_pk
            print(bckeytable)

        #証明書の検証
        print("Verifying Cert Signature...")
        cert_valid = cert.verify(bc_pk)

        if cert_valid:
            print("Cert Signature Valid")
        else:
            raise Exception("Cert Signature Invalid")
        
        #----コンテンツの検証----#
        # コンテンツの公開鍵を証明書から取得
        content_pk_hex = cert_json['pubkey']
        content_pk_bytes = bytes.fromhex(content_pk_hex)
        content_pk = ed25519.Ed25519PublicKey.from_public_bytes(content_pk_bytes)
        print("Verifying Content Signature...")

        # コンテンツの署名を検証
        content_valid = content.verify(content_pk)
    
        if content_valid:
            print("Content Signature Valid")
        else:
            raise Exception("Content Signature Invalid")

        if content_valid and cert_valid:
            print("Content is perfectly valid and trusted!")

# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()