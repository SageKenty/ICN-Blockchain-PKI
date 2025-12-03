import sys
sys.path.append("./kentolib")

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

# ---引数処理--- #
parser = argparse.ArgumentParser()

forge_mode = {0:"No Forge",
              1:"Content : Fake Content Data",
              2:"Content : Fake Content Signature",
              3:"Cert : Bad BC Node Signature",
              4:"Cert : Bad Public Key",
              5:"Cert : Namespace Forge",
              6:"BC Key : Send Dummy Key"
              }

parser.add_argument("forge",nargs='?',type=int,default=0,help=(
                    "Forge mode:\n"
                    + "".join([f"{forge} : {forge_mode[forge]}\n" for forge in forge_mode])
                    + "\n"))

args = parser.parse_args()
print(f"Forge mode: {args.forge} : {forge_mode[args.forge]}")

# クラスのインポート
from lib.libs import Content,Cert

# 関数のインポート
from lib.libs import (receive_interest,request_and_receive,
                      datasend,bytes_to_json)

# ---データ構造--- #

# --- 署名部分 --- #
def forge_data(data,forge,fake_sk):
    '''
    0:そのまま 
    [コンテンツ関係]1:コンテンツ改ざん 2:不正署名
    [証明書関係]3:不正BCノード署名 4:不正公開鍵 5:Namespace改ざん
    [鍵関係]6:ダミー鍵送信,
    '''

    # 0の時はそのまま返す。
    if not forge:
        return data

    # インタレスト名を分割
    parts = data.name.split("/")
    #偽公開鍵、偽秘密鍵を生成
    
    fake_pk = fake_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    if parts[2] == "key":
        if forge == 6:
            print("Dummy Key")
            # ダミー鍵を送信
            data.payload = fake_pk.hex()
        return data
    # メッセージ内部のオブジェクト
    message_object = None

    # メッセージをjson形式で取り出す
    message = bytes_to_json(data.payload)

    if parts[1] == "Content":
        #　登録リクエストオブジェクト生成
        content = Content(**message)
        if forge == 1:
            print("Forging Content Data")
            content.data = random.randbytes(1024).hex()
        if forge == 2:
            print("Forging signature")
            content.sign(fake_sk)

        message_object = content

    elif parts[1] == "Cert":
        fake_hash = hashlib.sha256(random.randbytes(100)).hexdigest()
        cert = Cert(**message)
        if forge == 3:
            print("Forging BC Node Signature")
            cert.sign(fake_sk)
        if forge == 4:
            print("Forging Public Key")
            cert.pubkey = fake_pk
        if forge == 5:
            print("Forging Namespace")
            cert.namespace = "ccnx:/Content/FAKE"

        message_object = cert
    
    else:
        raise Exception("Unknown Type for Forging or This is Not CR1 Target")
    
    # 改ざんしたメッセージをバイト列に変換
    message_str = json.dumps(message_object.to_json()).encode("utf-8")
    

    # 改ざんしたメッセージをセットし直す
    data.payload = message_str

    return data

def main():
    with cefpyco.create_handle() as handle:
        #偽秘密鍵生成
        fake_sk = ed25519.Ed25519PrivateKey.generate()
        while True:
            interest = None
            #改ざん番号によってアプリ側で受け取るInterestを調整
            interest = receive_interest(handle,["ccnx:/Content","ccnx:/Cert","ccnx:/BC/key"])
            #cr1ではInterestは改ざんせず、そのまま送信する
            info = request_and_receive(handle,interest.name + "/forged")

            #代わりに、受け取ったDataを改ざんする。
            info = forge_data(info,args.forge,fake_sk)
            # 得られた結果を転送する。
            datasend(handle,interest.name,info.payload,info.msg_org)
            
# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()