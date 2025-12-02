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

parser.add_argument("forge",nargs='?',type=int,default=0,help=
                    "Forge mode:\n"
                    "0: No Forge\n" 
                    "ContentForge \n" 
                    "1: Name forge, 2: Fake Content \n"
                    "CertForge \n"
                    "4: badbcsig 5:bad pubkey,6:Namespace Forge\n"
                    "Narisumasi" \n"
                    " \n")

args = parser.parse_args()
print(f"Forge mode: {args.forge}")

# クラスのインポート
from lib.libs import RegisterRequest,Block,Transaction

# 関数のインポート
from lib.libs import (receive_interest,request_and_receive,
                      datasend,bytes_to_json)

# ---データ構造--- #

# --- 署名部分 --- #
def forge_interest(interest,forge):
    '''
    0:そのまま 
    [リクエスト関係]1:名前改ざん 2:不正署名 3:公開鍵改ざん
    [ブロックチェーン関係] 4:index改ざん 5:Timestamp改ざん 6:ブロックハッシュ改ざん 7:不正ブロック署名
    [トランザクション関係] 8:トランザクション内容改ざん 9:不正トランザクションID 10:不正トランザクション署名
    '''

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
            register_request.namespace = "ccnx:/Content/FAKE"
        if forge == 2:
            print("Forging signature")
            register_request.sign(fake_sk)
        if forge == 3:
            print("Forging pubkey")
            register_request.pubkey = fake_pk
        
        message_object = register_request

    if parts[2] == "Block":
        fake_hash = hashlib.sha256(random.randbytes(100)).hexdigest()
        block = Block(**message)
        transaction = Transaction(**block.transaction)
    
        if forge == 4:
            print("Forge index")
            block.index = 1600
        if forge == 5:
            print("Forge Timestamp")
            block.timestamp = 9999999999
        if forge == 6:
            print("Forge Block Hash")
            block.hash = fake_hash
        if forge == 7:
            print("Forge BCNode sig")
            block.sign(fake_sk)

        # ---トランザクション改ざん--- #
        if forge == 8:
            #トランザクションの内容の改ざん
            print("Forge Transaction Contet")
            transaction.namespace = "FAKE"
            transaction.pubkey = fake_pk
        if forge == 9:
            #トランザクションIDの改ざん
            print("Forge Transaction ID")
            transaction.txid = fake_hash
            
        if forge == 10:
            print("Forge Transaction Sig")
            transaction.sign(fake_sk)
        
        block.transaction = transaction.to_json()
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
                info = request_and_receive(handle,interest.name,interest.msg_org)
                true_name = info.name.replace("/forged","")
                datasend(handle,true_name,info.payload,info.msg_org)            
            
# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()