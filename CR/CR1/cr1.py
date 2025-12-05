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

mitm_mode = {
    0:"MITM : No MITM",
    1:"Weak Cert Attack : Send Fake Cert",
    2:"Strong Cert Attack : Send Fake Cert and Fake BCKey (Out Of Scope)",
    3:"Weak Content Attack: Send Fake Content Data and Signature",
    4:"Strong Content Attack: Send Fake Content Data and Signature and Fake Cert",
    5:"Strongest Attack: Send Fake Content Data and Signature and Fake Cert and Fake BCKey (Out Of Scope)"
}

parser.add_argument("forge",nargs='?',type=int,default=0,help=(
                    "Forge mode:\n"
                    + "".join([f"{forge} : {forge_mode[forge]}\n" for forge in forge_mode])
                    + "\n"
                    ))

parser.add_argument("mitm",nargs='?',type=int,default=0,help=(
                    "MITM mode:\n"
                    + "".join([f"{mitm} : {mitm_mode[mitm]}\n" for mitm in mitm_mode])
                    + "\n"
                    ))

args = parser.parse_args()
#print(f"Forge mode: {args.forge} : {forge_mode[args.forge]}")
print(f"MITM mode: {args.mitm} : {mitm_mode[args.mitm]}")

# クラスのインポート
from lib.libs import Content,Cert

# 関数のインポート
from lib.libs import (receive_interest,request_and_receive,
                      datasend,bytes_to_json)

#偽秘密鍵、偽公開鍵生成

fake_sk = ed25519.Ed25519PrivateKey.generate()
fake_pk = fake_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

fake_bc_sk = ed25519.Ed25519PrivateKey.generate()
fake_bc_pk = fake_bc_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

# ---データ構造--- #

# --- 署名部分 --- #
def forge_data(data,forge):
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
    
    if parts[2] == "key":
        if forge == 6:
            print("Dummy Key")
            # ダミー鍵を送信
            data.payload = fake_bc_pk.hex()
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
            cert.sign(fake_bc_sk)
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

def mitm(handle, mitm_mode):
    '''
    MITMの処理を行う。
    ここでは、受け取ったInterestに対して、改ざんしたDataを返す。
    '''
    if not mitm_mode:
        print("No MITM")
        return
    
    if mitm_mode == 1:
        # 受け取ったInterestに対して、偽の証明書を返すだけ
        # 偽の証明書のBC署名と、コンテンツ公開鍵を偽物にする。
        # ここでは、偽の証明書を返すだけで、実際のBCKeyは送信しない。
        # BCNode署名検証で弾かれる
        interest = receive_interest(handle,["ccnx:/Cert","ccnx:/Content"])
        if interest.name.startswith("ccnx:/Content"):
            # コンテンツのInterestを受け取った場合は、そのまま通常処理に戻す。
            datasend(handle, interest.name, request_and_receive(handle,interest.name + "/normal").payload, interest.msg_org)
            #　再起呼び出し。次はCertのInterestが来るはずなので。
            mitm(handle,1)
            return
        # 証明書をリクエスト
        info = request_and_receive(handle,interest.name + "/mitm")
        # 証明書の公開鍵を偽にする
        info = forge_data(info,4) # 公開鍵改ざん
        # 証明書の署名を偽にする
        info = forge_data(info,3) # BCノード署名改ざん
        # 受け取ったInterestに対して、偽の証明書を返す。
        datasend(handle, interest.name, info.payload, info.msg_org)
    
    elif mitm_mode == 2:
        # 強力な証明書攻撃:偽の証明書用に偽のBCKeyを送信。これをやるとマジで偽証明書がとおっちまう。 (範囲外)
        # 証明書は通るものの、コンテンツの署名検証は失敗する(コンテンツの改ざんができてないから)
        #偽の証明書を送信
        mitm(handle,1)
        interest = receive_interest(handle,["ccnx:/BC/key"])
        info = request_and_receive(handle,interest.name + "/mitm")
        # 偽の公開鍵を送信
        datasend(handle, interest.name, fake_bc_pk.hex(), info.msg_org)
        
    elif mitm_mode == 3:
        # 弱いコンテンツ攻撃:偽のコンテンツデータと偽の署名付きのコンテンツを送信
        # この攻撃は証明書は通るものの、コンテンツの署名検証で失敗する。
        interest = receive_interest(handle,["ccnx:/Content"])
        info = request_and_receive(handle,interest.name + "/mitm")
        # 偽のコンテンツデータと署名を送信
        info = forge_data(info,1) # データ改ざん
        info = forge_data(info,2) # 署名改ざん
        datasend(handle, interest.name, info.payload, info.msg_org)

    elif mitm_mode == 4:
        # 強いコンテンツ攻撃:偽のコンテンツデータと署名、偽のコンテンツ公開鍵を送信
        # 要は弱い証明書攻撃 + 弱いコンテンツ攻撃を組み合わせたもの
        #　この攻撃はコンテンツは通るが、BCノードの署名検証で失敗する。
        mitm(handle,3)
        mitm(handle,1)

    elif mitm_mode == 5:
        # 想定できる中で最も強力な攻撃:偽のコンテンツデータと署名、偽の証明書公開鍵、偽のBCKeyを送信
        # 要は強い証明書攻撃で偽物の証明書を通し、弱いコンテンツ攻撃でトドメをさす。 (範囲外)
        mitm(handle,3)
        mitm(handle,2)
        print("This is Perfect MITM Attack and my Program's Limit!")

    else:
        print("Unknown MITM Mode")
        return
    
def Normal(handle):
    interest = None
    #改ざん番号によってアプリ側で受け取るInterestを調整
    interest = receive_interest(handle,["ccnx:/Content","ccnx:/Cert","ccnx:/BC/key"])
    #cr1ではInterestは改ざんせず、そのまま送信する
    info = request_and_receive(handle,interest.name + "/normal")
    # 通常改ざん
    info = forge_data(info,args.forge)
    # 得られた結果を転送する。
    datasend(handle,interest.name,info.payload,info.msg_org)

def main():
    with cefpyco.create_handle() as handle:
        while True:
            # 改ざんモードの処理。
            if args.mitm:
                mitm(handle, args.mitm)
                Normal(handle)
            else:
                Normal(handle)

            
# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()