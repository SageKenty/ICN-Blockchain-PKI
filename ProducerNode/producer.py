###-----インポート-----##
#パスのインポート
import sys
sys.path.append("/kentolib")
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
# random(乱数生成ライブラリ)
import random
# シェル関連。
import argparse

#クラス構造のインポート
from libs import RegisterRequest,Content

#関数構造のインポート(libs.pyから)
from libs import (request_and_receive,receive_interest,
                      datasend,bytes_to_json)


# ---引数処理--- #
parser = argparse.ArgumentParser()

parser.add_argument("count",nargs='?',type=int,default=1,help=
                    "Process Takes : What Times Register??\n")

args = parser.parse_args()
print(f"Process Times: {args.count}")

#---グローバル変数---#
certs = []  #証明書
contents = []  #コンテンツデータ

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
            raise Exception("Request Rejected")

def process_client(handle,contents,certs):
    #ここではcontent,certはjsonとして渡されている
    print("process_client called\n")
    interest = receive_interest(handle,["ccnx:/Content","ccnx:/Cert"])
    
    parts = interest.name.split("/")
    if parts[1] == "Content":
        datasend(handle,interest.name,contents[int(parts[2])-1])
    elif parts[1] == "Cert":
        datasend(handle,interest.name,certs[int(parts[2])-1])
    else:
        datasend(handle,interest.name,"Invalid Request")
    
def main():
    with cefpyco.create_handle() as handle:
        register_count = 1
        while register_count <= args.count:
            #　名前空間情報
            namespace = "ccnx:/Content/" + str(register_count)
            #コンテンツデータ(1KBのバイト列を生成し、2KBのhexdigestにしてJSONで扱えるように。)
            content_data = random.randbytes(1024).hex()
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
            content.keylocator = "ccnx:/Cert/" + str(register_count)
            #contentに署名
            content.sign(content_sk)
            #contentと証明書をjson化
            content_json = content.to_json()

            #複数テスト用、コンテンツと証明書を保存
            #contentを保存
            contents.append(content_json)
            #証明書を保存
            certs.append(cert_json)

            register_count += 1

        while True:
           #リクエストを受け付ける
           process_client(handle,contents,certs)
       

# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()