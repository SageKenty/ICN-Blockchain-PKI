# Cryptographyライブラリのインポート
import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
# cefpyco(ネットワーク)のインポート
import cefpyco
#シェル引数処理用
import argparse


##　クラスのインポート　##
from lib.libs import Content,Cert
##　関数のインポート　##
from lib.libs import (request_and_receive,bytes_to_json)

#---グローバル変数---#
cert = None #証明書
bckeytable = {} #BCノードの公開鍵表

# ---引数処理--- #
parser = argparse.ArgumentParser()

parser.add_argument("count",nargs='?',type=int,default=1,help=
                    "Process Takes : What Times Register??\n")

args = parser.parse_args()
print(f"Process Times: {args.count}")

##--------実動作部分--------##

def main():
    with cefpyco.create_handle() as handle:
        request_count = 1

        while request_count <= args.count:
            ##----コンテンツの取得----##
            req_content_name = "ccnx:/Content/" + str(request_count)
            content = request_and_receive(handle,req_content_name)

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
                print(f"\nbckeytable : {bckeytable}")
            else:
                print("Key Found In BCKeytable")


            #証明書の検証
            print("Verifying Cert Signature...")
            cert_valid = cert.verify(bc_pk)

            #----コンテンツの検証----#
            # コンテンツの公開鍵を証明書から取得
            content_pk_hex = cert_json['pubkey']
            content_pk_bytes = bytes.fromhex(content_pk_hex)
            content_pk = ed25519.Ed25519PublicKey.from_public_bytes(content_pk_bytes)
            print("Verifying Content Signature...")

            # コンテンツの署名を検証
            content_valid = content.verify(content_pk)


            if content_valid and cert_valid:
                print("Content is perfectly valid and trusted!")
            elif content_valid and not cert_valid:
                print("Content is valid but Cert is NOT trusted!")
                raise Exception("Cert Test Failed")
            elif cert_valid and not content_valid:
                print("Cert is valid but Content is NOT trusted!")
                raise Exception("Content Test Failed")
            else:
                raise Exception("Both Content and Cert are NOT trusted!")

            request_count += 1

# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()