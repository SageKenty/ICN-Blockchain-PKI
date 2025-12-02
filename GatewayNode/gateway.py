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

# ---関数をインポート --- #
from lib.libs import (receive_interest,request_and_receive,datasend)

# ---引数処理--- #
parser = argparse.ArgumentParser()

parser.add_argument("node",nargs='?',type=int,default=0)
args = parser.parse_args()
print(f"Node number: {args.node}")

##--------実動作部分--------##

def main():
    with cefpyco.create_handle() as handle:
        while True:
            if args.node == 0:
                sendnode = random.randint(1,3)
            else:
                sendnode = args.node

            #Interestを受信、(登録要求のみアプリケーション側にて取り扱う。)
            interest = receive_interest(handle,"ccnx:/BC/Register")
            # Broadcast用の名前
            broadcast_name = "ccnx:/BC/Register/BCNode<n>"
            # ランダムに送り先を決める
            broadcast_name = broadcast_name.replace("<n>",str(sendnode))
            # リクエストを送信し、結果を待つ
            info = request_and_receive(handle,broadcast_name,interest.msg_org)
            # 得られた結果を転送する。
            datasend(handle,interest.name,info.payload,info.msg_org)

# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()