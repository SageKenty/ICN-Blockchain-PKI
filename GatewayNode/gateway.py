
#cefpyco(ネットワーク)のインポート
import cefpyco
# jsonやhashlibなどデータフォーマット関連のインポート
import json
#乱数生成
import random
# タイムスタンプ,小待機用
import time

## Cefpyco関係 ##
def request_and_receive(handle,name,message = None):
    # インスタンスを定義
    print(f"Send Interest \n name: {name}:\n message:{message} \n")
    handle.send_interest(name,0,msg_org = message)
    while True:
        # ccnxにしないと失敗する。理由は不明。 
        info = handle.receive()
        if info.is_succeeded:
            print("Success")
            print(info)
            return info

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

def receive_interest(handle):
    handle.register("ccnx:/BC/Register")
    while True:
        info = handle.receive() 
        if info.is_succeeded and info.name == "ccnx:/BC/Register":
            print("")
            print(f"Receive Interest :\n Name:{info.name}\n msg_org:{info.msg_org}\n")
            return info
            #handle.send_data("ccnx:/request", f"msgorg:{info.msg_org} \n",0)

##--------実動作部分--------##

def main():
    with cefpyco.create_handle() as handle:
        while True:
            #Interestを受信、(登録要求のみアプリケーション側にて取り扱う。)
            interest = receive_interest(handle)
            # Broadcast用の名前
            broadcast_name = "ccnx:/BC/Register/BCNode<n>"
            # ランダムに送り先を決める
            n = random.randint(1,3)
            broadcast_name = broadcast_name.replace("<n>",str(n))
            # リクエストを送信し、結果を待つ
            info = request_and_receive(handle,broadcast_name,interest.msg_org)
            # 得られた結果を転送する。
            print(info.msg_org)
            datasend(handle,interest.name,info.payload,info.msg_org)

# ファイルが直接実行されたらこれを呼び出す。
if __name__ == "__main__":
    main()