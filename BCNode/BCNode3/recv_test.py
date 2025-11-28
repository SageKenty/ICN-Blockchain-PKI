# recv_test.py (BCNode3で実行)
import cefpyco

with cefpyco.create_handle() as h:
    # ざっくり /BC 以下全部
    h.register("ccnx:/BC")
    print("Waiting Interest on ccnx:/BC ...")
    while True:
        info = h.receive()
        if info.is_succeeded:
            print("=== RECEIVED ===")
            print(f"name     : {info.name}")
            print(f"msg_org  : {info.msg_org}")
            break