# send_test.py (CR2で実行)
import cefpyco
import time

with cefpyco.create_handle() as h:
    name = "ccnx:/BC/Register/BCNode3"
    print(f"Send Interest: {name}")
    h.send_interest(name, 0)
    # ちょっとだけ待つ（ログや tcpdump のため）
    time.sleep(1)