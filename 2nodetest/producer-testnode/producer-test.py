import cefpyco

with cefpyco.create_handle() as handle:
    handle.register("ccnx:/test")
    handle.register("ccnx:/request")
    while True:
        info = handle.receive()
        if info.is_succeeded and (info.name == "ccnx:/request"):
            print("msgorg:")
            print(info.msg_org, "\n")
            handle.send_data("ccnx:/request", f"msgorg:{info.msg_org} \n",0)
        elif info.is_succeeded and info.name == "ccnx:/test" : 
            print("This is Test Interest")
            handle.send_data("ccnx:/test","Test Interest Received! Second Success! \n",0)

    print("Receive loop is ended.\n")
    