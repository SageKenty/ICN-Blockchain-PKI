FROM cefore-base
# Userをrootにする
ENV USER=root
# buildコンテキストの初めはPKI直下。
COPY ./GatewayNode/cefnetd.fib /usr/local/cefore/cefnetd.fib
# 作業ディレクトリ
WORKDIR /root/opt/home/sekigawa/GatewayNode
# ENTRYPOINT
ENTRYPOINT ["/entrypoint.sh"]
