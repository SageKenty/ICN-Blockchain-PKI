FROM cefore-base
# Userをrootにする
ENV USER=root
# buildコンテキストの初めはPKI直下。
COPY ./BCNode/BCNode1/cefnetd.fib /usr/local/cefore/cefnetd.fib
# ENTRYPOINT を差し替え
ENTRYPOINT ["/entrypoint.sh"]
#ディレクトリ移動
WORKDIR /root/opt/home/sekigawa/BCNode/BCNode1