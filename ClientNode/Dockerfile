FROM cefore-base
##ユーザをrootにしする
ENV USER=root
# buildコンテキストの初めはPKI直下。
COPY ./ClientNode/cefnetd.fib /usr/local/cefore/cefnetd.fib
# ENTRYPOINTーコンテナが起動した時のコマンド。
ENTRYPOINT ["/entrypoint.sh"]
# 作業ディレクトリ
WORKDIR /root/opt/home/sekigawa/ClientNode