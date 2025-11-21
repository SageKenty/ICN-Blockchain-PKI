FROM cefore-base
# Userをrootに
ENV USER=root
# FIB を配置
COPY ./CR/CR2/cefnetd.fib /usr/local/cefore/cefnetd.fib
# ENTRYPOINT
ENTRYPOINT ["/entrypoint.sh"]
# 作業ディレクトリ
WORKDIR /root/opt/home/sekigawa/CR/CR2