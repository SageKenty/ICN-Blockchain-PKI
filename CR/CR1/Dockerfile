FROM cefore-base
# Userをrootにする
ENV USER=root
# FIB を配置
COPY ./CR/CR1/cefnetd.fib /usr/local/cefore/cefnetd.fib
# ENTRYPOINT
ENTRYPOINT ["/entrypoint.sh"]