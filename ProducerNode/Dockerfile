FROM cefore-base
# Userをrootにする
ENV USER=root
# buildコンテキストの初めはPKI直下。
COPY ./ProducerNode/cefnetd.fib /usr/local/cefore/cefnetd.fib
# ENTRYPOINT
ENTRYPOINT ["/entrypoint.sh"]