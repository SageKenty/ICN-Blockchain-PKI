FROM ubuntu:22.04
RUN mkdir -p cefore

# 必要な依存関係　を入れる
RUN apt-get update
RUN apt-get install -y \
    build-essential libssl-dev automake cmake pkg-config \
    iputils-ping net-tools ifstat

# ソース配置
WORKDIR /cefore
COPY ./cefore  /cefore/cefore
COPY ./cefpyco /cefore/cefpyco

# cefore のビルド
WORKDIR /cefore/cefore
RUN ./configure
RUN make
RUN make install
RUN make clean
RUN ldconfig

ENV USER=root
# FIB を配置
COPY ./CR/CR2/cefnetd.fib /usr/local/cefore/cefnetd.fib

# Confを配置
COPY ./CR/CR2/cefnetd.conf /usr/local/cefore/cefnetd.conf
# ログを取りつつ実行
RUN mkdir -p /logs
ENTRYPOINT ["bash", "-c", "cefnetdstart 2>&1 | tee -a /logs/cefnetd_cr2.log"]

# 作業ディレクトリ
WORKDIR /root/opt/home/sekigawa/CR/cr2
