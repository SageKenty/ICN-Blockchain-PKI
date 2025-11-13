FROM ubuntu:22.04
RUN mkdir -p cefore

# 必要な依存関係　を入れる
RUN apt-get update
RUN apt-get install -y \
    build-essential libssl-dev automake cmake pkg-config \
    python3 python3-pip \
    iputils-ping net-tools ifstat

# Pythonツール
RUN pip3 install --upgrade pip
RUN pip3 install setuptools wheel click numpy build

# Cryptographyを利用したい場合は追加で以下をインストール
RUN apt-get install -y python3-dev libffi-dev cargo
RUN pip3 install cryptography

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

# cefpyco のビルド
WORKDIR /cefore/cefpyco
RUN rm -rf CMakeFiles CMakeCache.txt
RUN cmake .
RUN make
RUN make install
RUN ldconfig

ENV USER = root
# FIB を配置
COPY ./BCNode/BCNode2/cefnetd.fib /usr/local/cefore/cefnetd.fib

# 起動（cefnetd を上げて待機）
ENTRYPOINT ["bash","-c","cefnetdstart && tail -f /dev/null"]

# 作業ディレクトリ
WORKDIR /root/opt/home/sekigawa/BCNode/bcnode2
