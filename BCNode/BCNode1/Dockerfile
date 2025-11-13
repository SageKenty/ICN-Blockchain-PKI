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
##ユーザをrootにしする
ENV USER=root
# buildコンテキストの初めはPKI直下。
COPY ./BCNode/BCNode1/cefnetd.fib /usr/local/cefore/cefnetd.fib
# ENTRYPOINTーコンテナが起動した時のコマンド。今回は　cefnetd(cefore)を起動し、コンテナを終了させないためにtailコマンドでバックグラウンドで動かし続ける
ENTRYPOINT ["bash", "-c","cefnetdstart && tail -f /dev/null"]
WORKDIR /root/opt/home/sekigawa/BCNode/bcnode1