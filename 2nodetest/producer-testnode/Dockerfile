# 参考:https://zenn.dev/k4e/articles/k4e-cefore-on-ubuntu
# 参考:https://github.com/LilyYurin/cefore-docker
# ベースイメージとしてUbuntuを使用(CeforeはUbuntu前提のため)
FROM ubuntu:22.04
# CeforeをおよびCefpycoをインストールするディレクトリ
RUN mkdir -p /cefore
WORKDIR /cefore
# 必要なパッケージリストを更新
RUN apt update
# コンパイルに必要なツールやライブラリをインストール
# 以下はceforeに必要
RUN apt install -y build-essential libssl-dev
RUN apt install -y automake
RUN apt install -y iputils-ping net-tools ifstat
# python3のインストール
RUN apt install -y python3
# キャッシュを削除(バグり防止か)
RUN apt -y clean
# Cefore ver:0.11.0 Cefpyco ver:0.10.0.4
COPY ./cefore /cefore/cefore
COPY ./cefpyco /cefore/cefpyco
# Cefpycoをインストールするディレクトリに移動
WORKDIR /cefore/cefpyco
# CMakeやpipなどのインストール,アップデート
RUN apt install -y cmake python3-pip
RUN apt -y clean
RUN pip3 install --upgrade pip
RUN pip3 install setuptools click numpy build
# Cryptographyを利用したいため、追加で以下をインストール
RUN apt install -y python3-dev libffi-dev cargo
RUN pip3 install cryptography
# Ceforeのビルド
WORKDIR /cefore/cefore
RUN ./configure
RUN make
RUN make install
RUN make clean
RUN ldconfig
# Cefpycoのビルド
WORKDIR /cefore/cefpyco
RUN cmake .
RUN make
RUN make install
# ユーザーをrootに変更
ENV USER=root
# cefnetdのFIB設定ファイルを配置
# buildコンテキストの初めはPKI直下。
COPY ./2nodetest/producer-testnode/cefnetd.fib /usr/local/cefore/cefnetd.fib
# ENTRYPOINTーコンテナが起動した時のコマンド。今回は　cefnetd(cefore)を起動し、コンテナを終了させないためにtailコマンドでバックグラウンドで動かし続ける
ENTRYPOINT ["bash", "-c","cefnetdstart && tail -f /dev/null"]
WORKDIR /root/opt/home/sekigawa/producer-testnode