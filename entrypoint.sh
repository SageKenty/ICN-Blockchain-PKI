#!/bin/bash
set -e
#Ceforeのデーモン、cefnetdを起動
cefnetdstart
# PID 1を維持するために無限ループで待機
exec tail -f /dev/null