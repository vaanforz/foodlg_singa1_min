#!/bin/bash
set -e

nvidia-docker run -p 8085:5000 -v /home/wangwei/database:/root/database -v /home/wangwei/model-zoo:/root/model-zoo -v /home/wangwei/server-front-sep/foodlg/:/root/foodlg -d foodlg-gpu:v2

