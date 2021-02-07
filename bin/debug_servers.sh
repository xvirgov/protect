#!/bin/bash -ex

cd ..
./build.sh
cd bin
./destroy-local-cluster.sh -t protect_server
./setup-local-cluster.sh -n 5 -k 3 -t protect_server