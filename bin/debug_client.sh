#!/bin/bash -ex

CONFIG_DIR=conf-tmp

cd ..
./build.sh
cd bin
CONTAINER_ID=$(sudo docker ps -a -q --filter "label=client_host")
sudo docker container restart "$CONTAINER_ID"
sudo docker cp  $CONFIG_DIR "$CONTAINER_ID":/protect/config
sudo docker cp ../pross-client/target/pross-client-1.0-SNAPSHOT.jar "$CONTAINER_ID":/protect/pross-client-1.0-SNAPSHOT.jar
sudo docker exec "$CONTAINER_ID" java -classpath /protect/pross-client-1.0-SNAPSHOT.jar com.ibm.pross.client.app.ClientApplication /protect/config administrator