#!/bin/bash -ex

CONFIG_DIR=conf-tmp

cd ..
./build.sh
cd bin
CONTAINER_ID=$( docker ps -a -q --filter "label=client_host")
 docker container restart "$CONTAINER_ID"
 docker cp  $CONFIG_DIR "$CONTAINER_ID":/protect/config
 docker cp ../pross-client/target/pross-client-1.0-SNAPSHOT.jar "$CONTAINER_ID":/protect/pross-client-1.0-SNAPSHOT.jar
 docker exec "$CONTAINER_ID" java -classpath /protect/pross-client-1.0-SNAPSHOT.jar com.ibm.pross.client.app.ClientApplication /protect/config administrator