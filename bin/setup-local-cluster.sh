#!/bin/bash -e

# TODO-thesis: move file names into variables

# Setup local cluster of docker containers
# This scripts was created for testing

NODES_NR=""
THRESHOLD=""
IMAGE_NAME=""

APP_PORT_BASE=65000
PORT_BASE=8080

CONFIG_DIR=conf-tmp

# Functions

error () {
	echo "Incorrect arguments specified"
  echo "Use -h for help"
  exit 1
}

eval_input () {
	if [ -z "$1" ]
	then
	  error;
	fi
}

usage () {
	echo "Usage:"
  echo "    -h                display help message"
  echo "    -n [number]       number of nodes"
  echo "    -k [number]       threshold value"
  echo "    -t [name]         docker image name"
  echo "    -s [number]       security level in bits (default = 128) [128, 156, 192, 256]"
  echo "    -f [number]       refresh frequency in seconds (default = 60)"
  echo "Mandatory input parameters: -n, -k, -t"
}

# Parse the arguments
while getopts ":hn:k:t:f:s:" opt; do
  case ${opt} in
   h )
      usage
      exit 0
      ;;
    n ) # Specify number of nodes
	NODES_NR=$OPTARG
      ;;
    k ) # Specify threshold value
	THRESHOLD=$OPTARG
      ;;
    t ) # Specify name of image
	IMAGE_NAME=$OPTARG
      ;;
    f )
	REFRESH_FREQUENCY=$OPTARG
      ;;
    s )
	SECURITY_LEVEL=$OPTARG
      ;;
    \? )
    	error
     ;;
  esac
done

eval_input "$NODES_NR"
eval_input "$THRESHOLD"
eval_input "$IMAGE_NAME"

[ -z $SECURITY_LEVEL ] && SECURITY_LEVEL=128
[ -z $REFRESH_FREQUENCY ] && REFRESH_FREQUENCY=60

# Get IP address of docker network
DOCKER_NET_IP=$(ip addr show docker0  | grep inet | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}' | head -1)

# Print info message
echo "System parameters:"
echo "[number of nodes     : \"$NODES_NR\"],"
[ $THRESHOLD -gt 0 ] && \
echo "[threshold           : \"$THRESHOLD\"],"
echo "[docker image name   : \"$IMAGE_NAME\"],"
[ $REFRESH_FREQUENCY -gt 0 ] && \
echo "[refresh frequency   : \"$REFRESH_FREQUENCY\"],"
[ $SECURITY_LEVEL -gt 0 ] && \
echo "[security level      : \"$SECURITY_LEVEL\"],"
echo "[docker inet address : \"$DOCKER_NET_IP\"]"

# Build docker image for client and server apps
docker build -t "$IMAGE_NAME" .

# Create a common config file
echo "num_servers = $NODES_NR" > common.config
[ $REFRESH_FREQUENCY -gt 0 ] && \
echo "refresh_frequency=$REFRESH_FREQUENCY" >> common.config
[ $SECURITY_LEVEL -gt 0 ] && \
echo "security_level=$SECURITY_LEVEL" >> common.config


# Create ssl-extensions file
printf "[v3_ca]\nbasicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\nsubjectAltName = " > ssl-extensions-x509.cnf-tmp

# Start server containers
i=1
CONTAINERS=()
while [ $i -le "$NODES_NR" ]
do
	CONTAINER_ID=$( docker run -d -p 127.0.0.1:$((PORT_BASE + i)):$((PORT_BASE + i)) -p $((APP_PORT_BASE + 10*i)):$((APP_PORT_BASE + 10*i))  -p $((APP_PORT_BASE + 10*i + 1)):$((APP_PORT_BASE + 10*i + 1)) --hostname "${IMAGE_NAME}_$i" -i -t "$IMAGE_NAME" /bin/bash &)
	echo "Container $CONTAINER_ID is running a server ID:$i"
	CONTAINER_IP=$( docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_ID")
	echo "server.$i = $CONTAINER_IP:$((APP_PORT_BASE + 10*i))" >> common.config
	printf "IP:%s," "$CONTAINER_IP" >> ssl-extensions-x509.cnf-tmp
	CONTAINERS+=("$CONTAINER_ID")
  i=$((i+1))
done

# Delete last comma
sed '$ s/.$/\n/' ssl-extensions-x509.cnf-tmp > ssl-extensions-x509.cnf
rm ssl-extensions-x509.cnf-tmp

[ "$THRESHOLD" -gt 0 ] && echo "reconstruction_threshold = $THRESHOLD" >> common.config

# Prepare configuration directory with all the keys
rm -rf $CONFIG_DIR || true
mkdir -p $CONFIG_DIR/ca $CONFIG_DIR/server/bft-config $CONFIG_DIR/client && \
cp common.config $CONFIG_DIR/server && \
cp -R ../pross-server/config/server/bft-config $CONFIG_DIR/server && \
mv ssl-extensions-x509.cnf $CONFIG_DIR && \
./setup-config.sh "$NODES_NR" $CONFIG_DIR $SECURITY_LEVEL #&& \
#rm setup-config.sh ssl-extensions-x509.cnf && \
#cd ..

# Prepare configuration directories for each server separately
i=1
while [ $i -le "$NODES_NR" ]
do
	rm -rf $CONFIG_DIR-$i
	mkdir -p $CONFIG_DIR-$i/ca $CONFIG_DIR-$i/client/certs $CONFIG_DIR-$i/client/keys $CONFIG_DIR-$i/server/bft-config $CONFIG_DIR-$i/server/certs $CONFIG_DIR-$i/server/keys
	cp $CONFIG_DIR/ca/*.pem $CONFIG_DIR/ca/*$i* $CONFIG_DIR-$i/ca  || true
	cp $CONFIG_DIR/client/certs/*  $CONFIG_DIR-$i/client/certs
	cp $CONFIG_DIR/client/clients.config $CONFIG_DIR-$i/client/clients.config
	cp $CONFIG_DIR/client/keys/public-* $CONFIG_DIR-$i/client/keys/
	cp $CONFIG_DIR/server/common.config $CONFIG_DIR-$i/server/common.config
	cp $CONFIG_DIR/server/bft-config/system.config $CONFIG_DIR-$i/server/bft-config
	cp $CONFIG_DIR/server/certs/* $CONFIG_DIR-$i/server/certs
	cp $CONFIG_DIR/server/keys/public* $CONFIG_DIR/server/keys/*$i* $CONFIG_DIR-$i/server/keys || true
  i=$((i+1))
done

# Start server applications
i=1
while [ $i -le "$NODES_NR" ]
do
	 docker cp $CONFIG_DIR-$i "${CONTAINERS[$((i-1))]}":/protect/config
	 docker cp ../pross-server/target/pross-server-1.0-SNAPSHOT.jar "${CONTAINERS[$((i-1))]}":/protect/pross-server-1.0-SNAPSHOT.jar
	 docker exec "${CONTAINERS[$((i-1))]}" java -classpath /protect/pross-server-1.0-SNAPSHOT.jar com.ibm.pross.server.app.ServerApplication /protect/config/server $i &
	echo "Server $i was started"
	rm -rf $CONFIG_DIR-$i
  i=$((i+1))
done

# Prepare configuration directory for client app
CLIENT_CONFIG_DIR=$CONFIG_DIR-client
rm -rf $CLIENT_CONFIG_DIR
mkdir -p $CLIENT_CONFIG_DIR/ca $CLIENT_CONFIG_DIR/client/certs $CLIENT_CONFIG_DIR/client/keys $CLIENT_CONFIG_DIR/server/bft-config $CLIENT_CONFIG_DIR/server/certs $CLIENT_CONFIG_DIR/server/keys
cp $CONFIG_DIR/ca/*.pem $CONFIG_DIR/ca/*clients* $CLIENT_CONFIG_DIR/ca  || true
cp $CONFIG_DIR/client/certs/*  $CLIENT_CONFIG_DIR/client/certs
cp $CONFIG_DIR/client/clients.config $CLIENT_CONFIG_DIR/client/clients.config
cp $CONFIG_DIR/client/keys/* $CLIENT_CONFIG_DIR/client/keys/
cp $CONFIG_DIR/server/common.config $CLIENT_CONFIG_DIR/server/common.config
cp $CONFIG_DIR/server/bft-config/system.config $CLIENT_CONFIG_DIR/server/bft-config
cp $CONFIG_DIR/server/certs/* $CLIENT_CONFIG_DIR/server/certs
cp $CONFIG_DIR/server/keys/public* $CLIENT_CONFIG_DIR/server/keys


## Start client application
CONTAINER_ID=$( docker run -d -p 127.0.0.1:$PORT_BASE:$PORT_BASE -p $APP_PORT_BASE:$APP_PORT_BASE --hostname "${IMAGE_NAME}_c" --label client_host -i -t "${IMAGE_NAME}" /bin/bash &)
echo "Container $CONTAINER_ID is running a client app"
#CONTAINER_IP=$( docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_ID")
 docker cp  $CLIENT_CONFIG_DIR "$CONTAINER_ID":/protect/config
 docker cp ../pross-client/target/pross-client-1.0-SNAPSHOT.jar "$CONTAINER_ID":/protect/pross-client-1.0-SNAPSHOT.jar
 docker exec "$CONTAINER_ID" java -classpath /protect/pross-client-1.0-SNAPSHOT.jar com.ibm.pross.client.app.ClientApplication /protect/config administrator &
