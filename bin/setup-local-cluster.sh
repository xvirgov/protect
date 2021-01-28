#!/bin/bash -e

# TODO-thesis: [important for performance evaluation] make this more scalable: generate certs, check ports, ...
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
  echo "Mandatory input parameters: -n, -k"
}

# Parse the arguments
while getopts ":hn:k:t:" opt; do
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
    \? )
    	error
     ;;
  esac
done

eval_input "$NODES_NR"
eval_input "$IMAGE_NAME"

# Get IP address of docker network
DOCKER_NET_IP=$(ip addr show docker0  | grep inet | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}' | head -1)

# Print info message
echo "System parameters:"
echo "[number of nodes     : \"$NODES_NR\"],"
[ $THRESHOLD -gt 0 ] && \
echo "[threshold           : \"$THRESHOLD\"],"
echo "[docker image name   : \"$IMAGE_NAME\"],"
echo "[docker inet address : \"$DOCKER_NET_IP\"]"

# Build docker image for client and server apps
sudo docker build -t "$IMAGE_NAME" .

# Create a common config file
echo "num_servers = $NODES_NR" > common.config

# Create ssl-extensions file
printf "[v3_ca]\nbasicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\nsubjectAltName = " > ssl-extensions-x509.cnf-tmp

# Start server containers
i=0
CONTAINERS=()
while [ $i -le "$NODES_NR" ]
do
	CONTAINER_ID=$(sudo docker run -d -p 127.0.0.1:$((PORT_BASE + i)):$((PORT_BASE + i)) -p $((APP_PORT_BASE + 10*i)):$((APP_PORT_BASE + 10*i))  -p $((APP_PORT_BASE + 10*i + 1)):$((APP_PORT_BASE + 10*i + 1)) --hostname "${IMAGE_NAME}_$i" -i -t "$IMAGE_NAME" /bin/bash &)
	echo "Container $CONTAINER_ID is running a server ID:$i"
	CONTAINER_IP=$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_ID")
	echo "server.$i = $CONTAINER_IP:$((APP_PORT_BASE + 10*i))" >> common.config
	printf "IP:%s," "$CONTAINER_IP" >> ssl-extensions-x509.cnf-tmp
	CONTAINERS+=("$CONTAINER_ID")
  i=$((i+1))
done

# Delete last comma
sed '$ s/.$/\n/' ssl-extensions-x509.cnf-tmp > ssl-extensions-x509.cnf
rm ssl-extensions-x509.cnf-tmp

[ "$THRESHOLD" -gt 0 ] && echo "reconstruction_threshold = $THRESHOLD" >> common.config

# Prepare configuration
rm -rf $CONFIG_DIR || true
mkdir -p $CONFIG_DIR/ca $CONFIG_DIR/server/bft-config $CONFIG_DIR/client && \
cp common.config $CONFIG_DIR/server && \
cp ../pross-server/config/ca/ca-cert-clients.pem $CONFIG_DIR/ca && \
cp ../pross-server/config/ca/ca-key-clients $CONFIG_DIR/ca && \
cp -R ../pross-server/config/client $CONFIG_DIR && \
cp -R ../pross-server/config/server/bft-config $CONFIG_DIR/server && \
mv ssl-extensions-x509.cnf $CONFIG_DIR && \
cp setup-config.sh $CONFIG_DIR && \
cd $CONFIG_DIR && \
./setup-config.sh "$NODES_NR" && \
rm setup-config.sh ssl-extensions-x509.cnf && \
cd ..

# Start server applications
i=1
while [ $i -le "$NODES_NR" ]
do
	sudo docker cp $CONFIG_DIR "${CONTAINERS[$((i-1))]}":/protect/config # TODO [low pri] fix certificates here - everybody has everyone's private key
	sudo docker cp ../pross-server/target/pross-server-1.0-SNAPSHOT.jar "${CONTAINERS[$((i-1))]}":/protect/pross-server-1.0-SNAPSHOT.jar
	sudo docker exec "${CONTAINERS[$((i-1))]}" java -classpath /protect/pross-server-1.0-SNAPSHOT.jar com.ibm.pross.server.app.ServerApplication /protect/config/server $i &
	echo "Server $i was started"
  i=$((i+1))
done
#
## Start client application
#CONTAINER_ID=$(sudo docker run -d -p 127.0.0.1:$PORT_BASE:$PORT_BASE -p $APP_PORT_BASE:$APP_PORT_BASE --hostname "${IMAGE_NAME}_c" -i -t "${IMAGE_NAME}" /bin/bash &)
#echo "Container $CONTAINER_ID is running a client app"
#CONTAINER_IP=$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_ID")
#sudo docker cp  $CONFIG_DIR "$CONTAINER_ID":/protect/config
#sudo docker cp ../pross-client/target/pross-client-1.0-SNAPSHOT.jar "$CONTAINER_ID":/protect/pross-client-1.0-SNAPSHOT.jar
#sudo docker exec "$CONTAINER_ID" java -classpath /protect/pross-client-1.0-SNAPSHOT.jar com.ibm.pross.client.app.ClientApplication /protect/config/server 0 &
#
