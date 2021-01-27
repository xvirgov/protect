#!/bin/bash -e

# Setup local cluster of docker containers
# This scripts was created for testing

NODES_NR=""
THRESHOLD=""
IMAGE_NAME=""

APP_PORT_BASE=65000
PORT_BASE=8080

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

# Start server containers
i=1
CONTAINERS=()
while [ $i -le "$NODES_NR" ]; do
	CONTAINER_ID=$(sudo docker run -d -p 127.0.0.1:$((PORT_BASE + i)):$((PORT_BASE + i)) -p $((APP_PORT_BASE + 10*i)):$((APP_PORT_BASE + 10*i))  -p $((APP_PORT_BASE + 10*i + 1)):$((APP_PORT_BASE + 10*i + 1)) --hostname "${IMAGE_NAME}_$i" -i -t "$IMAGE_NAME" /bin/bash &)
	echo "Container $CONTAINER_ID is running a server ID:$i"
	CONTAINER_IP=$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_ID")
	echo "server.$i = $CONTAINER_IP:$((APP_PORT_BASE + 10*i))" >> common.config
	CONTAINERS+=("$CONTAINER_ID")
  i=$((i+1))
done

[ "$THRESHOLD" -gt 0 ] && echo "reconstruction_threshold = $THRESHOLD" >> common.config

# Start server applications
i=1
while [ $i -le "$NODES_NR" ]; do
	sudo docker cp ../pross-server/config "${CONTAINERS[$((i-1))]}":/protect/config # TODO fix certificates here
	sudo docker cp common.config "${CONTAINERS[$((i-1))]}":/protect/config/server/common.config
	sudo docker cp ../pross-server/target/pross-server-1.0-SNAPSHOT.jar "${CONTAINERS[$((i-1))]}":/protect/pross-server-1.0-SNAPSHOT.jar
	sudo docker exec "${CONTAINERS[$((i-1))]}" java -classpath /protect/pross-server-1.0-SNAPSHOT.jar com.ibm.pross.server.app.ServerApplication /protect/config/server $i &
	echo "Server $i was started"
  i=$((i+1))
done

# Start client application
#CONTAINER_ID=$(sudo docker run -d -p 127.0.0.1:$PORT_BASE:$PORT_BASE -p $APP_PORT_BASE:$APP_PORT_BASE -i -t "$IMAGE_NAME" /bin/bash &)
#echo "Container $CONTAINER_ID is running a client app"
#sudo docker cp ../pross-server/config "$CONTAINER_ID":/protect/config
#sudo docker cp common.config "$CONTAINER_ID":/protect/config/server/common.config
