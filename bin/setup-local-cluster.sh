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
#DOCKER_NET_IP_BASE=$(ip addr show docker0 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1 | rev | cut -c 3- | rev)
DOCKER_NET_IP=$(ip addr show docker0  | grep inet | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}' | head -1)


# Print info message
echo "System parameters:"
echo "[number of nodes     : \"$NODES_NR\"],"

[ $THRESHOLD -gt 0 ] && \
echo "[threshold           : \"$THRESHOLD\"],"

echo "[docker image name   : \"$IMAGE_NAME\"],"
echo "[docker inet address : \"$DOCKER_NET_IP\"]"

# Prepare common config file
#echo "num_servers = $NODES_NR" > common.config
#i=1
#while [ $i -le "$NODES_NR" ]
#do
#	IP_LAST_OCTET=$(echo "$DOCKER_NET_IP" | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sed -r 's!/.*!!; s!.*\.!!')
#	IP_BASE=$(echo "$DOCKER_NET_IP" | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
#
#  echo "server.$i = $IP_BASE.$((IP_LAST_OCTET+i+3)):$((APP_PORT_BASE + 10*i))" >> common.config
#
#  i=$((i+1))
#done
#
#[ "$THRESHOLD" -gt 0 ] && echo "reconstruction_threshold = $THRESHOLD" >> common.config

#cp -R config ../config
#mv common.config ../config/server/common.config

# Build docker image for client and server apps
sudo docker build -t "$IMAGE_NAME" ..

# Start servers
# Generate keys
# Finish configuration
# Copy server application

echo "num_servers = $NODES_NR" > common.config

echo "Starting containers..."
i=1
CONTAINERS=()
while [ $i -le "$NODES_NR" ]; do
#	CONTAINER_ID=$(sudo docker run -d -p 127.0.0.1:$((PORT_BASE + i)):$((PORT_BASE + i)) -p $((APP_PORT_BASE + 10*i)):$((APP_PORT_BASE + 10*i)) -i -t "$IMAGE_NAME" /bin/bash &) && \
	CONTAINER_ID=$(sudo docker run -d -p 127.0.0.1:$((PORT_BASE + i)):$((PORT_BASE + i)) -p $((APP_PORT_BASE + 10*i)):$((APP_PORT_BASE + 10*i))  -p $((APP_PORT_BASE + 10*i + 1)):$((APP_PORT_BASE + 10*i + 1)) --hostname "${IMAGE_NAME}_$i" -i -t "$IMAGE_NAME" /bin/bash &)
	echo "Container $CONTAINER_ID is running a server ID:$i"

	CONTAINER_IP=$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_ID")
#	CONTAINER_IP="127.0.0.1"
	echo "server.$i = $CONTAINER_IP:$((APP_PORT_BASE + 10*i))" >> common.config

	CONTAINERS+=("$CONTAINER_ID")

#	sudo docker cp ../pross-server/config "$CONTAINER_ID":/protect/config # TODO fix certificates here
#	sudo docker cp ../pross-server/target/pross-server-1.0-SNAPSHOT.jar "$CONTAINER_ID":/protect/pross-server-1.0-SNAPSHOT.jar

#	sudo docker cp config "$CONTAINER_ID":/protect/config # TODO fix certificates here
#	sudo docker cp common.config "$CONTAINER_ID":/protect/config/server/common.config
#	sudo docker cp ../pross-server/target/pross-server-1.0-SNAPSHOT.jar "$CONTAINER_ID":/protect/pross-server-1.0-SNAPSHOT.jar

#	sudo docker exec "$CONTAINER_ID" java -classpath /protect/pross-server-1.0-SNAPSHOT.jar com.ibm.pross.server.app.ServerApplication /protect/config/server 1 &
#	echo "Server $i was started"

  i=$((i+1))
done

[ "$THRESHOLD" -gt 0 ] && echo "reconstruction_threshold = $THRESHOLD" >> common.config


i=1

while [ $i -le "$NODES_NR" ]; do
#	CONTAINER_ID=$(sudo docker run -d -p 127.0.0.1:$((PORT_BASE + i)):$((PORT_BASE + i)) -p $((APP_PORT_BASE + 10*i)):$((APP_PORT_BASE + 10*i)) -i -t "$IMAGE_NAME" /bin/bash &) && \
#	echo "Container $CONTAINER_ID is running"
#
#	CONTAINER_IP=$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_ID")
#
#	echo "server.$i = $CONTAINER_IP:$((APP_PORT_BASE + 10*i))" >> common.config
#	echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ${CONTAINERS[$((i-1))]}"
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


# Start client app