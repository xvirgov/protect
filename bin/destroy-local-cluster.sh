#!/bin/sh

# Stop all docker containers specified by a tag of image
# This scripts was created for testing

IMAGE_TAG=""

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
  echo "    -t [name]         docker image tag"
  echo "Mandatory input parameters: -n, -k and -t"
}

# Parse the arguments
while getopts ":ht:" opt; do
  case ${opt} in
   h )
      usage
      exit 0
      ;;
    t ) # Specify name of image
	IMAGE_TAG=$OPTARG
      ;;
    \? )
    	error
     ;;
  esac
done

eval_input "$IMAGE_TAG"

# Perform the cleanup
CONTAINER_TAGS=$(sudo docker ps -a -q --filter="ancestor=$IMAGE_TAG")

for TAG in $CONTAINER_TAGS
do
	sudo docker container stop "$TAG" && \
	sudo docker container rm "$TAG" ||
	exit 1
done