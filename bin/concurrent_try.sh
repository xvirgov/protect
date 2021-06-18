#!/bin/bash -x

NUMSERVERS=5
THRESHOLD=3
ITERATIONS=20
ROUND_ITER=20
REFRESH_FREQUENCY=80
FILESIZE=10048576

WAIT_TRIES=200
RETRY_TIME=5
LOGFILE=log.txt
TESTFILE=test.txt
RESULTS_DIR="../../results/"
RESULTS_LABEL="-${NUMSERVERS}-${THRESHOLD}-${FILESIZE}"

# wait until a string occured multiple times in the log
wait_for() {
	STRING=$1
	COUNT=$2

	COUNTER=0
	while [[ $COUNTER -lt $WAIT_TRIES ]]
	do
		CURRENT_COUNT=$(cat ${LOGFILE} | grep "$STRING" | wc -l)

		[[ $CURRENT_COUNT -ge $COUNT ]] && return 0
		sleep 5
		COUNTER=$((COUNTER+1))
	done

	echo "Timeout for a string to appear in the logs! [$STRING]"
	exit 1
}

# build the application and change dirs
# cd /home/xvirgov/MThesis/repos/protect-xvirgov
#cd protect
#./build.sh
#cd bin

# generate a random file of set size (plaintext)
dd if=/dev/urandom of=test.txt bs=1 count=$FILESIZE

######################## ECIES ################################################

# run the application
#echo "log start" > $LOGFILE # this is here due to grep not working on bin files
#./setup-local-cluster.sh -n $NUMSERVERS -k $THRESHOLD -t protect_server -f $REFRESH_FREQUENCY >> $LOGFILE
#wait_for "http.HttpRequestProcessor - Ready to process requests." $((NUMSERVERS+1))
#echo "Cluster was started!"

sleep 5

# perform dkg
./interact-with-client.sh -c ecies -a gen -s prf-secret
wait_for "avpss.ApvssShareholder - DKG Complete!" $NUMSERVERS
echo "DKG was performed!"

# perform enc and dec with different sizes of plaintexts
COUNTER_ITERATIONS=0
COUNTER_REFRESH=0
while [[ $COUNTER_ITERATIONS -lt $((ITERATIONS)) ]]
do

	INNER_COUNTER=0
	while [[ $INNER_COUNTER -lt $ROUND_ITER ]]
	do
		sleep 1

		echo "Encrypting file..."
		./interact-with-client.sh -c ecies -a enc -s prf-secret -i $TESTFILE -o ciphertext.bin

		sleep 1

		echo "Decrypting file..."
		./interact-with-client.sh -c ecies -a dec -s prf-secret -i ciphertext.bin -o tmp-test.txt

		INNER_COUNTER=$((INNER_COUNTER+1))
	done

	diff $TESTFILE tmp-test.txt || echo "Decryted files were not the same!!"

	COUNTER_ITERATIONS=$((COUNTER_ITERATIONS+1))

	COUNTER_REFRESH=$((COUNTER_REFRESH+NUMSERVERS))
	wait_for "avpss.ApvssShareholder - Refresh Complete!" $COUNTER_REFRESH
done

./destroy-local-cluster.sh -t protect_server

./extract-stats.sh $RESULTS_LABEL
cp extracted/* $RESULTS_DIR

######################## RSA ################################################

# run the application
echo "log start" > $LOGFILE # this is here due to grep not working on bin files
./setup-local-cluster.sh -n $NUMSERVERS -k $THRESHOLD -t protect_server -f $REFRESH_FREQUENCY >> $LOGFILE
wait_for "http.HttpRequestProcessor - Ready to process requests." $((NUMSERVERS+1))
echo "Cluster was started!"

sleep 5

# generate keys
./interact-with-client.sh -c proactive-rsa -a gen -s rsa-secret
wait_for "Proactive refresh of RSA secret was successful for new epoch 0" $NUMSERVERS
echo "Key generation was performed!"

# perform enc and dec with different sizes of plaintexts
COUNTER_ITERATIONS=0
while [[ $COUNTER_ITERATIONS -lt $((ITERATIONS)) ]]
do

	INNER_COUNTER=0
	while [[ $INNER_COUNTER -lt $ROUND_ITER ]]
	do
		sleep 2

		echo "Encrypting file..."
		./interact-with-client.sh -c proactive-rsa -a enc -s rsa-secret -i $TESTFILE -o ciphertext.bin

		sleep 2

		echo "Decrypting file..."
		./interact-with-client.sh -c proactive-rsa -a dec -s rsa-secret -i ciphertext.bin -o tmp-test.txt

		INNER_COUNTER=$((INNER_COUNTER+1))
	done

	diff $TESTFILE tmp-test.txt || echo "Decryted files were not the same!!"

	COUNTER_ITERATIONS=$((COUNTER_ITERATIONS+1))

	wait_for "Proactive refresh of RSA secret was successful for new epoch ${COUNTER_ITERATIONS}" $NUMSERVERS
done

./destroy-local-cluster.sh -t protect_server

./extract-stats.sh $RESULTS_LABEL
cp extracted/* $RESULTS_DIR