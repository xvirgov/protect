#!/bin/bash -e

NODES_NR=$1
CA_KEY=ca-key-server
CA_CERT=ca-cert-server
CLIENT_CERT=cert
#clientPK=public
CLIENT_SK=private

mkdir -p ca server/certs server/keys

# Generate keys and certificates for servers
i=1
while [ $i -le "$NODES_NR" ]
do
	java -classpath ../../pross-server/target/pross-server-1.0-SNAPSHOT.jar com.ibm.pross.server.app.KeyGeneratorCli server/keys $i
	openssl req -new -sha256 -key server/keys/$CLIENT_SK-$i -out my-$i.csr -subj '/CN=Server client '$i'/ST=TEST/O=TEST'
	openssl ecparam -name secp521r1 -genkey -noout -out ca/$CA_KEY-$i
	openssl req -x509 -new -nodes -key ca/$CA_KEY-$i -sha256 -days 1024 -out ca/$CA_CERT-$i.pem -subj '/CN=CA Server '$i'/ST=TEST/O=TEST'
	openssl x509 -req -in my-$i.csr -CA ca/$CA_CERT-$i.pem -CAkey ca/$CA_KEY-$i -CAcreateserial -out server/certs/$CLIENT_CERT-$i -days 500 -sha256 -extensions v3_ca -extfile ./ssl-extensions-x509.cnf
	rm my-$i.csr
	rm ca/$CA_CERT-$i.srl
	i=$((i+1))
done

java -classpath ../../pross-server/target/pross-server-1.0-SNAPSHOT.jar com.ibm.pross.server.app.KeyGeneratorCli server/keys 0
#openssl req -new -sha256 -key server/keys/$CLIENT_SK-0 -out my-0.csr -subj '/CN=Server client '0'/ST=TEST/O=TEST'
#openssl ecparam -name secp521r1 -genkey -noout -out ca/$CA_KEY-0
#openssl req -x509 -new -nodes -key ca/$CA_KEY-0 -sha256 -days 1024 -out ca/$CA_CERT-0.pem -subj '/CN=CA Server '0'/ST=TEST/O=TEST'
#openssl x509 -req -in my-0.csr -CA ca/$CA_CERT-0.pem -CAkey ca/$CA_KEY-0 -CAcreateserial -out server/certs/$CLIENT_CERT-0 -days 500 -sha256 -extensions v3_ca -extfile ./ssl-extensions-x509.cnf
#rm my-0.csr
#rm ca/$CA_CERT-0.srl

## Generate key and certificate for a client
#openssl ecparam -name secp521r1 -genkey -noout -out private.key
#openssl req -new -sha256 -key private.key -out my.csr -subj '/CN=Client App/ST=TEST/O=TEST'
#openssl ecparam -name secp521r1 -genkey -noout -out ca-key
#openssl req -x509 -new -nodes -key ca-key -sha256 -days 1024 -out ca-cert -subj '/CN=CA Client App/ST=TEST/O=TEST'
#openssl x509 -req -in my.csr -CA ca-cert -CAkey ca-key -CAcreateserial -out cert -days 500 -sha256 -extensions v3_ca -extfile ./ssl-extensions-x509.cnf
##Formats into PKCS8
#openssl pkey -in private.key -out private
