#!/bin/bash -x

cd conf-tmp
 curl -k --cacert ca/ca-key-clients.pem --cert client/certs/cert-administrator --key client/keys/private-administrator "https://localhost:8080/generate-keys?cipher=kyber&secretName=rsa-secret"