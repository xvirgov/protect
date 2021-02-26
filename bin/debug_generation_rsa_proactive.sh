#!/bin/bash -x

cd conf-tmp
sudo curl -k --cacert ca/ca-key-clients.pem --cert client/certs/cert-administrator --key client/keys/private-administrator "https://localhost:8080/generate-keys?cipher=proactive-rsa&secretName=rsa-secret"