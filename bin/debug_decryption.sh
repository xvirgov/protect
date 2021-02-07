#!/bin/bash -x

cd conf-tmp

sudo curl -k -v --data-binary "@/home/xvirgov/MThesis/repos/protect-xvirgov/bin/cipher"   --cacert ca/ca-key-clients.pem --cert client/certs/cert-administrator --key client/keys/private-administrator "https://localhost:8080/decrypt?cipher=rsa&secretName=rsa-secret" --output plain-after
#sudo curl -k -v --data-binary "@/home/xvirgov/MThesis/repos/protect-xvirgov/bin/plain"   --cacert ca/ca-key-clients.pem --cert client/certs/cert-administrator --key client/keys/private-administrator "https://localhost:8080/decrypt?cipher=rsa&secretName=rsa-secret" --output ciphertext