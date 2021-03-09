#!/bin/bash -x

cd conf-tmp
sudo curl -k -vvv --data-binary "@/home/xvirgov/MThesis/repos/protect-xvirgov/bin/plain"   --cacert ca/ca-key-clients.pem --cert client/certs/cert-administrator --key client/keys/private-administrator "https://localhost:8080/encrypt?cipher=ecies&secretName=prf-secret" --output ../ciphertext
