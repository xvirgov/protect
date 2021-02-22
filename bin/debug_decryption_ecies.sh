#!/bin/bash -x

cd conf-tmp

sudo curl -k -v --data-binary "@/home/xvirgov/MThesis/repos/protect-xvirgov/bin/ciphertext"   --cacert ca/ca-key-clients.pem --cert client/certs/cert-administrator --key client/keys/private-administrator "https://localhost:8080/decrypt?cipher=ecies&secretName=prf-secret" --output plain-after
