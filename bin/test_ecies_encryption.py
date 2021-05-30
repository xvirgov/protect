import requests

#  curl -k -v --data-binary "@/home/xvirgov/MThesis/repos/protect-xvirgov/bin/conf-tmp/plain"   --cacert ca/ca-key-clients.pem --cert client/certs/cert-administrator --key client/keys/private-administrator "https://localhost:8080/ecies?operation=encrypt&secretName=prf-secret" --output cipher
#  curl -k -v --data-binary "@/home/xvirgov/MThesis/repos/protect-xvirgov/bin/conf-tmp/cipher"   --cacert ca/ca-key-clients.pem --cert client/certs/cert-administrator --key client/keys/private-administrator "https://localhost:8080/ecies?operation=decrypt&secretName=prf-secret" --output plain-after

# Key generation
#  curl -k --cacert ca/ca-key-clients.pem --cert client/certs/cert-administrator --key client/keys/private-administrator "https://localhost:8080/generate-keys?cipher=rsa&secretName=rsa-secret"

plaintext = open('/home/xvirgov/MThesis/repos/protect-xvirgov/bin/conf-tmp/plain', 'rb').read()
encryption = requests.post('https://localhost:8080/ecies?operation=encrypt&secretName=prf-secret', data=plaintext, verify=False) # TODO-thesis fix verification of certificates

ciphertext = encryption.content

decryption = requests.post('https://localhost:8080/ecies?operation=decrypt&secretName=prf-secret', data=ciphertext, verify=False)

print('Plaintext:')
print(plaintext)
print('Ciphertext:')
print(ciphertext)
print('Decrypted plaintext:')
print(decryption.content)