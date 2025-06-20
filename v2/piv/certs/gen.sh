#!/bin/bash -e

rm -f *.pem
curl -O https://developers.yubico.com/PKI/yubico-ca-certs.txt
curl -O https://developers.yubico.com/PKI/yubico-ca-1.pem
curl -O https://developers.yubico.com/PKI/yubico-intermediate.pem
echo "Timestamp: $( date -u )" > metadata.txt
