#!/bin/bash
# Set all the following variables as per yor 
export OAUTH_URL=http://127.0.0.1:5000/oauth/token
export CLIENT_ID=yourClientID
export CLIENT_SECRET=yourClientSecret
export AZURE_ENDPOINT="https://sourcegraph-test-oai.openai.azure.com/"


openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:4096
openssl req -x509 -new -nodes -key key.pem -sha256 -days 365 -out cert.pem -config cert.conf -batch
