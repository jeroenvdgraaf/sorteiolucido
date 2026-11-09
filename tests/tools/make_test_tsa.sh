#!/bin/sh
# (Re)gera a PKI de TESTE usada pelos testes de carimbo de tempo: CA, certificado e chave da TSA.
# Somente para testes; nunca use estas chaves para nada real.
set -eu
D="$(cd "$(dirname "$0")/../fixtures/tsa" 2>/dev/null || mkdir -p "$(dirname "$0")/../fixtures/tsa" && cd "$(dirname "$0")/../fixtures/tsa"; pwd)"
cd "$D"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 7300 \
  -subj "/O=SorteioLucido TEST/CN=Test Root CA (not real)" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tsa.key -out tsa.csr -subj "/O=SorteioLucido TEST/CN=Test TSA (not real)" 2>/dev/null
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n' > tsa.ext
openssl x509 -req -in tsa.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tsa.crt -days 7300 -extfile tsa.ext 2>/dev/null
rm -f tsa.csr tsa.ext ca.srl ca.key
# Uma CA estranha, para testar cadeia não confiável.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout other.key -out other-ca.crt -days 7300 -subj "/CN=Unrelated CA (not real)" 2>/dev/null
rm -f other.key
echo "PKI de teste gerada em $D"
