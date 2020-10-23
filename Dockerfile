FROM debian:testing-slim as builder

RUN apt-get update && apt-get install --no-install-recommends -yV \
    build-essential \
    devscripts \
    equivs

WORKDIR /openssl-pqe-engine-0.1.0/

COPY CMakeLists.txt                ./
COPY ibrand_common                 ./ibrand_common/
COPY ibrand_lib/CMakeLists.txt     ./ibrand_lib/
COPY ibrand_lib/software           ./ibrand_lib/software/
COPY ibrand_service                ./ibrand_service/
COPY ibrand_openssl                ./ibrand_openssl/
COPY PQCrypto-LWEKE/CMakeLists.txt ./PQCrypto-LWEKE/
COPY PQCrypto-LWEKE/src            ./PQCrypto-LWEKE/src/
COPY debian                        ./debian/

ENV DEBIAN_FRONTEND noninteractive
ENV DEBIAN_PRIORITY critical
ENV DEBCONF_NOWARNINGS yes

RUN mk-build-deps -irt 'apt-get --no-install-recommends -yV' ./debian/control
RUN rm -rf /var/lib/apt/lists/*
RUN debuild -b -uc -us -nc

FROM debian:testing-slim as runner

RUN apt-get update && apt-get install --no-install-recommends -yV \
    openssl \
    ca-certificates \
    libcurl4 \
    rsyslog \
    curl \
    jq \
 && rm -rf /var/lib/apt/lists/*

COPY ./_sample_data/ibrand_openssl.cnf /usr/lib/ssl/
COPY --from=builder /openssl-pqe-engine_0.1.0_amd64.deb .

RUN dpkg -i ./openssl-pqe-engine_0.1.0_amd64.deb
RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
RUN mkdir -p /var/lib/ibrand/
RUN echo '#!/bin/sh\n\
set -x\n\
service rsyslog start\n\
certSerial=$(openssl x509 -noout -serial -in /certs/client.pem | cut -d'\''='\'' -f2)\n\
jwtToken=$(curl --http1.1 --silent --cert /certs/client.pem --key /certs/client_key.pem --data-raw "" '\''https://ironbridgeapi.com/api/login'\'' | jq -r '\''.token'\'')\n\
# Diago's config:
#curl --http1.1 --silent --fail --show-error --cert /certs/client.pem --key /certs/client_key.pem --header "Authorization: Bearer $jwtToken" --header "Content-Type: application/json" --data-raw "{\"clientCertName\":\"monarca.iadb.org\", \"clientCertSerialNumber\":\"$certSerial\", \"countryCode\":\"GB\", \"smsNumber\":\"10000000001\", \"email\":\"diegol@iadb.org\", \"keyparts\": \"2\", \"kemAlgorithm\":\"222\"}" '\''https://ironbridgeapi.com/api/setupclient'\'' -o /ironbridge_clientsetup_OOB.json\n\
# Ben's config:
curl --http1.1 --cert /certs/client.pem --key /certs/client_key.pem --header "Authorization: Bearer $jwtToken" --header "Content-Type: application/json" --data-raw "{\"clientCertName\":\"client.ironbridgeapi.com\", \"clientCertSerialNumber\":\"$certSerial\", \"countryCode\":\"GB\", \"smsNumber\":\"10000000001\", \"email\":\"ben.merriman@cambridgequantum.com\", \"keyparts\": \"2\", \"kemAlgorithm\":\"222\"}" '\''https://ironbridgeapi.com/api/setupclient'\'' -o /ironbridge_clientsetup_OOB.json\n\
ret=$?\n\
if [ $ret -ne 0 ] ; then\n\
  exit 1\n\
fi\n\
cat > /ibrand.cnf <<_EOF_\n\
JSON:{\n\
  "GeneralSettings":\n\
  {\n\
    "_1_Verbosity_bitmapped_field":"STATUS=1, CONFIG=2, PROGRESS=4, AUTH=8, DATA=16, CURL=32, SPARE6=64, SPARE7=128",\n\
    "LOGGING_VERBOSITY":"27"\n\
  },\n\
  "AuthSettings":\n\
  {\n\
    "AUTHTYPE":"CLIENT_CERT",\n\
    "AUTHURL":"https://ironbridgeapi.com/api/login",\n\
    "AUTHUSER":"notused1",\n\
    "AUTHPSWD":"notused2",\n\
    "AUTHSSLCERTTYPE":"PEM",\n\
    "AUTHSSLCERTFILE":"/certs/client.pem",\n\
    "AUTHSSLKEYFILE":"/certs/client_key.pem",\n\
    "AUTHRETRYDELAY":"5"\n\
  },\n\
  "SecuritySettings":\n\
  {\n\
    "USESECURERNG":"1",\n\
    "CLIENTSETUPOOBFILENAME":"/ironbridge_clientsetup_OOB.json",\n\
    "OURKEMSECRETKEYFILENAME":"/ibrand_sk.bin"\n\
  },\n\
  "CommsSettings":\n\
  {\n\
    "BASEURL":"https://ironbridgeapi.com/api",\n\
    "BYTESPERREQUEST":"256",\n\
    "RETRIEVALRETRYDELAY":"3"\n\
  },\n\
  "StorageSettings":\n\
  {\n\
    "STORAGETYPE":"SHMEM",\n\
    "STORAGEDATAFORMAT":"RAW",\n\
    "STORAGEFILENAME":"/ibrand_data.bin",\n\
    "STORAGELOCKFILEPATH":"/tmp",\n\
    "SHMEM_BACKINGFILENAME":"shmem_ibrand01",\n\
    "SHMEM_STORAGESIZE":"20480",\n\
    "SHMEM_SEMAPHORENAME":"sem_ibrand01",\n\
    "STORAGEHIGHWATERMARK":"20480",\n\
    "STORAGELOWWATERMARK":"5120",\n\
    "IDLEDELAY":"3"\n\
  }\n\
}\n\
_EOF_\n\
export OPENSSL_CONF=/usr/lib/ssl/ibrand_openssl.cnf\n\
export IBRAND_CONF=/ibrand.cnf\n\
ibrand_service -f /ibrand.cnf\n\
openssl engine\n\
#tail -f /var/log/syslog\n'\
sleep 15\n\
openssl rand 24\n'\
>> /run.sh
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
