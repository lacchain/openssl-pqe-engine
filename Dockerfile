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

ENV SERVER_HOST=ironbridgeapi.com

RUN apt-get update && apt-get install --no-install-recommends -yV \
    openssl \
    ca-certificates \
    libcurl4 \
    rsyslog \
    curl \
    jq \
    wait-for-it \
    file \
 && rm -rf /var/lib/apt/lists/*

COPY ./_sample_data/ibrand_openssl.cnf /usr/lib/ssl/
COPY --from=builder /openssl-pqe-engine_0.1.0_amd64.deb .

RUN dpkg -i ./openssl-pqe-engine_0.1.0_amd64.deb
RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
RUN mkdir -p /var/lib/ibrand/
RUN mkdir /certs/
RUN echo '#!/bin/sh\n\
set -x\n\
service rsyslog start\n\
cp /ca-certs/root.crt /usr/local/share/ca-certificates/\n\
update-ca-certificates -v\n\
openssl genrsa -out /certs/client.key 2048\n\
openssl req -new -sha512 -key /certs/client.key -subj "/C=US/ST=CA/O=IADB/CN=client" -out /certs/client.csr\n\
openssl x509 -req -in /certs/client.csr -CA /ca-certs/root.crt -CAkey /ca-certs/root.key -CAcreateserial -out /certs/client.crt -days 500 -sha512\n\
certSerial=$(openssl x509 -noout -serial -in /certs/client.crt | cut -d'\''='\'' -f2)\n\
curl --http1.1 --fail --show-error --silent --cert /certs/client.crt --key /certs/client.key https://$SERVER_HOST/api/testconnection\n\
ret=$?\n\
if [ $ret -ne 0 ] ; then\n\
  exit 1\n\
fi\n\
curl --http1.1 --silent --fail --show-error --cert /certs/client.crt --key /certs/client.key --header "Content-Type: application/json" --data-raw "{\"clientCertName\":\"monarca.iadb.org\", \"clientCertSerialNumber\":\"$certSerial\", \"countryCode\":\"GB\", \"smsNumber\":\"10000000001\", \"email\":\"diegol@iadb.org\", \"keyparts\": \"2\", \"kemAlgorithm\":\"222\"}" https://$SERVER_HOST/api/setupclient -o /ironbridge_clientsetup_OOB.json\n\
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
    "AUTHURL":"https://$SERVER_HOST/api/login",\n\
    "AUTHUSER":"notused1",\n\
    "AUTHPSWD":"notused2",\n\
    "AUTHSSLCERTTYPE":"PEM",\n\
    "AUTHSSLCERTFILE":"/certs/client.crt",\n\
    "AUTHSSLKEYFILE":"/certs/client.key",\n\
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
    "BASEURL":"https://$SERVER_HOST/api",\n\
    "BYTESPERREQUEST":"4096",\n\
    "RETRIEVALRETRYDELAY":"3"\n\
  },\n\
  "StorageSettings":\n\
  {\n\
    "STORAGETYPE":"SHMEM",\n\
    "FILE_DATAFORMAT":"RAW",\n\
    "FILE_FILENAME":"/ibrand_data.bin",\n\
    "FILE_LOCKFILEPATH":"/tmp",\n\
    "FILE_HIGHWATERMARK":"20480",\n\
    "FILE_LOWWATERMARK":"5120",\n\
    "SHMEM_BACKINGFILENAME":"shmem_ibrand01",\n\
    "SHMEM_SEMAPHORENAME":"sem_ibrand01",\n\
    "SHMEM_STORAGESIZE":"102400",\n\
    "SHMEM_LOWWATERMARK":"40960",\n\
    "IDLEDELAY":"1"\n\
  }\n\
}\n\
_EOF_\n\
export OPENSSL_CONF=/usr/lib/ssl/ibrand_openssl.cnf\n\
export IBRAND_CONF=/ibrand.cnf\n\
ibrand_service\n\
openssl engine\n\
#tail -f /var/log/syslog\n'\
sleep 15\n\
openssl rand 24\n\
curl -v http://$SERVER_HOST:8080/shutdown\n'\
>> /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
