FROM debian:testing-slim as base

RUN apt-get update && apt-get install --no-install-recommends -yV \
    dpkg-dev \
    wget \
    ca-certificates

RUN mkdir /debs/
RUN wget --directory-prefix=/debs/ https://github.com/lacchain/liboqs-debian/releases/download/0.4.0/liboqs-dev_0.4.0_amd64.deb
RUN wget --directory-prefix=/debs/ https://github.com/lacchain/liboqs-debian/releases/download/0.4.0/liboqs_0.4.0_amd64.deb
RUN wget --directory-prefix=/debs/ https://github.com/lacchain/liboqs-debian/releases/download/0.4.0/SHA256SUMS
RUN cd /debs/ && sha256sum --check --ignore-missing --status SHA256SUMS && dpkg-scanpackages . /dev/null | gzip -9c > Packages.gz
RUN echo "deb [trusted=yes] file:/debs ./" >> /etc/apt/sources.list

FROM base as builder

RUN apt-get update && apt-get install --no-install-recommends -yV \
    build-essential \
    devscripts \
    equivs

WORKDIR /openssl-pqe-engine-0.1.0/

COPY debian                        ./debian/

ENV DEBIAN_FRONTEND noninteractive
ENV DEBIAN_PRIORITY critical
ENV DEBCONF_NOWARNINGS yes

RUN mk-build-deps -irt 'apt-get --no-install-recommends -yV' ./debian/control
RUN rm -rf /var/lib/apt/lists/*

COPY CMakeLists.txt                ./
COPY ibrand_common                 ./ibrand_common/
COPY ibrand_lib                    ./ibrand_lib/
COPY ibrand_service                ./ibrand_service/
COPY ibrand_engine                 ./ibrand_engine/
COPY ibinit_engine                 ./ibinit_engine/

RUN debuild -b -uc -us -nc

FROM base as runner

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
    liboqs \
 && rm -rf /var/lib/apt/lists/*

COPY ./_sample_data/ibrand_openssl.cnf $HOME/.ibrand
COPY --from=builder /openssl-pqe-engine_0.1.0_amd64.deb .

RUN dpkg -i ./openssl-pqe-engine_0.1.0_amd64.deb
RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
RUN mkdir -p /var/lib/ibrand/
RUN mkdir /certs/
RUN mkdir /oob/
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
curl --http1.1 --silent --fail --show-error --cert /certs/client.crt --key /certs/client.key --header "Content-Type: application/json" --data-raw "{\"clientCertName\":\"monarca.iadb.org\", \"clientCertSerialNumber\":\"$certSerial\", \"countryCode\":\"GB\", \"channels\":[{\"type\":\"email\", \"value\":\"diegol@iadb.org\"}, {\"type\":\"email\", \"value\":\"diegol1@iadb.org\"}, {\"type\":\"email\", \"value\":\"diegol2@iadb.org\"}], \"kemAlgorithm\":\"222\"}" https://$SERVER_HOST/api/clientsetupdata -o /oob/ironbridge_clientsetup_OOB_1.json\n\
slices=$(curl -s http://$SMTP_HOST:1080/messages | jq length)\n\
sleep 1\n\
i=1\n\
while [ "$i" -le "$slices" ]; do\n\
  curl -s http://$SMTP_HOST:1080/messages/$i.plain -o /oob/ironbridge_clientsetup_OOB_$(($i + 1)).json\n\
  i=$(($i + 1))\n\
done\n\
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
    "PREFERRED_KEM_ALGORITHM":"222",\n\
    "CLIENTSETUP_OOB_PATH":"/oob/",\n\
    "CLIENTSETUP_OOB1_FILENAME":"ironbridge_clientsetup_OOB_1.json",\n\
    "CLIENTSETUP_OOBN_FILENAME":"ironbridge_clientsetup_OOB_%d.json",\n\
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
    "FILE_HIGHWATERMARK":"30000",\n\
    "FILE_LOWWATERMARK":"20000",\n\
    "SHMEM_BACKINGFILENAME":"shmem_ibrand01",\n\
    "SHMEM_SEMAPHORENAME":"sem_ibrand01",\n\
    "SHMEM_STORAGESIZE":"102400",\n\
    "SHMEM_LOWWATERMARK":"40960",\n\
    "IDLEDELAY":"1"\n\
  }\n\
}\n\
_EOF_\n\
export OPENSSL_CONF=$HOME/.ibrand/ibrand_openssl.cnf\n\
export IBRAND_CONF=/ibrand.cnf\n\
ibrand_service\n\
openssl engine\n\
#tail -f /var/log/syslog\n'\
sleep 15\n\
openssl rand 24\n\
ret=$?\n\
curl -v http://$SERVER_HOST:8080/shutdown\n\
curl -v http://$SMTP_HOST:8080/shutdown\n\
exit $ret\n'\
>> /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]

FROM sj26/mailcatcher as mailcatcher

RUN wget https://github.com/msoap/shell2http/releases/download/1.13/shell2http_1.13_amd64.deb
RUN echo "4f41498fd58b9ddb856aef7ef59c267a3cf681a7d576eb9a73a376f5e88e92b2 shell2http_1.13_amd64.deb" | sha256sum --check --status
RUN dpkg -i shell2http_1.13_amd64.deb

RUN echo '#!/bin/sh\n\
set -x\n\
shell2http /shutdown "kill \$(ps aux | grep '\''[/]usr/local/bin/ruby '\'' | awk '\''{print \$2}'\'')" &>/dev/null\n\
mailcatcher --foreground --ip 0.0.0.0\n'\
>> /run.sh

RUN chmod +x /run.sh

ENTRYPOINT []
CMD ["/run.sh"]
