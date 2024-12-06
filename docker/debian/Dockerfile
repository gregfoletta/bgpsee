FROM debian

RUN apt update
RUN apt install libubsan1 libasan8 libjansson-dev make -y

COPY . /usr/local/src/bgpsee

WORKDIR /usr/local/src/bgpsee
RUN make
RUN cp bgpsee /usr/local/bin/

ENTRYPOINT ["bgpsee"]