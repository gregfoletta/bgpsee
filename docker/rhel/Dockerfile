FROM redhat/ubi9

RUN dnf install libubsan libasan jansson make -y

COPY . /usr/local/src/bgpsee

WORKDIR /usr/local/src/bgpsee
RUN make
RUN cp bgpsee /usr/local/bin/

ENTRYPOINT ["bgpsee"]