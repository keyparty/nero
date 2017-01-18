FROM scratch
MAINTAINER Pete Birley <pete@port.direct>
ADD nero /nero
ENTRYPOINT ["/nero"]
