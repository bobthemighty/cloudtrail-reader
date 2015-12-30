FROM alpine:3.3
ADD src/requirements.txt /opt/cloudtrail-reader/
RUN apk add --no-cache python && \
    apk add --no-cache --virtual=build-dependencies wget ca-certificates && \
    wget "https://bootstrap.pypa.io/get-pip.py" -O /dev/stdout | python && \
    pip install -r /opt/cloudtrail-reader/requirements.txt
ADD src/*.py /opt/cloudtrail-reader/
CMD ["python", "/opt/cloudtrail-reader/cloudtrail-reader.py"]
