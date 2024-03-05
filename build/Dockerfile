FROM python:2.7.18-stretch

WORKDIR b3DS

COPY build/entrypoint.sh .
COPY b3DSEncrypt.py .
COPY b3DSDecrypt.py .

RUN pip install pycrypto

CMD bash entrypoint.sh