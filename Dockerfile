FROM python:2.7-stretch
WORKDIR /b3DS
COPY b3DSDecrypt.py /b3DS/D.py
COPY b3DSEncrypt.py /b3DS/E.py
RUN pip install pycrypto
ENTRYPOINT [ "python" ]