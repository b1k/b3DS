# b3DS
A 3DS/New 3DS Rom Decryptor and Encrypter

### If anyone wants to improve on the code, feel free to do so.

## Prerequisites
* Python 2.7+
* pip
* pycrypto

## Installation
After you've installed the latest version of Python 2, run `pip install pycrypto` in command prompt.

## Usage
python b3DSEncrypt.py "File location of rom" eg. C:\Users\User\Downloads\New Super Mario Bros. 2 (USA).3ds

## Status
Supports all known crypto-types: 

* Normal (Key 0x2C)
* 7.x (Key 0x25)
* New3DS 9.3 (Key 0x18)
* New3DS 9.6 (Key 0x1B)

## Docker

You can use docker.  
For the first time or to rebuild use `docker compose up -d --build --remove-orphans`.
That would create the image and three folders.  
Put your encrypted files in the folder `to_decrypt` and run the container with `docker compose up`.
After its stop the decrypted files are in the folter `output`. 