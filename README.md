# b3DS
A 3DS/New 3DS Rom Decryptor and Encrypter
## Prerequisites
* Python 2.7+
* pip
* pycrypto

## With docker (recommended)
```sh
docker build -t b3ds:latest # to build docker image
docker run b3ds (D/E).py # D for decrypt and E for Encrypt
```

## Usage
```sh
python b3DSEncrypt.py (file.3ds) # to encrypt 3ds file
python b3DSDecrypt.py (file.cia) # to decrypt cia file
```
## Support
Supports all known crypto-types:

* Normal (Key 0x2C)
* 7.x (Key 0x25)
* New3DS 9.3 (Key 0x18)
* New3DS 9.6 (Key 0x1B)
