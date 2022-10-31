# tink-aead-cli
An implementation of Google Tink CLI for AEAD encryption based on Tink-Golang

## Usage:

```sh
Usage of tink-aead-cli:
-a string
    associated data to be encrypted/decrypted
-c string
    Cipher text file path to be encrypted/decrypted
-k string
    Stored DEK that is encrypted by KEK in KMS
-m string
    mode configuration, can be one of 'encrypt' or 'decrypt'
-p string
    Platin text file path to be encrypted/decrypted
-s string
    cerdential file for accessing kms
-t string
    Key templates for aead, can be one of: AES256CTRHMACSHA256,AES256GCMNoPrefix,ChaCha20Poly1305,AES128CTRHMACSHA256,AES128GCM (default "AES128GCM")
-u string
    kms key uri, can only be started with gcp-kms://
```

## Templates
Non-Streaming: AES128CTRHMACSHA256,AES128GCM,AES256CTRHMACSHA256,AES256GCMNoPrefix,ChaCha20Poly1305
Streaming: AES128CTRHMACSHA256,AES128GCM,AES256CTRHMACSHA256,AES256GCMNoPrefix,ChaCha20Poly1305

## Examples:

1. Encrypt plain text file by envelope encryption (DEK is stored in output cipher text file)
```sh
tink-aead-cli -m encrypt -p plainTextFile -c cipherTextFile -s credentials.json -u gcp-kms://xxx
```

2. Decrypt cipher text file by envelope encryption (DEK is stored in input cipher text file)
```sh
tink-aead-cli -m decrypt -p plainTextFile -c cipherTextFile -s credentials.json -u gcp-kms://xxx
```

3. Encrypt plain text file by stored keyset. (DEK is stored in a separate file)
```sh
tink-aead-cli -m encrypt -p plainTextFile -c cipherTextFile -k keyFile -s credentials.json -u gcp-kms://xxx
```

4. Decrypt cipher text file by stored keyset. (DEK is stored in a separate file)
```sh
tink-aead-cli -m decrypt -p plainTextFile -c cipherTextFile -k keyFile -s credentials.json -u gcp-kms://xxx
```

5. Create a data encryption key (DEK). (DEK will be stored in a separate file)
```sh
tink-aead-cli -m newkey -k keyFile -s credentials.json -u gcp-kms://xxx
```

# Build from source

```sh
./build.sh
```
