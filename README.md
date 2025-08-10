# YAS-cli

Yet Another Security cli version

### Usage

YAS is secure file transfer cli-tool. Manage PGP keys with independent directory.

##### mode

`-e` manual file encryption, [-i file|dir] [-o output] [-pw password] [-msg message] [-debug]

`-d` manual file decryption, [-i file] [-o output] [-pw password] [-debug]

`-s` automatic send, [-i file|dir] [-debug]

`-r` automatic receive, [-i ip:port] [-o output] [-debug]

`-pe` pgp text encryption, [-i text] [-me file] [-you file] [-sign]

`-pd` pgp text decryption, [-i text] [-me file] [-you file] [-sign]

`-ps` pgp data encryption, [-i file|dir] [-o output] [-me file] [-you file] [-sign] [-debug]

`-pr` pgp data decryption, [-i file] [-o output] [-me file] [-you file] [-sign] [-debug]

`-pk` generate pgp key, [-o output] [-sign]

`-h` print help message

##### options

`-i` target file or directory, plain text, ip address

`-o` output file or directory path

`-pw` manual mode password

`-msg` manual mode message

`-me` private key file of current user

`-you` public key file of other user

`-sign` sign or verify, make 4k pgp key

`-debug` print debug message

##### examples

```bash
yas -e -i dir_t -o enc.bin -msg zeros

yas -d -i enc.bin -pw 0000

yas -s -i dir_t -i file_t -debug

yas -r -i 192.168.0.2:1234 -o ../

yas -pe -i "secret" -you bob/public.txt -sign

yas -pd -i "..." -me alice/private.txt

yas -ps -i file_t -o enc.bin -me alice/private.txt -you bob/public.txt -sign -debug

yas -pr -i enc.bin -me alice/private.txt -you bob/public.txt

yas -pk -sign

yas -h
```

### YAS Protocol

`sender` generate RSA key pair

`sender` send RSA public key (8B size + nB data)

`receiver` generate session key and encrypt with RSA public key

`receiver` send encrypted session key (8B size + nB data)

`sender` decrypt session key and zip & encrypt data

`sender` send status code (8B) while doing data encryption
`0x0000000000000000 : wait, 0xFFFFFFFFFFFFFFFF : quit, else : size of data`

`receiver` get data size from status code and receive data

`receiver` send exit code, non-zero exit code will show warning
`0x0000000000000000 : safe exit, else : abnormal exit`

`receiver` decrypt and unzip data
