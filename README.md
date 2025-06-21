# YAS-cli

Yet Another Security cli version

### Usage

```bash
yas [mode] [options] targets[...]
```

`send mode` is the default mode.

starting without cli parameters will enable interpreting mode.

##### mode

`-s` send mode will transmit files and directories to remote user.
you can use `-debug` option.

`-r` receive mode will get files and directories from remote user.
you can use `-o -debug` options.

`-e` encrypt mode will encrypt files with password and message.
you can use `-o -pw -msg -debug` options.

`-d` decrypt mode will decrypt file with password.
you can use `-o -pw -debug` options.

`-help` help mode will print usage text.

##### options

`-o` designate output path. files and directories will be generated at this path.

`-pw` designate password.

`-msg` designate message.

`-debug` program will not delete temp files with this option.

##### targets

target file / directory / ip address (IP:port).

can use multiple parameters by iterating all targets.

##### examples

```bash
yas dir_t

yas -s -debug file_t dir_t

yas -r 192.168.0.1:5000 -o ../

yas -e file_t -pw 0000 -msg zeros -o end.bin

yas -d file_t -pw 0000
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
