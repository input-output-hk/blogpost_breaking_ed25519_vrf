The script here present works with the iquerejeta/h_string branch of
input-output-hk/libsodium. To build run gcc -Wl,-dead_strip -lsodium main.c -o test
after installing libsodium with
```shell
./autogen.sh
./configure
make
make install
```