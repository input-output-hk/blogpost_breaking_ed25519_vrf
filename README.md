To be able to run this script, one needs to install the `iquerejeta/h_string` branch of 
`input-output-hk/libsodium`. The reason why we need to use a branch is because the function
required to compute the public value `H` is not exposed by the public API. However, that
value is public and can be computed by the verifier. To that end, the only change 
we make is for the verifier to return the value of `H` when it verifies a proof.

First, fetch the correct branch and install libsodium:
```shell
git clone https://github.com/input-output-hk/libsodium.git
cd libsodium
git checkout iquerejeta/h_string

./autogen.sh
./configure
make
make install
```
Once we have libsodium installed, we can compile the test and run it, to extract 
a signature.
```shell
make run
```