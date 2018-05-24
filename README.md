# libsignal-protocol-javascript

Committing Encrypt-then-PRF (CEP) implementation based on 
[libsignal-protocol-javascript](https://github.com/signalapp/libsignal-protocol-javascript).

```
/sample     # [CEP] Sample client/server code that uses CEP
/original   # [CEP] Original library for comparing performance
/report     # [CEP] Usage, testing results, and discussion
/dist       # Distributables
/build      # Intermediate build files
/src        # JS source files
/native     # C source files for curve25519
/protos     # Protobuf definitions
/test       # Tests
```

## Overview
An implementation of CEP (Committing Encrypt-then-PRF), 
which is proposed and theoretically proved in 
[Message Franking via Committing Authenticated Encryption](https://eprint.iacr.org/2017/664).
In an end-to-end encrypted messaging scenario (i.e., libsignal),
the goal of CEP (or message franking) is to allow 
a receiver to report verifiable abused messages to the server.

Compared to the standard end-to-end encryption
(where only two clients manipulate messages),
CEP needs the server to MAC each message,
and then the receiver may need to report to the server later.
Hence, there are API changes in the format of not only cipher messages
but also *decrypted output*.
Such interfaces are needed to implement message franking correctly.
See the 
[report](https://github.com/RippleLeaf/libsignal-protocol-javascript/blob/master/report/cep.pdf)
for details.
