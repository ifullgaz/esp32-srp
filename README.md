esp32-srp
============
Derived from https://github.com/dwimberger/mbedtls-csrp

esp32-srp is a minimal C implementation of the [Secure Remote Password
protocol](http://srp.stanford.edu/). The project consists of a single
C file and is intended for direct inclusion into utilizing programs. 
It's only dependency is mbedtls (https://github.com/ARMmbed/mbedtls).
It can be dropped as is as a component in an ESP-IDF project.

SRP Overview
------------

SRP is a cryptographically strong authentication
protocol for password-based, mutual authentication over an insecure
network connection.

Unlike other common challenge-response autentication protocols, such
as Kereros and SSL, SRP does not rely on an external infrastructure
of trusted key servers or certificate management. Instead, SRP server
applications use verification keys derived from each user's password
to determine the authenticity of a network connection.

SRP provides mutual-authentication in that successful authentication
requires both sides of the connection to have knowledge of the
user's password. If the client side lacks the user's password or the
server side lacks the proper verification key, the authentication will
fail.

Unlike SSL, SRP does not directly encrypt all data flowing through
the authenticated connection. However, successful authentication does
result in a cryptographically strong shared key that can be used
for symmetric-key encryption.

Entropy
-------

You need to take care of entropy to achieve cryptograhically sound random values.
For real world use, you should change the implementation in srp_crypto_random_init() to supply your own seed
values. Also make sure to add entropy sources to your mbedtls port.

Installation
------------

Extract or clone the module directly into the components directory of your project

Test
----

The test can be ran from the command line as a normal ESP-IDF project.
Simply run ```make flash``` to run on a connected esp32 board.
In the test Makefile, you can uncomment the line that defines the ```_SRP_TEST_VECTOR``` constant to use hard coded test vectors.

Usage
-----

Please look at the test source file for an example of interaction between SRP client and server