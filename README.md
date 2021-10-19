# Protected network storage

This is a training university project to try and analyze different cryptography
algorithms. The aim of the project is to create protected network storage. The
implementation is divided into two parts. The server part should run on some
remote server. It accepts messages from the clients and stores their string
data (in memory). The client part can run anywhere else. It connects to the
server and can interact with it by sending or receiving strings (which are
called files in the code).

# Used algorithms

The flow of the program is as follows:

- The client generates an RSA key pair and sends the public key to the server.
Loading and saving the keys to the local storage is also supported. The server
identifies clients by their RSA keys, no other information is required.

- The client requests a session key from the server.

- The server generates a random 256-bit session key, which will be used as an
AES-256-CBC encryption key. This key is temporary and will expire in an hour.
Then the server encrypts the session key with the client public RSA key, and
sends everything to the client.

- The client requests some operation with the storage, providing a file name
and, possibly, file content (both encrypted using AES-256-CBC with the session
key and a random initialization vector). To ensure the file will not be
available to an attacker who has access to the server storage, it additionally
encrypts the file content using AES-256-CBC with SHA-256 hash of the client
local password as a key and a random initialization vector. The filenames are
also not passed to the server in the original form, their SHA-256 hashes are
used instead.

- The server receives the request, decrypts the filename and, possible, file
content (using the session key), and performs the requested operation (for
example, updating or deleting the file). If necessary, it returns some content
to the client (encrypting it using AES-256-CBC with the session key and a random
initialization vector).

Generally, this flow provides the following guarantees:

- MITM attacks on any stage of the process will be unsuccessfull. No information
about the client files (including, for example, the information on whether the
client requests updating the same file several times, or whether the different
clients have files with the same names or content) will be available to the
attacker. This is achieved by using the RSA algorithm for the initial
authorization, and the AES-256-CBC algorithm for all the next steps.

- The only information the attacker having read access to the server can
extract is whether the client requests updating the same file several times, or
whether the different clients have files with the same names. No other
information (including real file names, or any information regarding files
content) will be available to the attacker. This is achieved by hashing files
names using the SHA-256 algorithm, and encrypting files content using the
AES-256-CBC algorithm with local user password (not known to the server) as a
key on the client side.

It's important to note that if the client loses theirs local password,
the files' recovery will be impossible due to the nature of the used algorithms.

# Build instructions

The project uses [Bazel](https://bazel.build/) build system, [Abseil](https://abseil.io/)
library, [Google Protocol Buffers](https://developers.google.com/protocol-buffers)
library and [CryptoPP](https://cryptopp.com/) library.
[Unix sockets](https://man7.org/linux/man-pages/man2/socket.2.html) are
responsible for organizing the network communication.

CryptoPP library is supposed to be built and linked as a shared library. Headers
for [CryptoPP 8.6+](https://github.com/weidai11/cryptopp/tree/efbab52cf165ab774c23f13e8d9aae3d560ba82f)
and a built shared library file are available in the repo. If you want to
update them, please build the library by yourselves according to the
instructions on the official site.

To build the project, you need to install Bazel and a Protocol Buffers compiler.
All the other components will be fetched automatically by Bazel. The project
was developed in [CLion](https://www.jetbrains.com/clion/) with the
[Bazel plugin by Google](https://plugins.jetbrains.com/plugin/9554-bazel),
although this is not required.

# Run instructions

Build client and server executables using *bazel build* command and make sure
they can locate the CryptoPP shared library (which is originally present in the
*cryptopp/* subdirectory).
