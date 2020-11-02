# Mini TLS Crawler

A tool for crawling the IPv4 space and saving data resultant from a TLS handshake. This can include: certificates, key exchange information, and TCP/IP information.

## Prerequisites

This project must be run in Linux with MySQL and GCC installed. Doxygen is used to generate documentation.

For Ubuntu 20.04:

`sudo apt-get install -y gcc mysql-server libmysqlclient-dev doxygen`

## Setup your MySQL user

Here's how to make a user for your account on Ubuntu 20.04.

First, type `sudo mysql` to enter MySQL as admin.

```
drop user username@localhost;
flush privileges;
create user username@localhost identified by 'YOUR_PASSWORD';
grant all privileges on *.* to username@localhost;
```

## Building
Once mysql is installed along with the C API, the header file `crl_database_credentials.h` must be created in `impl/`. This file must have the following definitions:

```
#define MYSQL_HOST "hostname"
#define MYSQL_USER "username"
#define MYSQL_PWD "password" 
```

Once the credentials for the database have been defined, the application can be built.

In order to build, from a terminal navigate to the directory `impl/` in the project. To build for debugging, simply type:

```
make debugging
```

In order to build for release, simply type:

```
make prod
```

In order to build tests, simply type:

```
make testing
```

## Testing
After building the tests, navigate to the tests folder and simply type:
```
./tests
```
Unit tests were written using minunit: http://www.jera.com/techinfo/jtns/jtn002.html

## Running

From the the /debug/ or /release/ folder, run:
```
./crl_main --help
```
to see how the CLI works. 

An example run might look like:
```
./crl_main -p 172.217.0.0/21 -d test -c
```

This uses the prefix mode `-p`, with a database called test `-d` in create mode `-c`. Note that if you have alreayd created the DB `test` you should exclude the `-c` option (see below).

Note that, in order for this to run, it is expected that there is a file called cacert.pem in the directory where the executable is. These are the root certificates used when validating certificates. An example is provided in the top directory of this project from Mozilla. Also, the log files and database must not already exist.
- Note that `prop_impl/cacert.pem-example` will automatically copy itself to the build folder for the debugging build. 
- You may need to run as root depending on your MySQL setup.
