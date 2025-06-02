# Password Manager CLI

A simple, secure command-line password manager built with modern C++.

## Overview

This application provides a straightforward way to store, retrieve, and manage passwords from the command line.

## Features

- Store passwords securely
- Retrieve passwords by key
- List all stored password keys
- Delete password entries
- Simple command-line interface

## Build

### in-house build flow

Use [modi](https://github.com/uzleosharif/module-builder) tool.

```
$ git clone <this repo>
$ modi
$ ninja -f build/build.ninja
```

The built tool can be found as `build/upm`

### cmake

Should be fairly straightforward to use `clang++` (>v20) or `cmake` (>v4) to build the project. The 
source are provided:
- `password_manager.cppm`
- `main.cpp`

A sample `ninja` build file looks like:
```
cxx = clang++
cxx_flags = -std=c++26 -stdlib=libc++ -O3
module_flags = -fmodule-file=std=/modules/bmi/std.pcm -fmodule-file=uzleo.json=/modules/bmi/uzleo/json.pcm -fmodule-file=fmt=/modules/bmi/fmt.pcm  -fprebuilt-module-path=build/
ld_flags =  -lsodium -ljson -lfmt -L/modules/lib/ -L/modules/lib/uzleo/ 
rule cxx_module
  command = $cxx $cxx_flags $module_flags -fmodule-output -MJ $out.json -c $in -o $out
  description = Compiling module $in
rule cxx_regular
  command = $cxx $cxx_flags $module_flags -MJ $out.json -c $in -o $out
  description = Compiling source $in
rule link
  command = $cxx $cxx_flags $module_flags @link.rsp $ld_flags -o $out
  rspfile = link.rsp
  rspfile_content = $in
  description = Linking $out
build build/main.o: cxx_regular main.cpp | build/password_manager.o 
build build/password_manager.o: cxx_module password_manager.cppm
build build/upm: link build/main.o build/password_manager.o 

```

## Usage

Before running the tool, set the environment-variable `UPM_PASSWORDS_FILE_PATH` 
to point to the location of password-store file on file-system.
For example, `export UPM_PASSWORDS_FILE_PATH="/home/.upm/passwords.enc"`.

The password manager is used through command-line arguments:

```bash
# General syntax
upm <command> [arguments]
```

### Available Commands

#### Add a new password

```bash
upm add <key> <password>
```

Stores a new password under the specified key.

#### Retrieve a password

```bash
upm get <key>
```

Retrieves and displays the password associated with the specified key.

#### List all stored keys

```bash
upm list
```

Displays a list of all keys currently stored in the password manager.

#### Delete a password

```bash
upm delete <key>
```

Removes the password entry associated with the specified key.

## Encryption

On first usage, the master-password is set which will be used to encrypt the passwords file.
The tool works always with three files:
- password file such as `passwords.enc`
- salt `passwords.enc.salt`
- nonce `passwords.enc.nonce`

For machine portability, always make sure to port these three files together!

All subsequent operations (see above commands) can be used by providing the same password.
If you forget the master-password, then passwords file can not be decrypted anymore!

## License

This project is licensed under the MIT License.

