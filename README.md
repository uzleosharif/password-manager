# Password Manager CLI

A simple, secure command-line password manager built with modern C++.

The tool stores credentials in an encrypted JSON file and showcases the use of
C++20 modules alongside the libsodium crypto library. It is intentionally small
to keep the build and usage simple while still being practical.

## Overview

This application provides a straightforward way to store, retrieve, and manage passwords from the command line.

## Features

- Store passwords securely
- Retrieve passwords by key
- List all stored password keys
- Delete password entries
- Simple command-line interface

## Build

You can compile the project locally or inside the same Docker setup used by the
CI workflow (see `.github/workflows/main.yml`).  Both approaches rely on the
[modi](https://github.com/uzleosharif/module-builder) tool to generate the
`build.ninja` file.

### Local build

```bash
$ git clone <this repo>
$ modi && ninja -f build/build.ninja
```

The resulting `upm` binary will appear in `build/upm`.

### Docker build

```bash
# build the base image with the modules toolchain
docker buildx build \
  -f dockers/cpp-modules-base/cpp_modules_base.dockerfile \
  -t cpp-modules-base .

# build the final image containing the application
docker buildx build \
  -f dockers/password-manager.dockerfile \
  --load -t upm-final .

# run the build inside the container
docker run --rm -v $(pwd):/work -w /work upm-final \
  bash -c "modi && ninja -f build/build.ninja"
```

The `upm` binary will be produced in `build/` just like a local build.

### cmake

Should be fairly straightforward to use `clang++` (>v20) or `cmake` (>v4) to build the project. The
source files are provided:
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
to point to the location of encrypted vault file on disk.
For example, `export UPM_PASSWORDS_FILE_PATH="/home/user/.upm/vault.bin"`.

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

### Flow

On first usage, the tool will prompt for a master password. It derives a
key from that password plus a randomly generated salt. All data
(salt, nonce, and ciphertext) is stored together in one file
(e.g. `vault.bin`).

- Vault file layout:
```
[salt] [nonce] [passwords-map (encrypted)]
```

- On first run:
1. Generate random salt and nonce.
2. Derive the master key from the salt and user-provided master password.
3. Encrypt a dummy JSON store under a fresh nonce.
4. Write `salt || nonce || cipher-text` to `vault.bin`

- On subsequent runs:
1. Read salt+nonce from the front of `vault.bin`.
2. Derive the same key from salt+master-password.
3. Decrypt the remaining ciphertext using that nonce.
4. After any modification (add/delete), generate a new nonce, re-encrypt
the JSON, and overwrite `vault.bin` with `salt || nonce || cipher-text`.

If you forget the master password, the vault can not be decrypted.

## License

This project is licensed under the MIT License.

