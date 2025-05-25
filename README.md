# Password Manager CLI

A simple, secure command-line password manager built with modern C++.

## Overview

This application provides a straightforward way to store, retrieve, and manage passwords from the command line. It uses modern C++ features including modules efficient memory usage and improved code clarity.

## Features

- Store passwords securely
- Retrieve passwords by key
- List all stored password keys
- Delete password entries
- Simple command-line interface


## Usage

Before running the tool, set the environment-variable `UPM_PASSWORDS_FILE_PATH` 
to point to the location of password-store file on file-system.
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

## Security Considerations

- Passwords are stored locally
- Consider implementing encryption for the password store
- Use strong, unique passwords for each entry

## License

This project is licensed under the MIT License.

