# Project Overview

This project is a command-line password manager built with modern C++26.
It securely stores, retrieves, lists, and deletes password entries using
libsodium for encryption.

## Repository Layout

```
.
├── src/              # main application code
│   ├── main.cpp      # CLI entry point
│   └── password_manager.cppm  # C++ module implementing the store
├── test/             # Catch2 tests (currently empty)
├── build.json        # build configuration for in-house tool
└── README.md         # usage and build instructions
```

## Key Points

- `src/main.cpp` handles command-line parsing and prompts for the master
  password. It reads the vault path from the `UPM_PASSWORDS_FILE_PATH`
  environment variable and dispatches commands (`add`, `get`, `list`,
  `delete`).
- The `PasswordsStore` class in `src/password_manager.cppm` manages
  encryption and decryption of the password vault. A master key is
  derived from the user-provided password and a per-vault salt using
  libsodium.
- The vault file layout is `[salt][nonce][encrypted passwords]`. On each
  update, a new nonce is generated and the file is rewritten.

## Building

The project can be built either with the in-house **modi** tool or via a
standard CMake/Clang++ setup. See `README.md` for detailed steps.
Before running, set `UPM_PASSWORDS_FILE_PATH` to the path of your vault
file.

## Tips for New Contributors

1. Follow the build instructions to compile the project.
2. Explore `src/password_manager.cppm` to understand how passwords are
   encrypted and stored.
3. Tests under `test/` are mostly placeholders—adding more tests will
   improve reliability.
4. Potential areas for enhancement include better CLI parsing, improved
   error handling, and cross-platform support for secure password
   prompts.

