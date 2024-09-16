# CreamCracker - Hash Cracking Tool

## About the Project

**CreamCracker** is a tool written in **C** for cracking password hashes using brute force. The code uses multiple threads to test character combinations based on user-defined configurations. CreamCracker supports different hashing algorithms such as MD5, SHA-256, SHA-3, among others, and allows the definition of different alphabets for password search.

## Key Features

- Support for multiple hash algorithms like MD5, SHA-256, SHA-3.
- Multi-threaded implementation for better performance.
- Customizable character alphabets for brute-force attacks.
- Define password size limits for testing.

## Requirements

- **GCC** compiler or any other C-compatible compiler.
- **Linux** OS or any system compatible with **POSIX threads** (pthreads).

## How to Install

### Step 1: Clone the Repository

First, clone the CreamCracker repository to your local system.

```bash
git clone https://github.com/user/CreamCracker.git
cd CreamCracker
