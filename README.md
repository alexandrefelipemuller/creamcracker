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
make
cd ./bin
```


Execution Example


Here is an example of how to run CreamCracker:



./creamcracker c 3 5 e2fc714c4727ee9395f324cd2e7f331f


In this example, the program will attempt to crack the e2fc714c4727ee9395f324cd2e7f331f hash (an MD5 hash) using passwords made up of the most common characters (eaorinsltcmdhugp) with a length between 3 and 5 characters.

Expected Output

If a match is found, the program will display the corresponding string:



Match string found: abc


If no match is found up to the maximum password length, the program will print:



no results to size:5

failed: no results found
