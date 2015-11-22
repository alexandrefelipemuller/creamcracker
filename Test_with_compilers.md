Those times are in seconds (less is better).
Real means the time passed, and user means the time of all processors serialized.

# MD5 8 char length word #
```
clang
real 34.45
user 136.78
sys 0.01

gcc
real 35.09
user 139.47
sys 0.02

intel
real 36.10
user 143.21
sys 0.07

open64
real 55.36
user 220.03
sys 0.06
```

# SHA1 All possibilities with 5 chars #
```
intel
real 1.98
user 7.67
sys 0.00

clang
real 2.10
user 8.11
sys 0.01

gcc
real 2.38
user 9.24
sys 0.00

open64
real 2.66
user 10.32
sys 0.01
```