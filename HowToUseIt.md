# How to use #
To execute, use the syntax:
bin/md5decode `[`caAdx`]` X Y HASH

where:

  * `[`caAdx`]` is the dictionary
    * c is only 15 commons chars
    * a is lowercase letters
    * A all letters
    * d letters and numbers
    * x all chars
  * X Min size of word
  * Y Max size of word
  * HASH the hash key

## Example ##
```
tar -xzvf sourcecode.tar.gz
cd creamcracker
make
printf password|md5sum
38d3f61a006d53001637c9d0089176a3

bin/md5decode a 8 8 38d3f61a006d53001637c9d0089176a3
```