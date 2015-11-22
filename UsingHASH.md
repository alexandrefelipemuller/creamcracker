# A little bit about security #

In beginning of computer era, some systems stored password in "clear Text", it means all password were visible for administrators and hackers that invade them.
The solution were create hash: An algorithm that receives as input a string and output another sequence of bits making impossible to make the reverse transformation.
So nobody have access directly to it, but the system can generate the hash to authenticate user.
```
$ printf password |md5sum
5f4dcc3b5aa765d61d8327deb882cf99
```
Basically those hash algorithms takes some characters, makes some bitwise operations (shift and logical OR) and generate the hash.

# This Project #

This project generate all strings possible and compares with hash passed as input. So you have assurance (but it may take time) to have again what string could collide to the hash. OK I have not told you that it could spend seconds, hours, years or centuries. But using a good computer it possible to see must of passwords (~8 chars) are weak.

A good solution to this could be use SALT. You generate a random (or not) string and concatenate it to the password to generate hash.
Does some one have interesting to implement the input to salt on creamcracker?