# Tests with others projects #
## MD5 ##
### Test 1 ###
Using word: websit

Modification: for perl screen output functions were disabled

Configuration: lowercase alphabet, minimum size: 6, maximum size 6

  * perl md5cracking - **1540 seconds**
  * krhash 0.3 - **75 seconds**
  * creamcracker md5decode - **0.68 second**


### Test 2 ###
I found this article about benchmarks:
http://3.14.by/en/read/md5_benchmark

According to it, the fastest cracker is "Barswf"

I generated the hash for word myhash, using Intel Core i3:
  * Barswf SSE2 0.8 (Windows 7) **4.13** seconds
  * creamcracker 0.0 (Linux 2.6.35 server) **16.1** seconds

Hash for word website:
  * Barswf SSE2 0.8 (Windows 7) **12.86** seconds
  * creamcracker 0.0 (Linux 2.6.35 server) **33.68** seconds

Hash for word password:
  * Barswf SSE2 0.8 (Windows 7 64 bits) **29 minutes 40 seconds**
  * creamcracker 0.0 GCC 4.5 (Linux 2.6.35 server) **11 minutes 42 seconds**

It needs more test... In fact creamcracker does not use SSE in hash generation. So we can test less hashes/seconds of Barswf.
Those words were not chosen, to make our project faster. Our tries are generally better for real passwords (normal English or Latin words). Our efforts were ate moment and will be to improve our enumeration of tries.