# fac_n.py
Break weak rsa public keys by brute forcing common key problems (p or q too low, p or q to close to each other, ...)

usage: fac_n.py [-h] [-m {iterative,root}] [-file FILE] [-threads THREADS]
                [-o O] [-e E] [-n N]

Crack weak public rsa keys and generate private keys:
- Factor n using brute force.
- Based on common weak selections of p and q.

optional arguments:
  -h, --help           show this help message and exit
  -m {iterative,root}  mode to find p and q:
                       iterative	- better when p or q are too low
                       root		- better when p and q are close to each other
  -file FILE           public key file
  -threads THREADS     amount of threads to use
  -o O                 output private key pem file
  -e E                 education mode: e from public key
  -n N                 education mode: n from public key

