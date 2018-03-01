# machoke

CFG-based fuzzy hash for malware classification
by [CERT-Conix](http://blog.conixsecurity.fr/machoke-hashing/).

## Original work

This implementation is based on Machoc, originally published by ANSSI during SSTIC2015 as a part of polichombr (https://github.com/ANSSI-FR/polichombr). The original algorithm is the work of @Heurs.

Our implementation is roughly the same, but unlike ANSSI's Machoc, is implemented using radare2 and r2pipe instead of miasm or IDApython.

##  Objectives

- Get something better than md5/sha* (resistant to small changes inside samples notably, etc.)
- A fuzzy hash better than good old ssdeep
- Get a small and independent tool easy to use and deploy at large
- Let other tools do the clustering

## Usage
Machoke is usable with both python2 and python3.

`$ python Machoke.py sample.exe`
`$ python3 Machoke.py sample.exe`


## r2con
This tool was initially introduced at r2con 2017, you can find the [slides here](https://github.com/radareorg/r2con-2017/tree/master/talks/cfg-fuzzy-hash) and the [talk here](https://www.youtube.com/watch?v=D5JwagRfVy8)


## Installation
This tool relies on radare2 for analysis of the binaries. Thus the first step to use machoke is to get a [working installation of radare2](https://github.com/radare/radare2#install).

Then install r2pipe and mmh3:
`$ sudo pip install r2pipe mmh3`
`$ sudo pip3 install r2pipe mmh3`

Now you are good to use machoke.


## Authors
- Lancelot Bogard
