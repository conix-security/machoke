# machoke

CFG-based fuzzy hash for malware classification

## Original work

This implementation is based on Machoc, originally published by ANSSI during SSTIC2015 as a part of polichombr (https://github.com/ANSSI-FR/polichombr).

The algorythm is roughly the same, but unlike ANSSI's Machoc, is implemented using radare2 and r2pipe instead of miasm or IDApython.

##  Objectives

- Get something better than md5/sha* (resistant to small changes inside samples notably, etc.)
- A fuzzy hash better than good old ssdeep
- Get a small and independent tool easy to use and deploy at large
- Let other tools do the clustering

## Usage
`$ python Machoke.py sample.exe`


## r2con

This tool is going to be introduced at r2con 2017.


## Authors
- Lancelot Bogard
