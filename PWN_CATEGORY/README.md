# PWN_CATEGORY
This is a classification for pwn games that i used to do or recurrent. and all the problem in this repository is typical.

## heap
typical heap problems

### global_max_fast


### waiting for CATEGORY

* AddressSanitizer-uaf-0ctf2019-aegis

    game: 0ctf 2019

    description: AddressSanitizer is a memory protection that developed by google. it's a uaf problem.

    writeup link: [https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#aegis](https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#aegis)
* largebin_attack-lctf2017-2ez4u

    game: lctf 2017

    description: a typical largebin attack problem.

    writeup link: [Large bin attack--LCTF2017-2ez4u--writeup](https://ray-cp.github.io/archivers/Large%20bin%20attack--LCTF2017-2ez4u--writeup)

* overlap_chunk-malloc_consolidate-0ctf2019-babyheap
    game: 0ctf 2019

    description: `off-by-null` to form overlap_chunk, it also pwned by triggering `malloc_consolidate` when top chunk is too small.

    writeup link: [https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#babyheap](https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#babyheap)
* race_condition-uaf-0ctf2019-zerotask

    game: 0ctf 2019

    description: race condition to form `uaf` vuln.

    writeup link: [https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#zerotask](https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#zerotask)
* unlink-heap_brute-强网杯2018-note2

    game: 强网杯 2018

    description: unlink with brute.

    writeup link: none

## integer_overflow
typical integer overflow problems
* source_audit-integer_overflow-0ctf2019-If_on_a_winters_night_a_traveler

    game: 0ctf 2019

    description: give out a perm.diff, need to source audit, it use integer overflow to form `write-to-where` vuln.

    writeup link: [https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#if_on_a_winters_night_a_traveler](https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#if_on_a_winters_night_a_traveler)

## stack_overflow
typical stack overflow problems

* partial-stackoverwirte-2018-强网杯-opm

    game: 强网杯 2018

    description: a partial overwrite problem.
    
    writeup link: [https://ray-cp.github.io/archivers/强网杯-pwn-writeup#opm](https://ray-cp.github.io/archivers/强网杯-pwn-writeup#opm)

* pointer-stackoverwrite-starctf2019-quicksort

    game: starctf 2019

    description: overwite heap pointer in stack to leak and write.
    
    writeup link: [https://ray-cp.github.io/archivers/STARCTF_2019_PWN_WRITEUP#quicksort](https://ray-cp.github.io/archivers/STARCTF_2019_PWN_WRITEUP#quicksort)


## odd_skill
some odd skill that may suprise me
* rwx-upxpacked-starctf2019-upxofcpp

    game: starctf 2019

    description: a heap double free but with upx pack which form rwx segment.
    
    writeup link: [https://ray-cp.github.io/archivers/STARCTF_2019_PWN_WRITEUP#upxofcpp](https://ray-cp.github.io/archivers/STARCTF_2019_PWN_WRITEUP#upxofcpp)