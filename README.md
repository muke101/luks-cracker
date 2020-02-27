# overview
To provide experiance with systems programming, crypto programming and multithreaded programming all at once, I'm building a simple dictionary attack tool for LUKS encrytped devices. This will take the LUKS volume headers, read out the active key slots, and then implement LUKS's standard for key recovery (including an implementation of the LUKS Anti-Forensics Merger) to brute force passwords from a user provided wordlist. For every key slot containing a weak password provided in the wordlist, this program will through the use of multi-threading and extensive compiler optimizations be able to yield the corropsonding password for each key slot, which will themselves be usable to access the entire LUKS volume and bulk data. 

# build and run
To build, simply run `make`. You can pass the partition device node of your LUKS volume by the command line (`/dev/sdXn`) or you can pass the raw device node to the script `get_luks_header` which will copy just the LUKS header into a file in the current directory which can then itself be passed to the main program to be worked on. 

# implementation
The parsing is implemented quite directly by simply reading bytes one at a time from the start sector of the header, referancing the LUKS documentation on header structure found here: https://mirrors.edge.kernel.org/pub/linux/utils/cryptsetup/LUKS_docs/on-disk-format.pdf

The structure of the key recovery (crypto and anti-forensics reversal) is also derived from the above specification. 

The reading of the key, anti-forensics reversal and key decryption is implemented and fully functioning for both LUKS 1 and 2. 

The cracking side is currently being implemented, but the method of mutli-threading used will be tested against two different approaches. 

Firstly is the 'paralization' approach, of dividing the given wordlist amoung the given number of threads, and having each one act as the single threaded program within their section of the wordlist (ie, taking a password, attempting a decryption with it and trying the next one if not successful until a password is found or the list is exhausted).

The second approach however is a 'pipelining' method. This takes each subsection of a whole key recovery attempt (password hashing, anti-forensics reversal and key decryption attempt) and asings them to specific provided threads, such that a thread is only ever carrying out the same operation for different inputs provided from further up the pipeline throughout the brute force. This should in theory provide better cache utiliztion between cores that the threads run on, however modern operating systems and compilers being as they are there's no way to know for sure without some kind of benchmarking. Luckily we have access to a 40 thread machine to test both methods on, so the intention is to implement both and compare the differences, if any significant ones are even observed at all. This should be interesting research that could inform how to best approach brute forcing convoluted crypto systems like that found in LUKS.
