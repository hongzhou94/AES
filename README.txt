#AES 128/192/256

###This is an extension of the AES 256 project given by Prof. Bill Young in CS361 at UT Austin.

####This implementation will handle AES 128/192/256 encryption and decryption. Keys must be in text
####files formatted as 128/192/256 bits of hexadecimals, with no spaces. Plaintext files for encryption
####and ciphertext files for decryption must be in text files formatted as hexadecimals with no spaces.
####Each line must contain exactly 128 bits.


###Invoke with:

####"java AES 1 keyfile plaintext 2 3"

####1, 2, and 3 are flags/parameters that must be given on the command line.

####Flag 1: e / d for encryption/decryption
####Flag 2: v / n for verbose/non-verbose
####Flag 3: 128 / 192 / 256 for selecting desired key length
