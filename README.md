# advanced-encryption-standard

This implementation of AES is continued from a group project I worked on for CSE 494 - Cryptographic Algorithms and Protocols at ASU. The original repository for the project can be found at https://github.com/tylerbrockett/cse494-cryptography.

I have rewritten all of the code from that repository that was not originally written by me. Additionally, I have made the following changes:
- added CTR mode
- added CFB mode
- added support for hexadecimal input/output
- changed the padding method to PKCS #7
- cleaned up the menu system
- removed the SBox class
- simplified the structure of several files (mainly AES.cpp and Main.cpp) to make future expansion easier

This implementation of AES supports all three key sizes and has options for four modes of operation:
- Electronic Codebook
- Cipher Block Chaining
- Counter
- Cipher Feedback
