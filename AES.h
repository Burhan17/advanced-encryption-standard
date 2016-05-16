
#ifndef AES_H
#define AES_H

#include <iostream>
#include <sstream>
#include <string>
#include "Key.h"
using namespace std;

class AES {
    public:
        AES(int bits);
        ~AES();
		int getBits();
        string encryptECB(string key, string plaintext);
		string encryptCBC(string key, string plaintext);
		string encryptCTR(string key, string plaintext);
        string decryptECB(string key, string ciphertext);
		string decryptCBC(string key, string ciphertext);
		string decryptCTR(string key, string ciphertext);
    private:
        int bits;
		int rounds;
        string keyExpansion(string key, string str);
		string encryptBlockECB(Key *keySchedule, string plaintext);
		string decryptBlockECB(Key *keySchedule, string ciphertext);
		string encryptBlockCBC(Key *keySchedule, string plaintext, string previousBlock);
		string decryptBlockCBC(Key *keySchedule, string ciphertext, string previousBlock);
		string encryptBlockCTR(Key *keySchedule, string plaintext, string counter);
		string decryptBlockCTR(Key *keySchedule, string ciphertext, string counter);
		string generateIV();
		string createPaddingBlock(string text);
};

#endif //AES_H
