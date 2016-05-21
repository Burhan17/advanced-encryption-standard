#include <iostream>
#include <random>
#include <sstream>
#include "AES.h"
#include "State.h"
#include "Key.h"

//Constructor for AES class.
AES::AES(int bit){
    if (bit == 128 || bit == 192 || bit == 256){
        bits = bit;
    } else {
        bits = 128;
    }
	switch(bits){
	case 128:
		rounds = 10;
		break;
	case 192:
		rounds = 12;
		break;
	case 256:
		rounds = 14;
		break;
	}
}
//Returns the number of bits in the key for this
//instance of AES.
int AES::getBits() {
    return bits;
}

string AES::createPaddingBlock(string text){
	int difference = 15 - text.size();
	//cout << "Difference: " << hex << difference << endl;
	stringstream stream;
	stream << hex << difference;
	//string differenceString = to_string(difference);
	string differenceString = stream.str();
	for(int i = 0; i < (difference + 1); i++){
		text += differenceString;
	}
	return text;
}

//Encryption in electronic codebook mode.
string AES::encryptECB(string key, string plaintext) {
	Key *keySchedule = new Key(key);
	string ciphertext = "";
	int plaintextSize = plaintext.size();

	int bytesRemaining;
	for(int i = 0; i < plaintextSize; i += 16){
		bytesRemaining = plaintextSize - i;
		if(bytesRemaining >= 16){
			ciphertext += encryptBlockECB(keySchedule, plaintext.substr(i,16));
		}
	}
	string lastBlock;
	if(bytesRemaining == 16){
		lastBlock = createPaddingBlock("");
	}
	else{
		lastBlock = createPaddingBlock(plaintext.substr(plaintextSize - bytesRemaining));
	}
	ciphertext += AES::encryptBlockECB(keySchedule,lastBlock);

	return ciphertext;
}
//Encryption in cipher block chaining mode.
string AES::encryptCBC(string key, string plaintext){
	Key *keySchedule = new Key(key);
	string ciphertext = "";
	// Generate initialization vector (IV)
	string iv = generateIV();
	//The iv will be the first block of the ciphertext.
	ciphertext += iv;
	//The iv will also be XORed with the first block of the plaintext:
	string mostRecentBlockOfCipherText = iv;
	int plaintextSize = plaintext.size();
	
	int bytesRemaining;
	for(int i = 0; i < plaintextSize; i += 16){
		bytesRemaining = plaintextSize - i;
		if(bytesRemaining >= 16){
			mostRecentBlockOfCipherText = AES::encryptBlockCBC(keySchedule, plaintext.substr(i,16), mostRecentBlockOfCipherText);
			ciphertext += mostRecentBlockOfCipherText;
		}
	}
	string lastBlock;
	if(bytesRemaining == 16){
		lastBlock = createPaddingBlock("");
	}
	else{
		lastBlock = createPaddingBlock(plaintext.substr(plaintextSize - bytesRemaining));
	}
	ciphertext += AES::encryptBlockCBC(keySchedule,lastBlock,mostRecentBlockOfCipherText);

	return ciphertext;
}
//Encryption in counter mode.
string AES::encryptCTR(string key, string plaintext){
	Key *keySchedule = new Key(key);
	string ciphertext = "";

	// Generate initialization vector (IV) for our counter.
	string counter = generateIV();

	/*stream.str(std::string());
	stream.clear();*/

	//The counter will be the first block of the ciphertext.
	ciphertext += counter;

	int plaintextSize = plaintext.size();
	string currentBlockOfCipherText;
	int bytesRemaining;

	for(int i = 0; i < plaintextSize; i += 16){
		bytesRemaining = plaintextSize - i;
		if(bytesRemaining >= 16){
			counter = incrementCounter(counter);
			ciphertext += AES::encryptOrDecryptBlockCTR(keySchedule, plaintext.substr(i,16),counter);
		}
	}
	//Increment counter:
	counter = incrementCounter(counter);

	string lastBlock;
	if(bytesRemaining == 16){
		lastBlock = createPaddingBlock("");
	}
	else{
		lastBlock = createPaddingBlock(plaintext.substr(plaintextSize - bytesRemaining));
	}
	ciphertext += AES::encryptOrDecryptBlockCTR(keySchedule,lastBlock,counter);

	return ciphertext;
	//return decryptCTR(key, ciphertext);
}
//Encryption in cipher feedback mode.
string AES::encryptCFB(string key, string plaintext){
	Key *keySchedule = new Key(key);
	string ciphertext = "";
	// Generate initialization vector (IV)
	string iv = generateIV();
	//The iv will be the first block of the ciphertext.
	ciphertext += iv;
	//The iv will also be XORed with the first block of the plaintext:
	string mostRecentBlockOfCipherText = iv;
	int plaintextSize = plaintext.size();
	
	int bytesRemaining;
	for(int i = 0; i < plaintextSize; i += 16){
		bytesRemaining = plaintextSize - i;
		if(bytesRemaining >= 16){
			mostRecentBlockOfCipherText = AES::encryptOrDecryptBlockCFB(keySchedule, plaintext.substr(i,16), mostRecentBlockOfCipherText);
			ciphertext += mostRecentBlockOfCipherText;
		}
	}
	string lastBlock;
	if(bytesRemaining == 16){
		lastBlock = createPaddingBlock("");
	}
	else{
		lastBlock = createPaddingBlock(plaintext.substr(plaintextSize - bytesRemaining));
	}
	ciphertext += AES::encryptOrDecryptBlockCFB(keySchedule,lastBlock,mostRecentBlockOfCipherText);

	return ciphertext;
	//return decryptCFB(key, ciphertext);
}
//Encryption in output feedback mode.
string AES::encryptOFB(string key, string plaintext){
	Key *keySchedule = new Key(key);
	string ciphertext = "";
	// Generate initialization vector (IV)
	string iv = generateIV();
	//The iv will be the first block of the ciphertext.
	ciphertext += iv;
	//The iv will also be XORed with the first block of the plaintext:
	string mostRecentBlockOfCipherText = iv;
	string xorString = "first";
	int plaintextSize = plaintext.size();
	
	int bytesRemaining;
	for(int i = 0; i < plaintextSize; i += 16){
		bytesRemaining = plaintextSize - i;
		if(bytesRemaining >= 16){
			mostRecentBlockOfCipherText = AES::encryptOrDecryptBlockOFB(keySchedule, plaintext.substr(i,16), mostRecentBlockOfCipherText, xorString);
			ciphertext += mostRecentBlockOfCipherText;
			xorString = plaintext.substr(i,16);
		}
	}
	string lastBlock;
	if(bytesRemaining == 16){
		lastBlock = createPaddingBlock("");
	}
	else{
		lastBlock = createPaddingBlock(plaintext.substr(plaintextSize - bytesRemaining));
	}
	ciphertext += AES::encryptOrDecryptBlockOFB(keySchedule,lastBlock,mostRecentBlockOfCipherText, xorString);

	return ciphertext;
	//return decryptOFB(key, ciphertext);
}
//Encrypt a block of plaintext in ECB mode.
string AES::encryptBlockECB(Key *keySchedule, string plaintext){
	//Create state:
	State *state = new State(plaintext);

	//Initial round:
	state->addRoundKey(keySchedule->getKey(0));
	//Full rounds:
	for(int i = 1; i < rounds; i++){
		state->subBytes();
		state->shiftRows();
		state->mixColumns();
		state->addRoundKey(keySchedule->getKey(i));
	}
	//Final round:
	state->subBytes();
	state->shiftRows();
	state->addRoundKey(keySchedule->getKey(rounds));
	return state->printState();
}
//Encrypt a block of plaintext in CBC mode.
string AES::encryptBlockCBC(Key *keySchedule, string plaintext, string previousBlock){
	//Create state:
	State *state = new State(plaintext);
	
	//XOR the previous block of ciphertext with the current block of plaintext:
	state->XORWithString(previousBlock);
	
	//Initial round:
	state->addRoundKey(keySchedule->getKey(0));
	//Full rounds:
	for(int i = 1; i < rounds; i++){
		state->subBytes();
		state->shiftRows();
		state->mixColumns();
		state->addRoundKey(keySchedule->getKey(i));
	}
	//Final round:
	state->subBytes();
	state->shiftRows();
	state->addRoundKey(keySchedule->getKey(rounds));
	return state->printState();
}
//Encrypt or decrypt a block of text in CTR mode.
string AES::encryptOrDecryptBlockCTR(Key *keySchedule, string text, string counter){
	//Create state:
	State *state = new State(counter);
	
	//Initial round:
	state->addRoundKey(keySchedule->getKey(0));
	//Full rounds:
	for(int i = 1; i < rounds; i++){
		state->subBytes();
		state->shiftRows();
		state->mixColumns();
		state->addRoundKey(keySchedule->getKey(i));
	}
	//Final round:
	state->subBytes();
	state->shiftRows();
	state->addRoundKey(keySchedule->getKey(rounds));

	//XOR the encrypted counter with the current block of plaintext:
	state->XORWithString(text);

	return state->printState();
}
//Encrypt or decrypt a block of text in CFB mode.
string AES::encryptOrDecryptBlockCFB(Key *keySchedule, string text, string previousBlock){
	//Create state:
	State *state = new State(previousBlock);
	
	//Initial round:
	state->addRoundKey(keySchedule->getKey(0));
	//Full rounds:
	for(int i = 1; i < rounds; i++){
		state->subBytes();
		state->shiftRows();
		state->mixColumns();
		state->addRoundKey(keySchedule->getKey(i));
	}
	//Final round:
	state->subBytes();
	state->shiftRows();
	state->addRoundKey(keySchedule->getKey(rounds));

	state->XORWithString(text);

	return state->printState();
}
//Encrypt or decrypt a block of text in OFB mode.
string AES::encryptOrDecryptBlockOFB(Key *keySchedule, string text, string previousBlock, string xorText){
	//Create state:
	State *state = new State(previousBlock);
	if(xorText.compare("first") != 0){
		state->XORWithString(xorText);
	}
	//Initial round:
	state->addRoundKey(keySchedule->getKey(0));
	//Full rounds:
	for(int i = 1; i < rounds; i++){
		state->subBytes();
		state->shiftRows();
		state->mixColumns();
		state->addRoundKey(keySchedule->getKey(i));
	}
	//Final round:
	state->subBytes();
	state->shiftRows();
	state->addRoundKey(keySchedule->getKey(rounds));

	state->XORWithString(text);

	return state->printState();
}
//Decryption in electronic codebook mode.
string AES::decryptECB(string key, string ciphertext) {
	Key *keySchedule = new Key(key);
	string plaintext = "";

	int ciphertextSize = ciphertext.size();

	for(int i = 0; i < ciphertextSize; i += 16){
		plaintext += AES::decryptBlockECB(keySchedule, ciphertext.substr(i,16));
	}
	//Now we have to deal with the padded block at the end:
	string finalBlock = plaintext.substr(ciphertextSize - 16);
	char finalByteOfFinalBlock = finalBlock[15];

	int numberOfPaddedBytes;
	stringstream stream;
	stream << finalByteOfFinalBlock;
	stream >> hex >> numberOfPaddedBytes;
	numberOfPaddedBytes++;
	
	plaintext = plaintext.substr(0,(ciphertextSize - numberOfPaddedBytes));

    return plaintext;
}
//Decryption in cipher block chaining mode.
string AES::decryptCBC(string key, string ciphertext) {
	Key *keySchedule = new Key(key);
	string plaintext = "";

	//Extract the IV (which is the first block in the ciphertext).
	string mostRecentBlockOfCipherText = ciphertext.substr(0,16);

	int ciphertextSize = ciphertext.size();

	//Start at 16 to skip over the IV:
	for(int i = 16; i < ciphertextSize; i += 16){
		plaintext += AES::decryptBlockCBC(keySchedule, ciphertext.substr(i,16), mostRecentBlockOfCipherText);

		mostRecentBlockOfCipherText = ciphertext.substr(i,16);
	}

	//Now we have to deal with the padded block at the end:
	string finalBlock = plaintext.substr((ciphertextSize - 16) - 16);
	char finalByteOfFinalBlock = finalBlock[15];

	int numberOfPaddedBytes;
	stringstream stream;
	stream << finalByteOfFinalBlock;
	stream >> hex >> numberOfPaddedBytes;
	numberOfPaddedBytes++;
	
	plaintext = plaintext.substr(0,((ciphertextSize - 16) - numberOfPaddedBytes));

    return plaintext;
}
//Decryption in counter mode.
string AES::decryptCTR(string key, string ciphertext){
	Key *keySchedule = new Key(key);
	string plaintext = "";

	//Extract the IV (which is the first block in the ciphertext).
	string counter = ciphertext.substr(0,16);
	int counterInt = atoi(counter.c_str());

	int ciphertextSize = ciphertext.size();

	stringstream stream;
	//Start at 16 to skip over the IV:
	for(int i = 16; i < ciphertextSize; i += 16){
		counter = incrementCounter(counter);
		plaintext += AES::encryptOrDecryptBlockCTR(keySchedule, ciphertext.substr(i,16), counter);
	}

	//Now we have to deal with the padded block at the end:
	string finalBlock = plaintext.substr((ciphertextSize - 16) - 16);
	char finalByteOfFinalBlock = finalBlock[15];

	int numberOfPaddedBytes;
	stream << finalByteOfFinalBlock;
	stream >> hex >> numberOfPaddedBytes;
	numberOfPaddedBytes++;
	
	plaintext = plaintext.substr(0,((ciphertextSize - 16) - numberOfPaddedBytes));

    return plaintext;
}
//Decryption in cipher feedback mode.
string AES::decryptCFB(string key, string ciphertext){
	Key *keySchedule = new Key(key);
	string plaintext = "";

	//Extract the IV (which is the first block in the ciphertext).
	string mostRecentBlockOfCipherText = ciphertext.substr(0,16);

	int ciphertextSize = ciphertext.size();

	//Start at 16 to skip over the IV:
	for(int i = 16; i < ciphertextSize; i += 16){
		plaintext += AES::encryptOrDecryptBlockCFB(keySchedule, ciphertext.substr(i,16), mostRecentBlockOfCipherText);
		mostRecentBlockOfCipherText = ciphertext.substr(i,16);
	}

	//Now we have to deal with the padded block at the end:
	string finalBlock = plaintext.substr((ciphertextSize - 16) - 16);
	char finalByteOfFinalBlock = finalBlock[15];

	int numberOfPaddedBytes;
	stringstream stream;
	stream << finalByteOfFinalBlock;
	stream >> hex >> numberOfPaddedBytes;
	numberOfPaddedBytes++;
	
	plaintext = plaintext.substr(0,((ciphertextSize - 16) - numberOfPaddedBytes));

    return plaintext;
}
//Decryption in output feedback mode.
string AES::decryptOFB(string key, string ciphertext){
	Key *keySchedule = new Key(key);
	string plaintext = "";

	//Extract the IV (which is the first block in the ciphertext).
	string mostRecentBlockOfPlainText = ciphertext.substr(0,16);
	string xorString = "first";
	int ciphertextSize = ciphertext.size();

	//Start at 16 to skip over the IV:
	for(int i = 16; i < ciphertextSize; i += 16){
		mostRecentBlockOfPlainText = AES::encryptOrDecryptBlockOFB(keySchedule, ciphertext.substr(i,16), mostRecentBlockOfPlainText, xorString);
		plaintext += mostRecentBlockOfPlainText;
		xorString = ciphertext.substr(i,16);
	}

	//Now we have to deal with the padded block at the end:
	string finalBlock = plaintext.substr((ciphertextSize - 16) - 16);
	char finalByteOfFinalBlock = finalBlock[15];

	int numberOfPaddedBytes;
	stringstream stream;
	stream << finalByteOfFinalBlock;
	stream >> hex >> numberOfPaddedBytes;
	numberOfPaddedBytes++;
	
	plaintext = plaintext.substr(0,((ciphertextSize - 16) - numberOfPaddedBytes));

    return plaintext;
}

//Decrypt a block of ciphertext in ECB mode.
string AES::decryptBlockECB(Key *keySchedule, string ciphertext){
	//Create state:
	State *state = new State(ciphertext);
	//Initial round:
	state->addRoundKey(keySchedule->getKey(rounds));
	//Full rounds:
	for(int i = 1; i < rounds; i++){
		state->invShiftRows();
		state->invSubBytes();
		state->addRoundKey(keySchedule->getKey(rounds-i));
		state->invMixColumns();
	}
	//Final round:
	state->invShiftRows();
	state->invSubBytes();
	state->addRoundKey(keySchedule->getKey(0));

	return state->printState();
}
//Decrypt a block of ciphertext in CBC mode.
string AES::decryptBlockCBC(Key *keySchedule, string ciphertext, string previousBlock){
	//Create state:
	State *state = new State(ciphertext);
	//Initial round:
	state->addRoundKey(keySchedule->getKey(rounds));
	//Full rounds:
	for(int i = 1; i < rounds; i++){
		state->invShiftRows();
		state->invSubBytes();
		state->addRoundKey(keySchedule->getKey(rounds-i));
		state->invMixColumns();
	}
	//Final round:
	state->invShiftRows();
	state->invSubBytes();
	state->addRoundKey(keySchedule->getKey(0));
	
	state->XORWithString(previousBlock);
	
	return state->printState();
}
//Generate an initialization vector.
string AES::generateIV(){
	// Based on the recommendation of securingcoding.cert.org for how to generate pseudorandom numbers
	// (https://www.securecoding.cert.org/confluence/display/cplusplus/MSC50-CPP.+Do+not+use+std%3A%3Arand%28%29+for+generating+pseudorandom+numbers)
	// and the publication from NIST, Recommendation for Block Cipher Modes of Operation,
	// which explains how a random number generator can be used to generate a random data
	// block that can be used as an IV. (http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf)
	string iv = "";
	uniform_int_distribution<int> distribution(1000, 9999); //Distribution of 4 digit numbers.
    random_device rd;
    mt19937 engine(rd());
	for(int i = 0; i < 4; i++){ //Generate four numbers from that distribution.
		iv += to_string(distribution(engine));
	}
	return iv;
}
string AES::incrementCounter(string counter){
	stringstream stream;

	string firstHalf, secondHalf;
	firstHalf = counter.substr(0,8);
	secondHalf = counter.substr(8);

	long secondLong;
	string::size_type sz;
	
	secondLong = stol(secondHalf, &sz);
	
	secondLong++;
	if(secondLong > 99999999){
		secondHalf = "00000000";
	}
	else{
		//Now convert the long back to a string:
		stream << secondLong;
		secondHalf = stream.str();
	}

	return firstHalf + secondHalf;
}

AES::~AES(){
}
