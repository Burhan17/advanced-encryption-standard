#include "Key.h"
//Constructor for Key
Key::Key(string initialKey){
	bytes = initialKey.size();
	if(bytes == 16){
		Key::expandKey128(initialKey);
	}
	else if(bytes == 24){
		Key::expandKey192(initialKey);
	}
	else{
		Key::expandKey256(initialKey);
	}

	//Initialize SBoxes:
	// Rijndael S-box from https://en.wikipedia.org/wiki/Rijndael_S-box
	unsigned char tempSBox[256] = {
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };
	//Rijndael Inverse S-box from https://en.wikipedia.org/wiki/Rijndael_S-box
	unsigned char tempInvSBox[256] = {
			0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };
	for(int i = 0; i < 256; i++){
		sBox[i] = tempSBox[i];
	}
	for(int j = 0; j < 256; j++){
		invSBox[j] = tempInvSBox[j];
	}
}
//Key expansion function that is called when key is 128 bits.
//Based on method for key expansion described here:
//https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
void Key::expandKey128(string initialKey){
	//Precomputed round constant table:
	//Pulled from https://en.wikipedia.org/wiki/Rijndael_key_schedule
	unsigned char roundConstant[256] = {
		0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
		0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
		0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
		0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
		0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
		0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
		0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
		0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
		0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
		0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
		0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
		0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
		0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
		0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
		0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
		0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
	};

	//First 4 words (16 bytes) is just the initial key.
	for(int i = 0; i < 16; i++){
		key128[i][0] = initialKey[i];
    }

	//Each remaining group of 4 words is based on the last 4 words:
    for(int i = 1; i < 11; i++){
    	//Word 0: (Word 0 of previous group XOR g(Word 3 of previous group))
		unsigned char* gResult = g(key128[12][i-1], key128[13][i-1], key128[14][i-1], key128[15][i-1], roundConstant[i]);
    	key128[0][i] = XOR(key128[0][i-1], gResult[0]);
    	key128[1][i] = XOR(key128[1][i-1], gResult[1]);
    	key128[2][i] = XOR(key128[2][i-1], gResult[2]);
    	key128[3][i] = XOR(key128[3][i-1], gResult[3]);
    	
    	//Word 1: (Word 0 XOR Word 1 of previous group)
    	key128[4][i] = XOR(key128[0][i], key128[4][i-1]);
    	key128[5][i] = XOR(key128[1][i], key128[5][i-1]);
    	key128[6][i] = XOR(key128[2][i], key128[6][i-1]);
    	key128[7][i] = XOR(key128[3][i], key128[7][i-1]);
    		
    	//Word 2: (Word 1 XOR Word 2 of previous group)
    	key128[8][i] = XOR(key128[4][i], key128[8][i-1]);
    	key128[9][i] = XOR(key128[5][i], key128[9][i-1]);
    	key128[10][i] = XOR(key128[6][i], key128[10][i-1]);
    	key128[11][i] = XOR(key128[7][i], key128[11][i-1]);
    		
    	//Word 3: (Word 2 XOR Word 3 of previous group)
    	key128[12][i] = XOR(key128[8][i], key128[12][i-1]);
    	key128[13][i] = XOR(key128[9][i], key128[13][i-1]);
    	key128[14][i] = XOR(key128[10][i], key128[14][i-1]);
    	key128[15][i] = XOR(key128[11][i], key128[15][i-1]);
    }
}
//Key expansion function that is called when key is 192 bits.
//Based on method for key expansion described here:
//https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
void Key::expandKey192(string initialKey){
	//Precomputed round constant table:
	//Pulled from https://en.wikipedia.org/wiki/Rijndael_key_schedule
	unsigned char roundConstant[256] = {
		0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
		0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
		0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
		0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
		0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
		0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
		0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
		0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
		0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
		0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
		0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
		0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
		0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
		0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
		0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
		0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
	};
	//First 6 words (24 bytes) is just the initial key.
	for(int i = 0; i < 24; i++){
		key192[i] = initialKey[i];
    }
	//Each remaining group of 6 words (24 bytes) is based on the last 6 words:
	int i; 
    for(int j = 1; j < 9; j++){
		i = j * 24;
		//Word 0: (Word 0 of previous group XOR g(Word 5 of previous group))
		unsigned char* gResult = g(key192[i-4], key192[i-3], key192[i-2], key192[i-1], roundConstant[j]);
    	key192[i] = XOR(key192[i-24], gResult[0]);
    	key192[i+1] = XOR(key192[i-23], gResult[1]);
    	key192[i+2] = XOR(key192[i-22], gResult[2]);
    	key192[i+3] = XOR(key192[i-21], gResult[3]);

		//Word 1: (Word 0 XOR Word 1 of previous group)
		key192[i+4] = XOR(key192[i],key192[i-20]);
		key192[i+5] = XOR(key192[i+1],key192[i-19]);
		key192[i+6] = XOR(key192[i+2],key192[i-18]);
		key192[i+7] = XOR(key192[i+3],key192[i-17]);

		//Word 2: (Word 1 XOR Word 2 of previous group)
		key192[i+8] = XOR(key192[i+4],key192[i-16]);
		key192[i+9] = XOR(key192[i+5],key192[i-15]);
		key192[i+10] = XOR(key192[i+6],key192[i-14]);
		key192[i+11] = XOR(key192[i+7],key192[i-13]);

		//Word 3: (Word 2 XOR Word 3 of previous group)
		key192[i+12] = XOR(key192[i+8],key192[i-12]);
		key192[i+13] = XOR(key192[i+9],key192[i-11]);
		key192[i+14] = XOR(key192[i+10],key192[i-10]);
		key192[i+15] = XOR(key192[i+11],key192[i-9]);

		//Word 4:(Word 3 XOR Word 4 of previous group)
		key192[i+16] = XOR(key192[i+12],key192[i-8]);
		key192[i+17] = XOR(key192[i+13],key192[i-7]);
		key192[i+18] = XOR(key192[i+14],key192[i-6]);
		key192[i+19] = XOR(key192[i+15],key192[i-5]);

		//Word 5:(Word 4 XOR Word 5 of previous group)
		key192[i+20] = XOR(key192[i+16],key192[i-4]);
		key192[i+21] = XOR(key192[i+17],key192[i-3]);
		if(j != 8){ //We ignore the last two bytes of the last group.
			key192[i+22] = XOR(key192[i+18],key192[i-2]);
			key192[i+23] = XOR(key192[i+19],key192[i-1]);
		}
	}
}
//Key expansion function that is called when key is 256 bits.
//Based on method for key expansion described here:
//https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
//Also incorporates some of the techniques covered here:
//http://www.samiam.org/key-schedule.html
void Key::expandKey256(string initialKey){
	//Precomputed round constant table:
	//Pulled from https://en.wikipedia.org/wiki/Rijndael_key_schedule
	unsigned char roundConstant[256] = {
		0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
		0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
		0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
		0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
		0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
		0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
		0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
		0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
		0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
		0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
		0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
		0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
		0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
		0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
		0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
		0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
	};
	//First 8 words (32 bytes) is just the initial key.
	for(int i = 0; i < 32; i++){
		key256[i] = initialKey[i];
    }
	int i;
	//Each remaining group of 8 words (32 bytes) is based on the last 8 words: 
    for(int j = 1; j < 8; j++){
		i = j * 32;
		//Word 0: (Word 0 of previous group XOR g(Word 5 of previous group))
		unsigned char* gResult = g(key256[i-4], key256[i-3], key256[i-2], key256[i-1], roundConstant[j]);
		
    	key256[i] = XOR(key256[i-32], gResult[0]);
    	key256[i+1] = XOR(key256[i-31], gResult[1]);
    	key256[i+2] = XOR(key256[i-30], gResult[2]);
    	key256[i+3] = XOR(key256[i-29], gResult[3]);

		//Word 1: (Word 0 XOR Word 1 of previous group)
		key256[i+4] = XOR(key256[i],key256[i-28]);
		key256[i+5] = XOR(key256[i+1],key256[i-27]);
		key256[i+6] = XOR(key256[i+2],key256[i-26]);
		key256[i+7] = XOR(key256[i+3],key256[i-25]);

		//Word 2: (Word 1 XOR Word 2 of previous group)
		key256[i+8] = XOR(key256[i+4],key256[i-24]);
		key256[i+9] = XOR(key256[i+5],key256[i-23]);
		key256[i+10] = XOR(key256[i+6],key256[i-22]);
		key256[i+11] = XOR(key256[i+7],key256[i-21]);

		//Word 3: (Word 2 XOR Word 3 of previous group)
		key256[i+12] = XOR(key256[i+8],key256[i-20]);
		key256[i+13] = XOR(key256[i+9],key256[i-19]);
		key256[i+14] = XOR(key256[i+10],key256[i-18]);
		key256[i+15] = XOR(key256[i+11],key256[i-17]);

		//Word 4:
		unsigned char* sBoxResult = sBox256(key256[i+12], key256[i+13], key256[i+14], key256[i+15]);
		key256[i+16] = XOR(key256[i-16],sBoxResult[0]);
		key256[i+17] = XOR(key256[i-15],sBoxResult[1]);
		key256[i+18] = XOR(key256[i-14],sBoxResult[2]);
		key256[i+19] = XOR(key256[i-13],sBoxResult[3]);

		//Word 5:(Word 4 XOR Word 5 of previous group)
		key256[i+20] = XOR(key256[i+16],key256[i-12]);
		key256[i+21] = XOR(key256[i+17],key256[i-11]);
		key256[i+22] = XOR(key256[i+18],key256[i-10]);
		key256[i+23] = XOR(key256[i+19],key256[i-9]);

		//Word 6:(Word 5 XOR Word 6 of previous group)
		key256[i+24] = XOR(key256[i+20],key256[i-8]);
		key256[i+25] = XOR(key256[i+21],key256[i-7]);
		key256[i+26] = XOR(key256[i+22],key256[i-6]);
		key256[i+27] = XOR(key256[i+23],key256[i-5]);

		//Word 7:(Word 6 XOR Word 7 of previous group)
		key256[i+28] = XOR(key256[i+24],key256[i-4]);
		key256[i+29] = XOR(key256[i+25],key256[i-3]);
		key256[i+30] = XOR(key256[i+26],key256[i-2]);
		key256[i+31] = XOR(key256[i+27],key256[i-1]);
	}
}
//Used by expandKey256(string initialKey) for running 4 unsigned chars through the S-box
unsigned char* Key::sBox256(unsigned char a, unsigned char b, unsigned char c, unsigned char d){
	unsigned char *result = new unsigned char[4];
	result[0] = a;
	result[1] = b;
	result[2] = c;
	result[3] = d;

	result[0] = sBox[result[0]];
	result[1] = sBox[result[1]];
	result[2] = sBox[result[2]];
	result[3] = sBox[result[3]];
	return result;
}
//g function that is called when expanding all 3 key sizes.
unsigned char* Key::g(unsigned char a, unsigned char b, unsigned char c, unsigned char d, unsigned char roundConstant){
	unsigned char *result = new unsigned char[4];
	//First rotate bytes one to the left:
	result[0] = b;
	result[1] = c;
	result[2] = d;
	result[3] = a;
	
	//Perform a byte substitution for each byte using the same 16�16 lookup
	// table used in the SubBytes step
	result[0] = sBox[result[0]];
	result[1] = sBox[result[1]];
	result[2] = sBox[result[2]];
	result[3] = sBox[result[3]];

	//XOR the first byte with the round constant
	result[0] = XOR(result[0], roundConstant);
	return result;
}
//Simple function that XORs two unsigned chars.
unsigned char Key::XOR(unsigned char a, unsigned char b){
	unsigned char result = NULL;
	for(int i = 0; i < 8; i++){
		if(Key::XOR(!!((a >> i) & 1), !!((b >> i) & 1))){
			result |= 1 << i;
		}
	}
	return result;
}
//Even simpler XOR function that is called by other XOR function.
bool Key::XOR(bool i, bool j) {
    return i ^ j;
}
//Returns the array of characters representing the key for a given round in 128 bit key schedule
unsigned char* Key::get128BitKey(int roundNumber){
	unsigned char *roundKey = new unsigned char[16];
	for(int i = 0; i < 16; i++){
		roundKey[i] = key128[i][roundNumber];
	}
	return roundKey;
}
//Returns the array of characters representing the key for a given round in 192 bit key schedule
unsigned char* Key::get192BitKey(int roundNumber){
	int startingPoint = roundNumber * 16;
	unsigned char *roundKey = new unsigned char[16];
	for(int i = 0; i < 16; i++){
		roundKey[i] = key192[startingPoint+i];
	}
	return roundKey;
}
//Returns the array of characters representing the key for a given round in 256 bit key schedule
unsigned char* Key::get256BitKey(int roundNumber){
	int startingPoint = roundNumber * 16;
	unsigned char *roundKey = new unsigned char[16];
	for(int i = 0; i < 16; i++){
		roundKey[i] = key256[startingPoint+i];
	}
	return roundKey;
}
//Called by other classes. Returns the key for a given round number.
unsigned char* Key::getKey(int roundNumber){
	if(bytes == 16){
		return Key::get128BitKey(roundNumber);
	}
	else if(bytes == 24){
		return Key::get192BitKey(roundNumber);
	}
	else{ //bytes == 32
		return Key::get256BitKey(roundNumber);
	}
}