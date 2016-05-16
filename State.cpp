#include <iostream>
#include <bitset>
#include <sstream>
#include "State.h"
#include "SBox.h"

using namespace std;

//Constructor for State class
State::State(string plaintext) {
	initializeStateArray(plaintext);
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
//Initializes stateArray with plaintext (which can also
//be ciphertext).
void State::initializeStateArray(string plaintext){
	int sizeOfPlainText = plaintext.size();
	int currentChar = 0;
	if(sizeOfPlainText == 16){ //No need to pad.
		for(int i = 0; i < 4; i++){
			for(int j = 0; j < 4; j++){
				stateArray[j][i] = plaintext[currentChar];
				currentChar++;
			}
		}
	}
	else{ //Have to pad to get it to 16 bytes.
		for(int i = 0; i < 4; i++){
			for(int j = 0; j < 4; j++){
				if(currentChar < sizeOfPlainText){
					stateArray[j][i] = plaintext[currentChar];
				}
				else{
					stateArray[j][i] = ' ';
				}
				currentChar++;
			}
		}
	}
}
//Returns state in a string form.
string State::printState(){
    string s = "";
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s+= stateArray[j][i];
        }
    }
    return s;
}

//Prints entire state in binary in a 4x4 grid (Used for testing)
string State::printStateInBinary(){
    string s = "";
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s+= charToBinaryString(stateArray[i][j]) + " ";
        }
        s += "\n";
    }
    return s;
}
//XOR the state with a 16 byte key.
void State::addRoundKey(unsigned char *subKey) {
	int counter = 0;
    for(int i = 0; i < 4; i++){
		for(int j = 0; j < 4; j++){
			stateArray[j][i] = XOR(stateArray[j][i], subKey[counter]); 
			counter++;
		}
	}
}

//Based on implementation described in:
//https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
void State::invMixColumns() {
	for(int i = 0; i < 4; i++){ //For each column:
		invMixIndividualColumn(i);
	}
}

void State::invMixIndividualColumn(int columnIndex){
	unsigned char resultColumn[4];
	unsigned char times9Product, times11Product, times13Product, times14Product;

	//First byte in the column:
	times14Product = galoisFieldMultiply(stateArray[0][columnIndex],14);
	times11Product = galoisFieldMultiply(stateArray[1][columnIndex],11);
	times13Product = galoisFieldMultiply(stateArray[2][columnIndex],13);
	times9Product = galoisFieldMultiply(stateArray[3][columnIndex],9);
	resultColumn[0] = XOR(XOR(times14Product,times11Product),XOR(times13Product,times9Product));

	//Second byte in the column:
	times9Product = galoisFieldMultiply(stateArray[0][columnIndex],9);
	times14Product = galoisFieldMultiply(stateArray[1][columnIndex],14);
	times11Product = galoisFieldMultiply(stateArray[2][columnIndex],11);
	times13Product = galoisFieldMultiply(stateArray[3][columnIndex],13);
	resultColumn[1] = XOR(XOR(times14Product,times11Product),XOR(times13Product,times9Product));

	//Third byte in the column:
	times13Product = galoisFieldMultiply(stateArray[0][columnIndex],13);
	times9Product = galoisFieldMultiply(stateArray[1][columnIndex],9);
	times14Product = galoisFieldMultiply(stateArray[2][columnIndex],14);
	times11Product = galoisFieldMultiply(stateArray[3][columnIndex],11);
	resultColumn[2] = XOR(XOR(times14Product,times11Product),XOR(times13Product,times9Product));
	
	//Fourth byte in the column:
	times11Product = galoisFieldMultiply(stateArray[0][columnIndex],11);
	times13Product = galoisFieldMultiply(stateArray[1][columnIndex],13);
	times9Product = galoisFieldMultiply(stateArray[2][columnIndex],9);
	times14Product = galoisFieldMultiply(stateArray[3][columnIndex],14);
	resultColumn[3] = XOR(XOR(times14Product,times11Product),XOR(times13Product,times9Product));
	
	for(int i = 0; i < 4; i++){
		stateArray[i][columnIndex] = resultColumn[i];
	}
}

//Inverts the ShiftRows operation.
//Shifts each row by a predetermined number of spots.
//Based on implementation described in:
//https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
void State::invShiftRows() {
	//Shift second row one byte to the right:
    unsigned char temp1 =  stateArray[1][3];
    stateArray[1][3] = stateArray[1][2];
    stateArray[1][2] = stateArray[1][1];
    stateArray[1][1] = stateArray[1][0];
    stateArray[1][0] = temp1;
    	
    //Shift third row two bytes to the right:
   	temp1 = stateArray[2][0];
   	unsigned char temp2 = stateArray[2][1];
   	stateArray[2][0] = stateArray[2][2];
   	stateArray[2][1] = stateArray[2][3];
   	stateArray[2][2] = temp1;
   	stateArray[2][3] = temp2;
    	
    //Shift fourth row three bytes to the right:
    temp1 = stateArray[3][0];
    stateArray[3][0] = stateArray[3][1];
    stateArray[3][1] = stateArray[3][2];
    stateArray[3][2] = stateArray[3][3];
    stateArray[3][3] = temp1;

}

//Inverts the SubBytes operation. 
//Iterates through each byte in the state and replaces it with 
//correct value from the inverse SBox.
//Based on implementation described in:
//https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
void State::invSubBytes() {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			stateArray[i][j] = invSBox[stateArray[i][j]];
        }
    }
}

//Based on implementation described in:
//https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
void State::mixColumns() {
	for(int i = 0; i < 4; i++){ //For each column:
		mixIndividualColumn(i);
	}
}

void State::mixIndividualColumn(int columnIndex){
	unsigned char resultColumn[4];
	unsigned char times2Product, times3Product;

	//First byte in the column:
	times2Product = galoisFieldMultiply(stateArray[0][columnIndex], 2);
	//cout << "Times 2 product " << charToBinaryString(times2Product) << endl;
	times3Product = galoisFieldMultiply(stateArray[1][columnIndex], 3);
	//cout << "Times 3 product " << charToBinaryString(times3Product) << endl;
	//cout << charToBinaryString(times2Product) << " XOR " << charToBinaryString(times3Product);
	//cout << " XOR " << charToBinaryString(stateArray[2][columnIndex]) << " XOR " << charToBinaryString(stateArray[3][columnIndex]) << endl;
	//cout << " = " << endl;
	//cout << charToBinaryString(XOR(times2Product,times3Product)) << " XOR " << charToBinaryString(XOR(stateArray[2][columnIndex],stateArray[3][columnIndex])) << endl;
	resultColumn[0] = XOR(XOR(times2Product,times3Product),XOR(stateArray[2][columnIndex],stateArray[3][columnIndex]));
	//cout << "Result: " << resultColumn[0] << endl;

	//Second byte in the column:
	times2Product = galoisFieldMultiply(stateArray[1][columnIndex], 2);
	times3Product = galoisFieldMultiply(stateArray[2][columnIndex], 3);
	resultColumn[1] = XOR(XOR(times2Product,times3Product),XOR(stateArray[3][columnIndex],stateArray[0][columnIndex]));

	//Third byte in the column:
	times2Product = galoisFieldMultiply(stateArray[2][columnIndex], 2);
	times3Product = galoisFieldMultiply(stateArray[3][columnIndex], 3);
	resultColumn[2] = XOR(XOR(times2Product,times3Product),XOR(stateArray[0][columnIndex],stateArray[1][columnIndex]));

	//Fourth byte in the column:
	times2Product = galoisFieldMultiply(stateArray[3][columnIndex], 2);
	times3Product = galoisFieldMultiply(stateArray[0][columnIndex], 3);
	resultColumn[3] = XOR(XOR(times2Product,times3Product),XOR(stateArray[1][columnIndex],stateArray[2][columnIndex]));

	for(int i = 0; i < 4; i++){
		stateArray[i][columnIndex] = resultColumn[i];
	}
}

unsigned char State::galoisFieldMultiply(unsigned char a, int num){
	unsigned char result;

	result = a << 1;
	//cout << "Result " << result << endl;
	/*
	unsigned char char1B = NULL;
	char1B |= 1 << 4;
	char1B |= 1 << 3;
	char1B |= 1 << 1;
	char1B |= 1 << 0;
	cout << "Char1b = " << charToBinaryString(char1B) << endl;
	*/

	if(((a >> 7) & 1) == 1){ //If high bit of first byte is set:
		//cout << "High bit is set!" << endl;
		unsigned char char1B = NULL;
		char1B |= 1 << 4;
		char1B |= 1 << 3;
		char1B |= 1 << 1;
		char1B |= 1 << 0;
		result = XOR(result, char1B);
	}

	if(num == 3){
		result = XOR(result, a);
	}

	if(num == 9){
		result = galoisFieldMultiply(result, 2);
		result = galoisFieldMultiply(result, 2);
		result = XOR(result, a);
	}

	if(num == 11){
		result = galoisFieldMultiply(result, 2);
		result = XOR(result, a);
		result = galoisFieldMultiply(result, 2);
		result = XOR(result, a);
	}

	if(num == 13){
		result = XOR(result, a);
		result = galoisFieldMultiply(result, 2);
		result = galoisFieldMultiply(result, 2);
		result = XOR(result, a);
	}

	if(num == 14){
		result = XOR(result, a);
		result = galoisFieldMultiply(result, 2);
		result = XOR(result, a);
		result = galoisFieldMultiply(result, 2);
	}

	return result;
}

//Shifts each row by a predetermined number of spots.
//Based on implementation described in:
//https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
void State::shiftRows() {
	//Shift second row one byte to the left:
	unsigned char temp1 = stateArray[1][0];
	stateArray[1][0] = stateArray[1][1];
    stateArray[1][1] = stateArray[1][2];
    stateArray[1][2] = stateArray[1][3];
    stateArray[1][3] = temp1;

	//Shift third row two bytes to the left:
	temp1 = stateArray[2][0];
    unsigned char temp2 = stateArray[2][1];
    stateArray[2][0] = stateArray[2][2];
    stateArray[2][1] = stateArray[2][3];
    stateArray[2][2] = temp1;
    stateArray[2][3] = temp2;
    	
    //Shift fourth row three bytes to the left:
    temp1 = stateArray[3][3];
    stateArray[3][3] = stateArray[3][2];
    stateArray[3][2] = stateArray[3][1];
    stateArray[3][1] = stateArray[3][0];
    stateArray[3][0] = temp1;
}
//Iterates through each byte in the state and replaces it with 
//correct value from the SBox.
//Based on implementation described in:
//https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
void State::subBytes() {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			stateArray[i][j] = sBox[stateArray[i][j]];
        }
    }    
}
//XORs the state with a string. Used in CBC mode.
void State::XORWithString(string previousCiphertextBlock){
	//Go through each character in previousCiphertextBlock
	//	Cast to unsigned char
	//	XOR with appropriate char in state
	unsigned char currentByte;
	int counter = 0;
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < 4; j++){
			currentByte = (unsigned char) previousCiphertextBlock[counter];
			stateArray[j][i] = XOR(stateArray[j][i], currentByte);
			counter++;
		}
	}
}
//XORs two unsigned chars and returns the result:
unsigned char State::XOR(unsigned char a, unsigned char b){
	return a ^ b;
}

//Convert an unsigned char to a binary string:
string State::charToBinaryString(unsigned char a) {
    //bitset<8> x(a);
	//string partA = x.to_string();
	string output = "";
	stringstream stream;
	for(int j = 0; j < 8; j++){
		int currentBit = (a >> (7-j)) & 1;
		stream << currentBit;
		output = stream.str();
	}
    //return x.to_string();
	return output;
}

State::~State() {
}
