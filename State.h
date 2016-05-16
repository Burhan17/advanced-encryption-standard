#ifndef STATE_H
#define STATE_H

#include <string>

using namespace std;

class State {

    private:
		unsigned char stateArray[4][4];
		unsigned char sBox[256];
		unsigned char invSBox[256];
		void initializeStateArray(string plaintext);
		void mixIndividualColumn(int columnIndex);
		void invMixIndividualColumn(int columnIndex);
		unsigned char galoisFieldMultiply(unsigned char a, int num);
    public:
        State(string plaintext);
        ~State();
        string printState();
        string printStateInBinary();
        void addRoundKey(unsigned char *subKey);
        void invMixColumns();
        void invShiftRows();
        void invSubBytes();
        void mixColumns();
        void shiftRows();
        void subBytes();
		void XORWithString(string previousCiphertextBlock);
		unsigned char XOR(unsigned char a, unsigned char b);
        string charToBinaryString(unsigned char a);
};

#endif //STATE_H
