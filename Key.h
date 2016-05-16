#ifndef KEY_H
#define KEY_H

#include <string>

using namespace std;

class Key {
    private:
        unsigned char key128[16][11];
		unsigned char key192[208];
		unsigned char key256[240];
		void expandKey128(string initialKey);
		void expandKey192(string initialKey);
		void expandKey256(string initialKey);
		unsigned char* get128BitKey(int roundNumber);
		unsigned char* get192BitKey(int roundNumber);
		unsigned char* get256BitKey(int roundNumber);
		unsigned char* g(unsigned char a, unsigned char b, unsigned char c, unsigned char d, unsigned char roundConstant);
		unsigned char* sBox256(unsigned char a, unsigned char b, unsigned char c, unsigned char d);
		unsigned char XOR(unsigned char a, unsigned char b);
        bool XOR(bool i, bool j);
		int bytes;
		unsigned char sBox[256];
		unsigned char invSBox[256];
    public:
        Key(string initialKey);
		unsigned char* getKey(int roundNumber);
};

#endif //KEY_H