#include <fstream>
#include <string>
#include <locale>
#include "AES.h"
#include "State.h"
using namespace std;

void menu();
bool encryption();
bool decryption();
void ciphertextMenu();
void plaintextMenu();
string getKey();
string getMode();
string getText(string type);
void handleResults(string result, string type);
string readFromFile(bool binary, bool key, string fileName);
bool writeToFile(bool binary, string outputText, string fileName);
string convertASCIIToBinary(string asciiText);
string convertHexToBinary(string hexText);
string convertBinaryToASCII(string binaryText, bool key);
string convertBinaryToHex(string binaryText, bool key);

//Our main method lets the user navigate through a series of menus to encrypt 
//and decrypt text using AES with their desired settings. 
int main() {
	menu();
	string input;
	bool flag = true;
	do{
		cout << "Enter Command: ";
		getline(cin,input);
		if(input.compare("E") == 0){ //Encrypt
			encryption();
			menu();
		}
		else if(input.compare("D") == 0){ //Decrypt
			decryption();
			menu();
		}
		else if(input.compare("Q") == 0){ //Quit
			cout << "\nExiting...";
			flag = false;
		}
		else{
			cout << "\nInvalid command. Please try again.\n" << endl;
		}
	}while(flag);
	return 0;
}
//Displays the main menu.
void menu() {
    cout << endl;
    cout << ".---------------------------------------." << endl;
    cout << "|               Main Menu               |" << endl;
    cout << "|---------------------------------------|" << endl;
    cout << "|   E - Encrypt                         |" << endl;
    cout << "|   D - Decrypt                         |" << endl;
	cout << "|   Q - Quit                            |" << endl;
    cout << "'---------------------------------------'" << endl;
    cout << endl;
}
//Displays the menu for encryption, takes user input, runs AES,
//and allows the user to view ciphertext or write it to a file.
bool encryption(){
	cout << endl;
    cout << ".---------------------------------------." << endl;
    cout << "|                Encrypt                |" << endl;
    cout << "'---------------------------------------'" << endl;
	cout << "(Enter R at any time to return to the main menu)" << endl;
	
	string input;

	//Get plaintext
	string plaintext = getText("plaintext");
	if(plaintext.size() == 0){
		return false;
	}

	//Get key:
	string key = getKey();
	if(key.size() == 0){
		return false;
	}
	int keySize = key.size();

	//Get mode of operation:
	//Let user choose ECB or CBC mode:
	input = getMode();
	if(input.compare("R") == 0){
		return false;
	}

	//Okay, we finally have everything we need.
	cout << "\nEncrypting..." << endl;

	AES aes = AES(keySize);
	string ciphertext;
	if(input.compare("E") == 0){ //User chose electronic codebook
		ciphertext = aes.encryptECB(key, plaintext);
	}
	else if(input.compare("C") == 0){ //User chose cipher block chaining
		ciphertext = aes.encryptCBC(key, plaintext);
	}
	else if(input.compare("T")== 0){ //User chose counter mode
		ciphertext = aes.encryptCTR(key, plaintext);
	}
	else if(input.compare("O")== 0){ //User chose output feedback mode
		ciphertext = aes.encryptOFB(key, plaintext);
	}
	else{ //User chose cipher feedback
		ciphertext = aes.encryptCFB(key, plaintext);
	}

	cout << "\nEncryption was successful." << endl;;
	
	handleResults(ciphertext, "ciphertext");

	return true; 
}
//Displays the menu for decryption, takes user input, runs AES,
//and allows the user to view decrypted text or write it to a file.
bool decryption() {
	cout << endl;
    cout << ".---------------------------------------." << endl;
    cout << "|                Decrypt                |" << endl;
    cout << "'---------------------------------------'" << endl;
	cout << "(Enter R at any time to return to the main menu)" << endl;
	
	string input;

	//Get ciphertext
	string ciphertext = getText("ciphertext");
	if(ciphertext.size() == 0){
		return false;
	}

	//Get key:
	string key = getKey();
	if(key.size() == 0){
		return false;
	}
	int keySize = key.size();

	//Get mode of operation:
	//Let user choose ECB or CBC mode:
	input = getMode();
	if(input.compare("R") == 0){
		return false;
	}

	//Okay, we finally have everything we need.
	cout << "\nDecrypting..." << endl;

	AES aes = AES(keySize);
	string plaintext;
	if(input.compare("E") == 0){ //User chose electronic codebook
		plaintext = aes.decryptECB(key, ciphertext);
	}
	else if(input.compare("C") == 0){ //User chose cipher block chaining
		plaintext = aes.decryptCBC(key, ciphertext);
	}
	else if(input.compare("T")== 0){ //User chose counter mode
		plaintext = aes.decryptCTR(key, ciphertext);
	}
	else if(input.compare("O")== 0){ //User chose output feedback mode
		plaintext = aes.decryptOFB(key, ciphertext);
	}
	else{ //User chose cipher feedback
		plaintext = aes.decryptCFB(key, ciphertext);
	}

	cout << "\nDecryption was successful." << endl;;
	
	handleResults(plaintext, "plaintext");

	return true; 
}
string getText(string type){
	string text = "";
	string input;
	//cout << "\nWould you like to enter ciphertext manually (M) or as a file (F)? ";
	cout << "\nHow would you like to enter the "<< type << "?" << endl;
	cout << "   F - File" << endl;
	cout << "   M - Manually" << endl;
	cout << "Enter F or M: ";
	getline(cin,input);
	bool flag = true;
	do{
		if(input.compare("M") == 0 || input.compare("F") == 0 || input.compare("R") == 0){
			flag = false;
		}
		else{
			cout << "\nInvalid input. Please enter M to enter " << type << " manually, \nF to enter " << type << " as a file, or R to return to the main menu: ";
			getline(cin,input);
		}
	} while(flag);
	
	if(input.compare("R") == 0){
		return text;
	}


	if(input.compare("M") == 0){ //User is entering text manually.
		//cout << "\nWould you like to enter the ciphertext in ASCII (A) or binary (B) format? ";
		cout << "\nIn which format would you like to enter the " << type << "?" << endl;
		cout << "   A - ASCII" << endl;
		cout << "   B - Binary" << endl;
		cout << "   H - Hexadecimal" << endl;
		cout << "Enter A, B, or H: ";
		getline(cin,input);
		flag = true;
		do{
			if(input.compare("A") == 0 || input.compare("B") == 0 || input.compare("H") == 0 ||input.compare("R") == 0){
				flag = false;
			}
			else{
				cout << "\nInvalid input. Please enter A for ASCII format, \nB for binary format, H for hexadecimal format, \nor R to return to the main menu: ";
				getline(cin,input);
			}
		}while(flag);

		if(input.compare("R") == 0){
			return text;
		}

		flag = true;
		do{
			cout << "\nEnter " << type << ": ";
			getline(cin, text);
			if(input.compare("B") == 0){ //Binary format
				//We have to convert binary to ASCII.
				text = convertBinaryToASCII(text, false);
				if(text.size() == 0){
					cout << "\nInvalid size. Number of bits must be divisible by 8.";
				}
				else{
					flag = false;
				}
			}
			else if(input.compare("H") == 0){ //Hex format
				if((text.size() % 2) != 0){
					cout << "\nInvalid size. Number of hexadecimal characters must be even.";
				}
				else{
					text = convertBinaryToASCII(convertHexToBinary(text), false);
				}
			}
			else{
				flag = false;
			}
		}while(flag);
	}
	else{ //User is entering text via a file.
		//cout << "\nIs the file in ASCII (A) or binary (B) format? ";
		cout << "\nWhat is the format of the " << type << " in the file?" << endl;
		cout << "   A - ASCII" << endl;
		cout << "   B - Binary" << endl;
		cout << "   H - Hexadecimal" << endl;
		cout << "Enter A, B, or H: ";
		getline(cin,input);
		flag = true;
		do{
			if(input.compare("A") == 0 || input.compare("B") == 0 || input.compare("H") == 0 || input.compare("R") == 0){
				flag = false;
			}
			else{
				cout << "\nInvalid input. Please enter A for ASCII format, \nB for binary format, H for hexadecimal format, \nor R to return to the main menu: ";
				getline(cin,input);
			}
		}while(flag);

		if(input.compare("R") == 0){
			return false;
		}

		cout << "\nPlease name your file \"" << type << ".txt\". Press enter when file is ready.";
		cin.ignore();

		flag = true;
		do{
			//Open file:
			ifstream inputFile;
			string fileName = type + ".txt";
			inputFile.open(fileName, ios::binary);
			if(!inputFile.is_open()){ //We were unable to open the file.
				cout << "\nFile could not be opened. Please make sure file is named \"" << type << ".txt\"";
				cout << "\nand that it is inside the correct directory. Press enter when file is ready.";
				cin.ignore();
			}
			else{ //File was successfully opened.
				inputFile.close(); //Since we are going to need to open it again in a function in a moment.
				if(input.compare("B") == 0){ //File is in binary format.
					text = readFromFile(true,false,fileName);
					if(text.size() == 0){
						cout << "\nInvalid size. Number of bits must be divisible by 8.";
						cout << "\nPlease modify file and try again. Press enter when \nfile is ready.";
						cin.ignore(); 
					}
					else{
						cout << "\nFile was read successfully." << endl;
						flag = false;
					}
				}
				else if(input.compare("A") == 0){ //File is in ASCII format.
					text = readFromFile(false, false,fileName);
					if(text.size() == 0){
						cout << "\nFile is empty. Please try again. Press enter when \nfile is ready.";
						cin.ignore();
					}
					else{
						cout << "\nFile was read successfully." << endl;
						flag = false;
					}
				}
				else{ //File is in hex format
					text = readFromFile(false, false,fileName);
					if(text.size() == 0){
						cout << "\nFile is empty. Please try again. Press enter when \nfile is ready.";
						cin.ignore();
					}
					else if((text.size() % 2) != 0){
						cout << "\nInvalid size. Number of hexadecimal characters must be even.\nPlease try again. Press enter when file is ready.";
					}
					else{
						text = convertBinaryToASCII(convertHexToBinary(text),false);
						cout << "\nFile was read successfully." << endl;
						flag = false;
					}
				}
			}
		}while(flag);
	}
	return text;
}
string getMode(){
	string input;
	//cout << "\nWould you like to use Electronic Codebook mode (E) or Cipher Block Chaining mode (C)? ";
	cout << "\nWhich mode of operation would you like to use? " << endl;
	cout << "   C - Cipher Block Chaining" << endl;
	cout << "   F - Cipher Feedback" << endl;
	cout << "   O - Output Feedback" << endl;
	cout << "   T - Counter" << endl;
	cout << "   E - Electronic Codebook" << endl;
	cout << "Enter C, F, T, or E: ";
	getline(cin,input);
	bool flag = true;
	do{
		if(input.compare("E") == 0 || input.compare("O") == 0 || input.compare("C") == 0 || input.compare("F") == 0 || input.compare("T") == 0 || input.compare("R") == 0){
			flag = false;
		}
		else{
			cout << "\nInvalid input. Please enter E for Electronic Codebook mode, \nC for Cipher Block Chaining mode, T for counter mode, \nF for Cipher Feedback mode, O for Output Feedback mode, \nor R to return to the main menu: ";
			getline(cin,input);
		}
	}while(flag);
	return input;
}
string getKey(){
	string input;
	string key = "";
	//int keySize;
	
	//Get key
	//cout << "\nWould you like to enter your key manually (M) or as a file (F)? ";
	cout << "\nHow would you like to enter your key?" << endl;
	cout << "   F - File" << endl;
	cout << "   M - Manually" << endl;
	cout << "Enter F or M: ";
	getline(cin,input);
	bool flag = true;
	do{
		if(input.compare("M") == 0 || input.compare("F") == 0 || input.compare("R") == 0){
			flag = false;
		}
		else{
			cout << "\nInvalid input. Please enter M to enter key manually, \nF to enter key as a file, or R to return to the main menu: ";
			getline(cin,input);
		}
	} while(flag);

	if(input.compare("R") == 0){
		return key;
	}

	if(input.compare("M") == 0){ //User is entering key manually.
		//cout << "\nWould you like to enter the key in ASCII (A) or binary (B) format? ";
		cout << "\nIn which format would you like to enter the key?" << endl;
		cout << "   A - ASCII" << endl;
		cout << "   B - Binary" << endl;
		cout << "   H - Hexadecimal" << endl;
		cout << "Enter A, B, or H: ";
		getline(cin,input);
		flag = true;
		do{
			if(input.compare("A") == 0 || input.compare("B") == 0 || input.compare("H") == 0 || input.compare("R") == 0){
				flag = false;
			}
			else{
				cout << "\nInvalid input. Please enter A for ASCII format, \nB for binary format, H for hexadecimal format, \nor R to return to main menu: ";
				getline(cin,input);
			}
		}while(flag);

		if(input.compare("R") == 0){
			return false;
		}

		flag = true;
		do{
			cout << "\nEnter key: ";
			getline(cin, key);
			if(input.compare("B") == 0){ //Binary format
				//We have to convert binary to ASCII.
				key = convertBinaryToASCII(key, true);
				if(key.size() == 0){
					cout << "\nInvalid size. Key must be 128, 192, or 256 bits.";
				}
				else{
					//keySize = key.size() * 8;
					flag = false;
				}
			}
			else if(input.compare("A") == 0){ //ASCII format
				if((key.size() != 16) && (key.size() != 24) && (key.size() != 32)){
					cout << "\nInvalid size. Key must be 128, 192, or 256 bits.";
				}
				else{
					//keySize = key.size() * 8;
					flag = false;
				}
			}
			else{ //Hex format
				if((key.size() != 32) && (key.size() != 48) && (key.size() != 64)){
					cout << "\nInvalid size. Key must be 128, 192, or 256 bits.";
				}
				else{
					//keySize = key.size() * 16;
					key = convertBinaryToASCII(convertHexToBinary(key), false);
					flag = false;
				}
			}
		}while(flag);
	}
	else{ //User is entering key via a file.
		//cout << "\nIs the file in ASCII (A) or binary (B) format? ";
		cout << "\nWhat is the format of the key in the file?" << endl;
		cout << "   A - ASCII" << endl;
		cout << "   B - Binary" << endl;
		cout << "   H - Hexadecimal" << endl;
		cout << "Enter A, B, or H: ";
		getline(cin,input);
		flag = true;
		do{
			if(input.compare("A") == 0 || input.compare("B") == 0 || input.compare("H") == 0 || input.compare("R") == 0){
				flag = false;
			}
			else{
				cout << "\nInvalid input. Please enter A for ASCII format, \nB for binary format, H for hexadecimal format, \nor R to return to main menu: ";
				getline(cin,input);
			}
		}while(flag);

		if(input.compare("R") == 0){
			return false;
		}

		cout << "\nPlease name your file \"key.txt\". Press enter when file is ready.";
		cin.ignore();

		flag = true;
		do{
			//Open file:
			ifstream inputFile;
			inputFile.open("key.txt", ios::binary);
			if(!inputFile.is_open()){ //We were unable to open the file.
				cout << "\nFile could not be opened. Please make sure file is named \"key.txt\"";
				cout << "\nand that it is inside the correct directory. Press enter when file is ready.";
				cin.ignore();
			}
			else{ //File was successfully opened.
				inputFile.close(); //Since we are going to need to open it again in a function in a moment.
				cout << "\nFile was read successfully." << endl;
				if(input.compare("B") == 0){ //File is in binary format.
					key = readFromFile(true,true,"");
					if(key.size() == 0){
						cout << "\nInvalid size. Key must be 128, 192, or 256 bits. Please";
						cout << "\nmodify file and try again. Press enter when file is ready.";
						cin.ignore();
					}
					else if((key.size() != 16) && (key.size() != 24) && (key.size() != 32)){
						cout << "\nInvalid size. Key must be 128, 192, or 256 bits. Please";
						cout << "\nmodify file and try again. Press enter when file is ready.";
						cin.ignore();
					}
					else{
						//keySize = key.size() * 8;
						flag = false;
					}
				}
				else if(input.compare("A") == 0){ //File is in ASCII format.
					key = readFromFile(false,true,"");
					if(key.size() == 0){
						cout << "\nFile is empty. Please try again. Press enter when file is ready.";
						cin.ignore();
					}
					else if((key.size() != 16) && (key.size() != 24) && (key.size() != 32)){
						cout << "\nInvalid size. Key must be 128, 192, or 256 bits. Please";
						cout << "\nmodify file and try again. Press enter when file is ready.";
						cin.ignore();
					}
					else{
						//keySize = key.size() * 8;
						flag = false;
					}
				}
				else{ //Key is in hex format
					key = readFromFile(false,true,"");
					if(key.size() == 0){
						cout << "\nFile is empty. Please try again. Press enter when file is ready.";
						cin.ignore();
					}
					else if((key.size() != 32) && (key.size() != 48) && (key.size() != 64)){
						cout << "\nInvalid size. Key must be 128, 192, or 256 bits. Please";
						cout << "\nmodify file and try again. Press enter when file is ready.";
						cin.ignore();
					}
					else{
						//keySize = key.size() * 16;
						key = convertBinaryToASCII(convertHexToBinary(key), false);
						flag = false;
					}
				}
			}
		}while(flag);
	}
	return key;
}
void handleResults(string result, string type){
	string input;
	bool flag = true;
	do{
		if(type.compare("plaintext") == 0){
			plaintextMenu();
		}
		else{
			ciphertextMenu();
		}
		cout << "Enter Command: ";
		getline(cin,input);
		cout << endl;

		if(input.compare("V") == 0){
			//cout << "Would you like to view the decrypted ciphertext in ASCII (A) \nor binary (B) format? ";
			cout << "In which format would you like to view the " << type << "?" << endl;
			cout << "   A - ASCII" << endl;
			cout << "   B - Binary" << endl;
			cout << "   H - Hexadecimal" << endl;
			cout << "Enter A, B, or H: ";
			getline(cin,input);

			do{
				if(input.compare("A") == 0 || input.compare("B") == 0 || input.compare("H") == 0){
					flag = false;
				}
				else{
					cout << "\nInvalid input. Please enter A for ASCII format, \nB for binary format, or H for hexadecimal format: ";
					getline(cin,input);
				}
			}
			while(flag);
			flag = true;

			if(input.compare("A") == 0){ //View result in ASCII format.
				if(type.compare("ciphertext") == 0){
					cout << "\nCiphertext:\n" << result << endl;
				}
				else{
					cout << "\nPlaintext" << ":\n" << result << endl;
				}
			}
			else if(input.compare("B") == 0){ //View result in binary format.
				if(type.compare("ciphertext") == 0){
					cout << "\nCiphertext:\n" << convertASCIIToBinary(result) << endl;
				}
				else{
					cout << "\nPlaintext:\n" << convertASCIIToBinary(result) << endl;
				}
			}
			else{ //View result in hex format.
				if(type.compare("ciphertext") == 0){
					cout << "\nCiphertext:\n" << convertBinaryToHex(convertASCIIToBinary(result), false) << endl;
				}
				else{
					cout << "\nPlaintext:\n" << convertBinaryToHex(convertASCIIToBinary(result), false) << endl;
				}
			}
			cout << endl;
		}
		else if(input.compare("W") == 0){
			//cout << "Would you like to write the file in ASCII (A) or binary (B) format? ";
			cout << "In which format would you like the file to be written?" << endl;
			cout << "   A - ASCII" << endl;
			cout << "   B - Binary" << endl;
			cout << "   H - Hexadecimal" << endl;
			cout << "Enter A, B, or H: ";
			getline(cin,input);

			do{
				if(input.compare("A") == 0 || input.compare("B") == 0 || input.compare("H") == 0){
					flag = false;
				}
				else{
					cout << "\nInvalid input. Please enter A for ASCII format, \nB for binary format, or H for hexadecimal format: ";
					getline(cin,input);
				}
			}
			while(flag);
			flag = true;

			string fileName = type + ".txt";
			if(input.compare("A") == 0){ //Write plaintext in ASCII format.
				writeToFile(false,result,fileName);
			}
			else if(input.compare("B") == 0){ //Write plaintext in binary format.
				writeToFile(true,result,fileName);
			}
			else{ //Write plaintext in hex format.
				writeToFile(false,convertBinaryToHex(convertASCIIToBinary(result), false),fileName);
			}
			cout << "\nThe " << type << " can be found in \"" << type << ".txt\"." << endl;
			cout << endl;
		}
		else if(input.compare("R") == 0){
			flag = false;
		}
		else{
			cout << "\nInvalid command. Please try again.\n" << endl;
		}
	}while(flag);
}

//Displays menu after ciphertext is created.
void ciphertextMenu() {
    cout << ".---------------------------------------." << endl;
    cout << "|   V - View Ciphertext                 |" << endl;
    cout << "|   W - Write Ciphertext to File        |" << endl;
    cout << "|   R - Return to Main Menu             |" << endl;
    cout << "'---------------------------------------'" << endl;
    cout << endl;
}

//Displays menu after ciphertext has been decrypted.
void plaintextMenu(){
	cout << ".---------------------------------------." << endl;
    cout << "|   V - View Decrypted Text             |" << endl;
    cout << "|   W - Write Decrypted Text to File    |" << endl;
    cout << "|   R - Return to Main Menu             |" << endl;
    cout << "'---------------------------------------'" << endl;
    cout << endl;
}

//Takes in a string in hex and converts it to binary.
string convertHexToBinary(string hexText){
	locale loc;
	string binaryString = "";
	char currentChar;
	for(int i = 0; i < hexText.size(); i++){ //For each character in the input string
		currentChar = tolower(hexText[i],loc);
		switch(currentChar){
		case '0':
			binaryString += "0000";
			break;
		case '1':
			binaryString += "0001";
			break;
		case '2':
			binaryString += "0010";
			break;
		case '3':
			binaryString += "0011";
			break;
		case '4':
			binaryString += "0100";
			break;
		case '5':
			binaryString += "0101";
			break;
		case '6':
			binaryString += "0110";
			break;
		case '7':
			binaryString += "0111";
			break;
		case '8':
			binaryString += "1000";
			break;
		case '9':
			binaryString += "1001";
			break;
		case 'a':
			binaryString += "1010";
			break;
		case 'b':
			binaryString += "1011";
			break;
		case 'c':
			binaryString += "1100";
			break;
		case 'd':
			binaryString += "1101";
			break;
		case 'e':
			binaryString += "1110";
			break;
		case 'f':
			binaryString += "1111";
			break;
		default:
			binaryString += "0000";
			break;
		}
	}
	return binaryString;
}
//Takes in a string in ASCII and converts it to binary.
string convertASCIIToBinary(string asciiText){
	string binaryString = "";
	for(int i = 0; i < asciiText.size(); i++){ //For each character in the input string
		//Convert it to binary and write it bit by bit to the outputFile
		for(int j = 0; j < 8; j++){
			int currentBit = (asciiText[i] >> (7-j)) & 1;
			if(currentBit == 1){
				binaryString += '1';
			}
			else{
				binaryString += '0';
			}
		}
	}
	return binaryString;
}
//Takes in a string in binary and converts it to ASCII.
string convertBinaryToASCII(string binaryText, bool key){
	string asciiText = "";
	if((binaryText.size() % 8) != 0){
		return asciiText;
	}
	if(key){
		if((binaryText.size() != 128) && (binaryText.size() != 192) && (binaryText.size() != 256)){ //Key isn't the right size.
			return "";
		}
	}
	char currentBit;
	for(int i = 0; i < binaryText.size(); i += 8){ //For each group of 8 bits in the binary string
		//Convert group of 8 bits to an unsigned char.
		unsigned char currentByte = NULL;
		for(int j = 0; j < 8; j++){
			currentBit = binaryText[i + j];
			if(currentBit == '1'){
				currentByte |= 1 << (7 - j);
			}
		}
		asciiText += currentByte;
	}
	return asciiText;
}
string convertBinaryToHex(string binaryText, bool key){
	string hexText = "";
	if((binaryText.size() % 8) != 0){
		return hexText;
	}
	if(key){
		if((binaryText.size() != 128) && (binaryText.size() != 192) && (binaryText.size() != 256)){ //Key isn't the right size.
			return "";
		}
	}
	string currentHalfByte;
	for(int i = 0; i < binaryText.size(); i += 4){ //For each group of 4 bits in the binary string
		//cout << "i = " << i << " - ";
		currentHalfByte = binaryText[i];
		currentHalfByte += binaryText[i+1];
		currentHalfByte += binaryText[i+2];
		currentHalfByte += binaryText[i+3];
		//cout << currentHalfByte << endl;
		if(currentHalfByte == "0000"){
			hexText += "0";
		}
		else if(currentHalfByte == "0001"){
			hexText += "1";
		}
		else if(currentHalfByte == "0010"){
			hexText += "2";
		}
		else if(currentHalfByte == "0011"){
			hexText += "3";
		}
		else if(currentHalfByte == "0100"){
			hexText += "4";
		}
		else if(currentHalfByte == "0101"){
			hexText += "5";
		}
		else if(currentHalfByte == "0110"){
			hexText += "6";
		}
		else if(currentHalfByte == "0111"){
			hexText += "7";
		}
		else if(currentHalfByte == "1000"){
			hexText += "8";
		}
		else if(currentHalfByte == "1001"){
			hexText += "9";
		}
		else if(currentHalfByte == "1010"){
			hexText += "a";
		}
		else if(currentHalfByte == "1011"){
			hexText += "b";
		}
		else if(currentHalfByte == "1100"){
			hexText += "c";
		}
		else if(currentHalfByte == "1101"){
			hexText += "d";
		}
		else if(currentHalfByte == "1110"){
			hexText += "e";
		}
		else if(currentHalfByte == "1111"){
			hexText += "f";
		}
	}
	return hexText;
}
//Writes a string to Output.txt. Writes in binary format, if the
//first parameter is true.
bool writeToFile(bool binary, string outputText, string fileName){
	ofstream outputFile;
	outputFile.open(fileName, ios::trunc | ios::binary);
	if(!outputFile.is_open()){ //We were unable to open/create the output file.
		return false;
	}
	if(binary){
		for(int i = 0; i < outputText.size(); i++){ //For each character in the output string
			//Convert it to binary and write it bit by bit to the outputFile
			for(int j = 0; j < 8; j++){
				int currentBit = (outputText[i] >> (7-j)) & 1;
				outputFile << currentBit;
			}
		}
	}
	else{
		outputFile << outputText;
	}
	outputFile.close();
	return true;
}
//Reads a string from specified file. Reads in binary format, if the
//first parameter is true.
string readFromFile(bool binary, bool key, string fileName){
	string input = "";
	ifstream inputFile;
	if(binary){
		if(key){
			inputFile.open("Key.txt");
		}
		else{
			inputFile.open(fileName);
		}
	}
	else{
		if(key){
			inputFile.open("Key.txt", ios::binary);
		}
		else{
			inputFile.open(fileName, ios::binary);
		}
	}
	if(!inputFile.is_open()){ //We were unable to open the input file.
		return input;
	}
	if(binary){ //If we're reading from a binary file:
		char currentBit;
		int counter = 0;
		while(inputFile.get(currentBit)){
			unsigned char currentByte = NULL;
			for(int i = 0; i < 8; i++){
				if(currentBit == '1'){
					currentByte |= 1 << (7 - i);
				}
				if(i != 7){
					if(!inputFile.get(currentBit)){
						return "";
					}
				}
			}
			input += currentByte;
			counter++;
		}
	}
	else{
		char currentChar;
		while(inputFile.get(currentChar)){
			currentChar = (unsigned char) currentChar;
			input += currentChar;
		}
	}
	inputFile.close();
	return input;
}