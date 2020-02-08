#include <iostream>
#include <vector>
#include "AES.h"


void print_hex(unsigned char x) {
    if (x / 16 < 10) {
        std::cout << (char) ((x / 16) + '0');
    }
    if (x / 16 >= 10) {
        std::cout << (char) ((x / 16 - 10) + 'A');
    }
    if (x % 16 < 10) {
        std::cout << (char) ((x % 16) + '0');
    }
    if (x % 16 >= 10) {
        std::cout << (char) ((x % 16 - 10) + 'A');
    }
}

int main() {

    unsigned char key[16] = {0xF4,0xC0,0x20,0xA0,0xA1,0xF6,0x04,0xFD,0x34,0x3F,0xAC,0x6A,0x7E,0x6A,0xE0,0xF9};
    unsigned char message[16] = {0xF2,0x95,0xB9,0x31,0x8B,0x99,0x44,0x34,0xD9,0x3D,0x98,0xA4,0xE4,0x49,0xAF,0xD8};


    AES aes(key);
    aes.encrypt(message);


    for (unsigned char i : message) {
        print_hex(i);
    }

    return 0;
}