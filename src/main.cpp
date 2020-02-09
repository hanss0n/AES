#include <iostream>
#include "AES.h"

int main() {

    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);




    //TODO: make this faster
    unsigned char key[16];
    unsigned char message[16];


    if (fread(key, 4, 4, stdin)) {
        AES aes(key);
        while (!feof(stdin)) {
            if (fread(message, 4, 4, stdin)) {
                if (!feof(stdin)) {
                    aes.encrypt_16_bytes(message);
                    fwrite(message, 4, 4, stdout);
                }
            }
        }
    }

    return 0;
}