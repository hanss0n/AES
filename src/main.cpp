#include <iostream>
#include "AES.h"

int main() {

    //TODO: make this faster
    unsigned char key[16];
    unsigned char message[16];
    size_t size_k, size_m;

    if (fread(key, 4, 4, stdin)) {
        AES aes(key);
        while (!feof(stdin)) {
            if (fread(message, 4, 4, stdin)) {
                if (!feof(stdin)) {
                    fwrite(aes.encrypt(message), 4, 4, stdout);
                }
            }
        }
    }

    return 0;
}