#include <iostream>

/* AES Encryption
 * Project will encrypt and decrypt files, probably copy the original so mistakes are not as bad
 * Stretch goal will be to create a GUI for file encryption
 *      Could transform into some kind of password manager
 *      just encrypt/decrypt XML file and do stuff with output
 * */

#include "AES.h"
#include "AES_FASTER.h"

int main() {
    AES aes = AES();
    AES_FASTER aes2 = AES_FASTER();

    uint8_t data[] = {0x00, 0x01, 0x02, 0x03,
                      0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x10, 0x11,
                      0x12, 0x13, 0x14, 0x15};
    uint8_t data2[] = {0x00, 0x01, 0x02, 0x03,
                      0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x10, 0x11,
                      0x12, 0x13, 0x14, 0x15};
    uint8_t key[] = {0x15, 0x14, 0x13, 0x12,
                     0x11, 0x10, 0x09, 0x08,
                     0x07, 0x06, 0x05, 0x04,
                     0x03, 0x02, 0x01, 0x00};
    uint8_t key2[] = {0x15, 0x14, 0x13, 0x12,
                     0x11, 0x10, 0x09, 0x08,
                     0x07, 0x06, 0x05, 0x04,
                     0x03, 0x02, 0x01, 0x00};
    auto testval = &data2;
    aes.encrypt(data, key, 128, 128);
    aes2.encrypt(key2, data2, 128, 128, nullptr);
    aes.decrypt();
    aes2.decrypt(key2, data2, 128, 128, nullptr);

    int debug = 0;
    return 0;
}
