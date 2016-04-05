#include <iostream>
#include <cstdint>
#include <cstdio>
#include <cmath>

const uint32_t Rcon[11] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 
                            0x10000000, 0x20000000, 0x40000000,
                            0x80000000, 0x1B000000, 0x36000000, 
                            0x6C000000 };

const uint8_t Encryption_Lookup_Table[16][16] = {
    { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 
      0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76 },

    { 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 
      0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0 },

    { 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
      0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15 },

    { 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
      0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75 },

    { 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
      0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84 },

    { 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
      0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xA8 },
    
    { 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
      0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8 },

    { 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 
      0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2 },

    { 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
      0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73 },

    { 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
      0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB },

    { 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
      0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79 },

    { 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
      0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08 },

    { 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
      0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A },

    { 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
      0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E },

    { 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
      0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF },

    { 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
      0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 }

};

const uint8_t Decryption_Lookup_Table[16][16] = {
      { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 
        0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB },

      { 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 
        0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB },

      { 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 
        0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E },

      { 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
        0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 },

      { 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 },

      { 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 
        0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 },

      { 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 
        0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 },

      { 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
        0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B },

      { 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 
        0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 },

      { 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 
        0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E },

      { 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 
        0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B },

      { 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 
        0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 },

      { 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 
        0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F },

      { 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
        0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF },

      { 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 
        0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 },

      { 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 
        0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D }
};

void encrypt(uint8_t message[16], uint8_t cipher[16], uint8_t key[16]);
void decrypt(uint8_t cipher[16], uint8_t message[16], uint8_t key[16]);

void generate_round_keys(uint32_t w[44], uint8_t key[][4]);

uint32_t SubBytes(uint32_t value);

void SubBytes(uint8_t array[][4]);
void Inverse_SubBytes(uint8_t array[][4]);

void ShiftRows(uint8_t array[][4]);
void Inverse_ShiftRows(uint8_t array[][4]);

void MixColumns(uint8_t array[][4]);
void Inverse_MixColumns(uint8_t array[][4]);

void XorRoundKey(uint8_t array[][4], uint8_t key[][4]);
void Inverse_XorRoundKey(uint8_t array[][4], uint8_t key[][4]);

uint32_t rotate32_left(uint32_t value, uint8_t shift);
uint8_t GF_Mult(uint8_t value1, uint8_t value2);

void print_state(uint8_t array[][4]);
void print_key(uint8_t array[][4]);

int main(int argc, char** argv)
{
    // Message is a 16 byte message to encrypt
    uint8_t message[16] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };

    printf("Message: ");
    for(uint8_t i = 0; i < 16; ++i)
    {
        printf("0x%02X ", message[i]);
    }
    printf("\n");

    // Cipher array to hold the value for the output of the encrypt function
    uint8_t cipher[16];

    // Plain_text array to hold decrypted message
    uint8_t plain_text[16];

    // Key is a 16 byte key for encrypting/decrypting the message
    uint8_t key[16] = { 0x0F, 0x15, 0x71, 0xC9, 0x47, 0xD9, 0xE8, 0x59,
                        0x0C, 0xB7, 0xAD, 0xD6, 0xAF, 0x7F, 0x67, 0x98 };

    printf("Key: ");
    for(uint8_t i = 0; i < 16; ++i)
    {
        printf("0x%02X ", key[i]);
    }
    printf("\n");
    
    encrypt(message, cipher, key);

    printf("Cipher: ");
    for(uint8_t i = 0; i < 16; ++i)
    {
        printf("0x%02X ", cipher[i]);
    }
    printf("\n");

    decrypt(cipher, plain_text, key);

    printf("Plain Text: ");
    for(uint8_t i = 0; i < 16; ++i)
    {
        printf("0x%02X ", plain_text[i]);
    }
    printf("\n");
    return 0;
}

void encrypt(uint8_t message[16], uint8_t cipher[16], uint8_t key[16])
{
    // Holds the 'state' for AES
    uint8_t input[4][4];

    // Holds the key in a more accessible way
    uint8_t key_2d[4][4];

    // Array for round keys
    uint32_t w[44];

    // split up the message and key into the input 2d array and key 2d array
    for(uint8_t i = 0; i < 16; ++i)
    {
        // i = 0  -> [0][0]
        // i = 1  -> [0][1]
        // ...
        // i = 14 -> [3][2]
        // i = 15 -> [3][3]
        input[i/4][i%4] = message[i];
        key_2d[i/4][i%4] = key[i];
    }

    generate_round_keys(w, key_2d);
    
    uint8_t round_key[4][4];

    //printf("Initial State:\n");
    //print_state(input);

    for(uint8_t i = 0; i < 4; ++i)
    {
        for(uint8_t j = 0; j < 4; ++j)
        {
            round_key[i][j] = (w[i] & (0xFF000000 >> j*8)) >> (24 - j*8);
        }
    }
    //printf("Round Key:\n");
    //print_key(round_key);

    XorRoundKey(input, round_key);
    //printf("Add Key: \n");
    //print_state(input);

    //printf("Starting...\n");
    for(uint8_t i = 1; i < 10; ++i)
    {
        //printf("Round: %d\n", i);
        SubBytes(input);
        //printf("SubBytes: \n");
        //print_state(input);

        ShiftRows(input);
        //printf("ShiftRows: \n");
        //print_state(input);

        MixColumns(input);
        //printf("MixColumns: \n");
        //print_state(input);

        //printf("Round Key:\n");
        for(uint8_t j = 0; j < 4; ++j)
        {
            for(uint8_t h = 0; h < 4; ++h)
            {
                round_key[j][h] = (w[4*i+j] & (0xFF000000 >> h*8)) >> (24 - h*8);
            }
        }
        //print_key(round_key);

        XorRoundKey(input, round_key);
        //printf("XorRoundKey: \n");
        //print_state(input);
    }

    //printf("End for loop\n\n");

    SubBytes(input);
    //printf("SubBytes: \n");
    //print_state(input);

    ShiftRows(input);
    //printf("ShiftRows: \n");
    //print_state(input);

    //printf("Round Key:\n");
    for(uint8_t j = 0; j < 4; ++j)
    {
        for(uint8_t h = 0; h < 4; ++h)
        {
            round_key[j][h] = (w[j+40] & (0xFF000000 >> h*8)) >> (24 - h*8);
        }
    }

    //print_key(round_key);

    XorRoundKey(input, round_key);
    //printf("XorRoundKey: \n");
    //print_state(input);

    for(uint8_t i = 0; i < 4; ++i)
    {
        for(uint8_t j = 0; j < 4; ++j)
        {
            cipher[i*4+j] = input[i][j];
        }
    }
}

void decrypt(uint8_t cipher[16], uint8_t message[16], uint8_t key[16])
{
    // Holds the 'state' for AES
    uint8_t input[4][4];

    // Holds the key in a more accessible way
    uint8_t key_2d[4][4];

    // Array for round keys
    uint32_t w[44];

    // split up the message and key into the input 2d array and key 2d array
    for(uint8_t i = 0; i < 16; ++i)
    {
        // i = 0  -> [0][0]
        // i = 1  -> [0][1]
        // ...
        // i = 14 -> [3][2]
        // i = 15 -> [3][3]
        input[i/4][i%4] = cipher[i];
        key_2d[i/4][i%4] = key[i];
    }

    generate_round_keys(w, key_2d);
    
    uint8_t round_key[4][4];

    //printf("Initial State:\n");
    //print_state(input);

    for(uint8_t i = 0; i < 4; ++i)
    {
        for(uint8_t j = 0; j < 4; ++j)
        {
            round_key[i][j] = (w[i+40] & (0xFF000000 >> j*8)) >> (24 - j*8);
        }
    }
    //printf("round key:\n");
    //print_key(round_key);

    XorRoundKey(input, round_key);
    //printf("Add Key:\n");
    //print_state(input);
    
    for(uint8_t i = 0; i < 9; ++i)
    {
        //printf("Round %d:", i);
        Inverse_ShiftRows(input);
        //printf("Inverse_ShiftRows:\n");
        //print_state(input);

        Inverse_SubBytes(input);
        //printf("Inverse_SubBytes:\n");
        //print_state(input);

        for(uint8_t j = 0; j < 4; ++j)
        {
            for(uint8_t h = 0; h < 4; ++h)
            {
                round_key[j][h] = (w[36-4*i+j] & (0xFF000000 >> h*8)) >> (24 - h*8);
            }
        }
        //printf("round key:\n");
        //print_key(round_key);

        XorRoundKey(input, round_key);
        //printf("Add key:\n");
        //print_state(input);

        Inverse_MixColumns(input);
        //printf("Inverse_MixColumns:\n");
        //print_state(input);
    }

    Inverse_ShiftRows(input);
    //printf("Inverse_ShiftRows:\n");
    //print_state(input);
    
    Inverse_SubBytes(input);
    //printf("Inverse_SubBytes:\n");
    //print_state(input);

    for(uint8_t i = 0; i < 4; ++i)
    {
        for(uint8_t j = 0; j < 4; ++j)
        {
            round_key[i][j] = (w[i] & (0xFF000000 >> j*8)) >> (24 - j*8);
        }
    }
    //printf("round key:\n");
    //print_key(round_key);

    XorRoundKey(input, round_key);
    //printf("Add Key:\n");
    //print_state(input);

    for(uint8_t i = 0; i < 4; ++i)
    {
        for(uint8_t j = 0; j < 4; ++j)
        {
            message[i*4+j] = input[i][j];
        }
    }
}

void generate_round_keys(uint32_t w[44], uint8_t key[][4])
{
    // Set up the initial round key based on the key input
    for(uint8_t i = 0; i < 4; ++i)
    {
        w[i] = key[i][0] << 24 | key[i][1] << 16 | key[i][2] << 8 | key[i][3];
        //printf("w[%d] = %08X\n", i, w[i]);
    }

    uint32_t temp;
    for(uint8_t i = 4; i < 44; ++i)
    {
        temp = w[i-1];

        if(i % 4 == 0)
        {
            temp = rotate32_left(temp, 8);
            //printf("RotWord() = %08X\n", temp);
            temp = SubBytes(temp);
            //printf("SubWord() = %08X\n", temp);
            temp = temp ^ Rcon[(i-4)/4];
            //printf("^ Rcon = %08X\n", temp);
        }
        w[i] = w[i-4] ^ temp;
        //printf("w[%d] = %08X\n", i, w[i]);
    }

}

uint32_t rotate32_left(uint32_t value, uint8_t shift)
{
    return (value << shift) | (value >> (32 - shift));
}

uint32_t SubBytes(uint32_t value)
{
    uint8_t temp[4];
    temp[0] = (0xFF000000 & value) >> 24;
    temp[1] = (0x00FF0000 & value) >> 16;
    temp[2] = (0x0000FF00 & value) >> 8;
    temp[3] = (0x000000FF & value);

    //printf("temp[0] = %02X\ntemp[1] = %02X\ntemp[2] = %02X\ntemp[3] = %02X\n\n",
            //temp[0], temp[1], temp[2], temp[3]);
    temp[0] = Encryption_Lookup_Table[(temp[0] & 0xF0) >> 4][temp[0] & 0x0F];
    temp[1] = Encryption_Lookup_Table[(temp[1] & 0xF0) >> 4][temp[1] & 0x0F];
    temp[2] = Encryption_Lookup_Table[(temp[2] & 0xF0) >> 4][temp[2] & 0x0F];
    temp[3] = Encryption_Lookup_Table[(temp[3] & 0xF0) >> 4][temp[3] & 0x0F];

    return (temp[0] << 24) | (temp[1] << 16) | (temp[2] << 8) | temp[3];
}

void SubBytes(uint8_t array[][4])
{
    for(uint8_t i = 0; i < 4; ++i)
    {
        for(uint8_t j = 0; j < 4; ++j)
        {
            array[i][j] = Encryption_Lookup_Table[(array[i][j] & 0xF0) >> 4][array[i][j] & 0x0F];
        }
    }
}

void Inverse_SubBytes(uint8_t array[][4])
{
    for(uint8_t i = 0; i < 4; ++i)
    {
        for(uint8_t j = 0; j < 4; ++j)
        {
            array[i][j] = Decryption_Lookup_Table[(array[i][j] & 0xF0) >> 4][array[i][j] & 0x0F];
        }
    }
}

void ShiftRows(uint8_t array[][4])
{
    uint8_t temp[4];
    
    // Keep the 0th the same
    // Shift the 1st row by 1
    temp[0] = array[0][1];
    temp[1] = array[1][1];
    temp[2] = array[2][1];
    temp[3] = array[3][1];

    array[0][1] = temp[1];
    array[1][1] = temp[2];
    array[2][1] = temp[3];
    array[3][1] = temp[0];

    // Shift the 2nd row by 2
    temp[0] = array[0][2];
    temp[1] = array[1][2];
    temp[2] = array[2][2];
    temp[3] = array[3][2];

    array[0][2] = temp[2];
    array[1][2] = temp[3];
    array[2][2] = temp[0];
    array[3][2] = temp[1];
    
    // Shift the 3nd row by 3
    temp[0] = array[0][3];
    temp[1] = array[1][3];
    temp[2] = array[2][3];
    temp[3] = array[3][3];

    array[0][3] = temp[3];
    array[1][3] = temp[0];
    array[2][3] = temp[1];
    array[3][3] = temp[2];
}

void Inverse_ShiftRows(uint8_t array[][4])
{
    uint8_t temp[4];
    
    // Keep the 0th the same
    // Shift the 1st row by 1
    temp[0] = array[0][1];
    temp[1] = array[1][1];
    temp[2] = array[2][1];
    temp[3] = array[3][1];

    array[0][1] = temp[3];
    array[1][1] = temp[0];
    array[2][1] = temp[1];
    array[3][1] = temp[2];

    // Shift the 2nd row by 2
    temp[0] = array[0][2];
    temp[1] = array[1][2];
    temp[2] = array[2][2];
    temp[3] = array[3][2];

    array[0][2] = temp[2];
    array[1][2] = temp[3];
    array[2][2] = temp[0];
    array[3][2] = temp[1];
    
    // Shift the 3nd row by 3
    temp[0] = array[0][3];
    temp[1] = array[1][3];
    temp[2] = array[2][3];
    temp[3] = array[3][3];

    array[0][3] = temp[1];
    array[1][3] = temp[2];
    array[2][3] = temp[3];
    array[3][3] = temp[0];
}

void Inverse_MixColumns(uint8_t array[][4])
{
    uint8_t temp[4];
    for(uint8_t i = 0; i < 4; ++i)
    {
        temp[0] = GF_Mult(array[i][0], 0x0E) ^ GF_Mult(array[i][1], 0x0B) ^ GF_Mult(array[i][2], 0x0D) ^ GF_Mult(array[i][3], 0x09);
        temp[1] = GF_Mult(array[i][0], 0x09) ^ GF_Mult(array[i][1], 0x0E) ^ GF_Mult(array[i][2], 0x0B) ^ GF_Mult(array[i][3], 0x0D);
        temp[2] = GF_Mult(array[i][0], 0x0D) ^ GF_Mult(array[i][1], 0x09) ^ GF_Mult(array[i][2], 0x0E) ^ GF_Mult(array[i][3], 0x0B);
        temp[3] = GF_Mult(array[i][0], 0x0B) ^ GF_Mult(array[i][1], 0x0D) ^ GF_Mult(array[i][2], 0x09) ^ GF_Mult(array[i][3], 0x0E);

        array[i][0] = temp[0];
        array[i][1] = temp[1];
        array[i][2] = temp[2];
        array[i][3] = temp[3];
    }
}

void MixColumns(uint8_t array[][4])
{
    uint8_t temp[4];
    for(uint8_t i = 0; i < 4; ++i)
    {
        temp[0] = GF_Mult(array[i][0], 2) ^ GF_Mult(array[i][1], 3) ^         array[i][2]     ^         array[i][3];
        temp[1] =         array[i][0]     ^ GF_Mult(array[i][1], 2) ^ GF_Mult(array[i][2], 3) ^         array[i][3];
        temp[2] =         array[i][0]     ^         array[i][1]     ^ GF_Mult(array[i][2], 2) ^ GF_Mult(array[i][3], 3);
        temp[3] = GF_Mult(array[i][0], 3) ^         array[i][1]     ^         array[i][2]     ^ GF_Mult(array[i][3], 2);

        array[i][0] = temp[0];
        array[i][1] = temp[1];
        array[i][2] = temp[2];
        array[i][3] = temp[3];
    }
}

void XorRoundKey(uint8_t array[][4], uint8_t key[][4])
{
    uint8_t temp;
    for(uint8_t i = 0; i < 4; ++i)
    {
        for(uint8_t j = 0; j < 4; ++j)
        {
            array[i][j] = array[i][j] ^ key[i][j];
        }
    }
}

void Inverse_XorRoundKey(uint8_t array[][4], uint8_t key[][4])
{
    uint8_t temp;
    for(uint8_t i = 0; i < 4; ++i)
    {
        for(uint8_t j = 0; j < 4; ++j)
        {
            array[i][j] = array[i][j] ^ key[i][j];
        }
    }
}

uint8_t GF_Mult(uint8_t value1, uint8_t value2)
{
    uint8_t ret = 0;
    while(value2)
    {
        if(value2 & 0x1)
        {
            ret ^= value1;
        }
        if(value1 & 0x80)
        {
            value1 = (value1 << 1) ^ 0x11b;
        }
        else
        {
            value1 <<= 1;
        }
        value2 >>= 1;
    }
    return ret;
}

void print_state(uint8_t array[][4])
{
    for(uint8_t i = 0; i < 4; ++i)
    {
        printf("input[%d] = ", i);
        for(uint8_t j = 0; j < 4; ++j)
        {
            printf("0x%02X ", array[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

void print_key(uint8_t array[][4])
{
    for(uint8_t i = 0; i < 4; ++i)
    {
        printf("key[%d] = ", i);
        for(uint8_t j = 0; j < 4; ++j)
        {
            printf("0x%02X ", array[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}
