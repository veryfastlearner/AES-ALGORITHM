#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* AES-128 Constants */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* Helper functions */
void SubBytes(uint8_t state[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = sbox[state[i][j]];
}

void InvSubBytes(uint8_t state[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = rsbox[state[i][j]];
}

void ShiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    /* Row 1 */
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    /* Row 2 */
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    /* Row 3 */
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

void InvShiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    /* Row 1 */
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    /* Row 2 */
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    /* Row 3 */
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    int i;
    for (i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void MixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];
    int i, j;
    for (i = 0; i < 4; i++) {
        temp[0] = gmul(state[0][i], 2) ^ gmul(state[1][i], 3) ^ state[2][i] ^ state[3][i];
        temp[1] = state[0][i] ^ gmul(state[1][i], 2) ^ gmul(state[2][i], 3) ^ state[3][i];
        temp[2] = state[0][i] ^ state[1][i] ^ gmul(state[2][i], 2) ^ gmul(state[3][i], 3);
        temp[3] = gmul(state[0][i], 3) ^ state[1][i] ^ state[2][i] ^ gmul(state[3][i], 2);
        for (j = 0; j < 4; j++) state[j][i] = temp[j];
    }
}

void InvMixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];
    int i, j;
    for (i = 0; i < 4; i++) {
        temp[0] = gmul(state[0][i], 0x0e) ^ gmul(state[1][i], 0x0b) ^ gmul(state[2][i], 0x0d) ^ gmul(state[3][i], 0x09);
        temp[1] = gmul(state[0][i], 0x09) ^ gmul(state[1][i], 0x0e) ^ gmul(state[2][i], 0x0b) ^ gmul(state[3][i], 0x0d);
        temp[2] = gmul(state[0][i], 0x0d) ^ gmul(state[1][i], 0x09) ^ gmul(state[2][i], 0x0e) ^ gmul(state[3][i], 0x0b);
        temp[3] = gmul(state[0][i], 0x0b) ^ gmul(state[1][i], 0x0d) ^ gmul(state[2][i], 0x09) ^ gmul(state[3][i], 0x0e);
        for (j = 0; j < 4; j++) state[j][i] = temp[j];
    }
}

void AddRoundKey(uint8_t state[4][4], uint8_t roundKey[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] ^= roundKey[i][j];
}

void KeyExpansion(const uint8_t key[16], uint8_t roundKeys[11][4][4]) {
    uint8_t temp[4];
    int i, j, k;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            roundKeys[0][j][i] = key[i * 4 + j];
        }
    }

    for (i = 1; i < 11; i++) {
        for (j = 0; j < 4; j++) temp[j] = roundKeys[i - 1][j][3];
        
        /* RotWord */
        {
            uint8_t rot = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = rot;
        }

        /* SubWord */
        for (j = 0; j < 4; j++) temp[j] = sbox[temp[j]];

        /* XOR with Rcon */
        temp[0] ^= rcon[i];

        for (j = 0; j < 4; j++) roundKeys[i][j][0] = roundKeys[i - 1][j][0] ^ temp[j];
        for (j = 1; j < 4; j++) {
            for (k = 0; k < 4; k++) {
                roundKeys[i][k][j] = roundKeys[i - 1][k][j] ^ roundKeys[i][k][j - 1];
            }
        }
    }
}

void Cipher(uint8_t in[16], uint8_t out[16], uint8_t roundKeys[11][4][4]) {
    uint8_t state[4][4];
    int i, j, round;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[j][i] = in[i * 4 + j];

    AddRoundKey(state, roundKeys[0]);

    for (round = 1; round < 10; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys[round]);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys[10]);

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            out[i * 4 + j] = state[j][i];
}

void InvCipher(uint8_t in[16], uint8_t out[16], uint8_t roundKeys[11][4][4]) {
    uint8_t state[4][4];
    int i, j, round;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[j][i] = in[i * 4 + j];

    AddRoundKey(state, roundKeys[10]);

    for (round = 9; round >= 1; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys[round]);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys[0]);

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            out[i * 4 + j] = state[j][i];
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void print_binary(const char *label, const uint8_t *data, size_t len) {
    size_t i;
    int j;
    printf("%s: ", label);
    for (i = 0; i < len; i++) {
        for (j = 7; j >= 0; j--) {
            printf("%d", (data[i] >> j) & 1);
        }
        printf(" ");
    }
    printf("\n");
}

uint8_t hex_char_to_byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len) {
    size_t len = strlen(hex);
    size_t i;
    if (len % 2 != 0) return -1;
    for (i = 0; i < len / 2 && i < max_len; i++) {
        bytes[i] = (hex_char_to_byte(hex[2 * i]) << 4) | hex_char_to_byte(hex[2 * i + 1]);
    }
    return (int)(len / 2);
}

int binary_to_bytes(const char *binary, uint8_t *bytes, size_t max_len) {
    size_t len = strlen(binary);
    size_t i, j;
    if (len % 8 != 0) return -1;
    for (i = 0; i < len / 8 && i < max_len; i++) {
        uint8_t byte = 0;
        for (j = 0; j < 8; j++) {
            if (binary[i * 8 + j] == '1') {
                byte |= (1 << (7 - j));
            } else if (binary[i * 8 + j] != '0') {
                return -1; /* Invalid character */
            }
        }
        bytes[i] = byte;
    }
    return (int)(len / 8);
}

int main() {
    char input_str[1024];
    uint8_t key[16];
    uint8_t *raw_input = NULL;
    size_t input_len = 0, padded_len = 0, i;
    uint8_t *padded_input, *encrypted, *decrypted;
    uint8_t padding_val, unpadding_val;
    size_t original_len;
    uint8_t roundKeys[11][4][4];
    int choice;

    /* Default key */
    memcpy(key, "thisisasecretkey", 16);

    printf("AES-128 ECB Implementation\n");
    printf("1. Input as String\n");
    printf("2. Input as Hex Bytes\n");
    printf("3. Input as Binary String (e.g., 01001000...)\n");
    printf("Choice: ");
    if (scanf("%d", &choice) != 1) return 1;
    getchar(); /* consume newline */

    if (choice == 1) {
        printf("Enter text: ");
        if (fgets(input_str, sizeof(input_str), stdin) == NULL) return 1;
        input_str[strcspn(input_str, "\n")] = 0;
        input_len = strlen(input_str);
        raw_input = (uint8_t *)malloc(input_len);
        memcpy(raw_input, input_str, input_len);
    } else if (choice == 2) {
        printf("Enter hex bytes (e.g., 48656C6C6F): ");
        if (fgets(input_str, sizeof(input_str), stdin) == NULL) return 1;
        input_str[strcspn(input_str, "\n")] = 0;
        input_len = strlen(input_str) / 2;
        raw_input = (uint8_t *)malloc(input_len);
        if (hex_to_bytes(input_str, raw_input, input_len) == -1) {
            printf("Invalid hex input\n");
            free(raw_input);
            return 1;
        }
    } else if (choice == 3) {
        printf("Enter binary string (multiples of 8 bits): ");
        if (fgets(input_str, sizeof(input_str), stdin) == NULL) return 1;
        input_str[strcspn(input_str, "\n")] = 0;
        input_len = strlen(input_str) / 8;
        raw_input = (uint8_t *)malloc(input_len);
        if (binary_to_bytes(input_str, raw_input, input_len) == -1) {
            printf("Invalid binary input (must be '0'/'1' and length multiple of 8)\n");
            free(raw_input);
            return 1;
        }
    } else {
        printf("Invalid choice\n");
        return 1;
    }

    padded_len = ((input_len / 16) + 1) * 16;
    padded_input = (uint8_t *)calloc(padded_len, 1);
    memcpy(padded_input, raw_input, input_len);

    /* PKCS#7 Padding */
    padding_val = (uint8_t)(padded_len - input_len);
    for (i = input_len; i < padded_len; i++) {
        padded_input[i] = padding_val;
    }

    KeyExpansion(key, roundKeys);

    encrypted = (uint8_t *)malloc(padded_len);
    for (i = 0; i < padded_len; i += 16) {
        Cipher(padded_input + i, encrypted + i, roundKeys);
    }

    printf("\n--- Results ---\n");
    print_binary("Original Binary", raw_input, input_len);
    print_hex("Encrypted (Hex)", encrypted, padded_len);
    print_binary("Encrypted (Binary)", encrypted, padded_len);

    decrypted = (uint8_t *)malloc(padded_len);
    for (i = 0; i < padded_len; i += 16) {
        InvCipher(encrypted + i, decrypted + i, roundKeys);
    }

    /* Remove Padding */
    unpadding_val = decrypted[padded_len - 1];
    original_len = padded_len - unpadding_val;
    
    print_binary("Decrypted Binary", decrypted, original_len);
    if (choice == 1) {
        decrypted[original_len] = '\0';
        printf("Decrypted String: %s\n", (char *)decrypted);
    }

    free(raw_input);
    free(padded_input);
    free(encrypted);
    free(decrypted);

    return 0;
}

