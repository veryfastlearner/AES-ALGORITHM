#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void load_state(char *bits, int bit_state[4][4]) {
    int idx = 0;
    int i, j;
    
    /* Initialize all to 0 first */
    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            bit_state[i][j] = 0;
        }
    }
    
    /* Load bits from input */
    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            if(bits[idx] != '\0') {
                if(bits[idx] == '1') {
                    bit_state[i][j] = 1;
                } else {
                    bit_state[i][j] = 0;
                }
                idx += 1;
            }
        }
    }
}

void extract_state(int bit_state[4][4], char *bits) {
    int idx = 0;
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            if(bit_state[i][j] == 1) {
                bits[idx] = '1';
            } else {
                bits[idx] = '0';
            }
            idx = idx + 1;
        }
    }
    bits[16] = '\0';
}

void sub_bits(int s[4][4]) {
    int i, j;
    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            if((i + j) % 2 == 0) {
                s[i][j] ^= 1;
            }
        }
    }
}

void shift_rows(int s[4][4]) {
    int temp;
    
    temp = s[1][0];
    s[1][0] = s[1][3];
    s[1][3] = temp;
    
    temp = s[1][1];
    s[1][1] = s[1][2];
    s[1][2] = temp;
    
    temp = s[2][0];
    s[2][0] = s[2][3];
    s[2][3] = temp;
    
    temp = s[2][1];
    s[2][1] = s[2][2];
    s[2][2] = temp;
    
    temp = s[3][0];
    s[3][0] = s[3][3];
    s[3][3] = temp;
    
    temp = s[3][1];
    s[3][1] = s[3][2];
    s[3][2] = temp;
}

void mix_columns(int s[4][4]) {
    int c, t;
    for(c = 0; c < 4; c++) {
        t = s[0][c] ^ s[1][c] ^ s[2][c] ^ s[3][c];
        s[0][c] = s[0][c] ^ t;
        s[1][c] = s[1][c] ^ t;
        s[2][c] = s[2][c] ^ t;
        s[3][c] = s[3][c] ^ t;
    }
}

void add_round_key(int s[4][4], int key[4][4]) {
    int i, j;
    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            s[i][j] = s[i][j] ^ key[i][j];
        }
    }
}

void encrypt(char *plaintext, char *ciphertext, int key[4][4]) {
    int state[4][4];
    int round;
    
    load_state(plaintext, state);
    add_round_key(state, key);
    
    for(round = 0; round < 10; round++) {
        sub_bits(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, key);
    }
    
    extract_state(state, ciphertext);
}

void decrypt(char *ciphertext, char *plaintext, int key[4][4]) {
    int state[4][4];
    int round;
    
    load_state(ciphertext, state);
    add_round_key(state, key);
    
    for(round = 0; round < 10; round++) {
        mix_columns(state);
        shift_rows(state);
        sub_bits(state);
        add_round_key(state, key);
    }
    
    extract_state(state, plaintext);
}

int main() {
    int key[4][4] = {
        {1, 0, 1, 0},
        {0, 1, 0, 1},
        {1, 0, 1, 0},
        {0, 1, 0, 1}
    };
    
    int choice;
    printf("1. Encrypt\n2. Decrypt\nChoose: ");
    scanf("%d", &choice);
    
    if(choice == 1) {
        char bits_input[256];
        char bits_padded[256];
        char *encrypted_full;
        int original_len, pad, i;
        char block[17];
        char block_encrypted[17];
        
        printf("Enter bits: ");
        scanf("%255s", bits_input);
        
        original_len = strlen(bits_input);
        strcpy(bits_padded, bits_input);
        
        pad = (16 - (original_len % 16)) % 16;
        if(pad == 0) {
            pad = 16;
        }
        
        for(i = 0; i < pad; i++) {
            strcat(bits_padded, "0");
        }
        
        encrypted_full = malloc(strlen(bits_padded) + 1);
        encrypted_full[0] = '\0';
        
        for(i = 0; i < strlen(bits_padded); i += 16) {
            strncpy(block, bits_padded + i, 16);
            block[16] = '\0';
            encrypt(block, block_encrypted, key);
            strcat(encrypted_full, block_encrypted);
        }
        
        printf("Ciphertext: %s\n", encrypted_full);
        printf("Original length: %d\n", original_len);
        
        free(encrypted_full);
        
    } else if(choice == 2) {
        char encrypted_input[256];
        int original_length;
        char *decrypted_full;
        int i;
        char block[17];
        char block_decrypted[17];
        
        printf("Enter ciphertext: ");
        scanf("%255s", encrypted_input);
        printf("Enter original length: ");
        scanf("%d", &original_length);
        
        decrypted_full = malloc(strlen(encrypted_input) + 1);
        decrypted_full[0] = '\0';
        
        for(i = 0; i < strlen(encrypted_input); i += 16) {
            strncpy(block, encrypted_input + i, 16);
            block[16] = '\0';
            decrypt(block, block_decrypted, key);
            strcat(decrypted_full, block_decrypted);
        }
        
        decrypted_full[original_length] = '\0';
        printf("Plaintext: %s\n", decrypted_full);
        
        free(decrypted_full);
    }
    
    return 0;
}
