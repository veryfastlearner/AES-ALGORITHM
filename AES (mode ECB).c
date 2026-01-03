#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void load_state(char *bits, int bit_state[4][4]) {
    int idx = 0;
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            bit_state[i][j] = (bits[idx] == '1') ? 1 : 0;
            idx++;
        }
    }
}

void extract_state(int bit_state[4][4], char *bits) {
    int idx = 0;
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            bits[idx] = (bit_state[i][j] == 1) ? '1' : '0';
            idx++;
        }
    }
    bits[16] = '\0';
}

void sub_bits(int s[4][4]) {
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            if((i + j) % 2 == 0) {
                s[i][j] = s[i][j] ^ 1;
            }
        }
    }
}

void inv_sub_bits(int s[4][4]) {
    sub_bits(s);
}

void shift_rows(int s[4][4]) {
    int temp = s[1][0];
    s[1][0] = s[1][1];
    s[1][1] = s[1][2];
    s[1][2] = s[1][3];
    s[1][3] = temp;
    
    temp = s[2][0];
    s[2][0] = s[2][2];
    s[2][2] = temp;
    temp = s[2][1];
    s[2][1] = s[2][3];
    s[2][3] = temp;
    
    temp = s[3][3];
    s[3][3] = s[3][2];
    s[3][2] = s[3][1];
    s[3][1] = s[3][0];
    s[3][0] = temp;
}

void inv_shift_rows(int s[4][4]) {
    int temp = s[1][3];
    s[1][3] = s[1][2];
    s[1][2] = s[1][1];
    s[1][1] = s[1][0];
    s[1][0] = temp;
    
    temp = s[2][0];
    s[2][0] = s[2][2];
    s[2][2] = temp;
    temp = s[2][1];
    s[2][1] = s[2][3];
    s[2][3] = temp;
    
    temp = s[3][0];
    s[3][0] = s[3][1];
    s[3][1] = s[3][2];
    s[3][2] = s[3][3];
    s[3][3] = temp;
}

void mix_columns(int s[4][4]) {
    for(int c = 0; c < 4; c++) {
        int a = s[0][c];
        int b = s[1][c];
        int d = s[2][c];
        int e = s[3][c];
        
        s[0][c] = a ^ b ^ d;
        s[1][c] = b ^ d ^ e;
        s[2][c] = a ^ d ^ e;
        s[3][c] = a ^ b ^ e;
    }
}

void inv_mix_columns(int s[4][4]) {
    mix_columns(s);
}

void add_round_key(int s[4][4], int key[4][4]) {
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            s[i][j] = s[i][j] ^ key[i][j];
        }
    }
}

void encrypt(char *plaintext, char *ciphertext, int key[4][4]) {
    int state[4][4];
    
    load_state(plaintext, state);
    add_round_key(state, key);
    
    for(int round = 0; round < 2; round++) {
        sub_bits(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, key);
    }
    
    extract_state(state, ciphertext);
}

void decrypt(char *ciphertext, char *plaintext, int key[4][4]) {
    int state[4][4];
    
    load_state(ciphertext, state);
    add_round_key(state, key);
    
    for(int round = 0; round < 2; round++) {
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bits(state);
        add_round_key(state, key);
    }
    
    extract_state(state, plaintext);
}

void remove_padding(char *data, int original_len) {
    data[original_len] = '\0';
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
        /* ENCRYPTION MODE */
        char bits_input[256];
        char bits_padded[256];
        
        printf("Enter bits to encrypt: ");
        scanf("%255s", bits_input);
        
        int len = strlen(bits_input);
        int pad = (16 - (len % 16)) % 16;
        
        strcpy(bits_padded, bits_input);
        for(int i = 0; i < pad; i++) {
            strcat(bits_padded, "0");
        }
        
        char *encrypted_full = malloc(strlen(bits_padded) + 1);
        encrypted_full[0] = '\0';
        
        for(int i = 0; i < strlen(bits_padded); i += 16) {
            char block[17];
            char block_encrypted[17];
            strncpy(block, bits_padded + i, 16);
            block[16] = '\0';
            encrypt(block, block_encrypted, key);
            strcat(encrypted_full, block_encrypted);
        }
        
        printf("Encrypted: %s\n", encrypted_full);
        free(encrypted_full);
        
    } else if(choice == 2) {
        /* DECRYPTION MODE */
        char encrypted_input[256];
        
        printf("Enter bits to decrypt: ");
        scanf("%255s", encrypted_input);
        
        char *decrypted_full = malloc(strlen(encrypted_input) + 1);
        decrypted_full[0] = '\0';
        
        for(int i = 0; i < strlen(encrypted_input); i += 16) {
            char block[17];
            char block_decrypted[17];
            strncpy(block, encrypted_input + i, 16);
            block[16] = '\0';
            decrypt(block, block_decrypted, key);
            strcat(decrypted_full, block_decrypted);
        }
        
        printf("Decrypted: %s\n", decrypted_full);
        free(decrypted_full);
        
    } else {
        printf("Invalid choice\n");
    }
    
    return 0;
}
