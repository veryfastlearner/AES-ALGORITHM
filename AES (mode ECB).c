#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* Rotation gauche */
uint8_t rotl(uint8_t x, int n) {
    return (x << n) | (x >> (8 - n));
}

uint8_t rotr(uint8_t x, int n) {
    return (x >> n) | (x << (8 - n));
}

/* SubBytes : XOR + rotation */
void sub_bytes(uint8_t s[4][4]) {
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            s[i][j] ^= rotl(s[i][j], 3);
}

/* Inverse SubBytes */
void inv_sub_bytes(uint8_t s[4][4]) {
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            s[i][j] ^= rotr(s[i][j], 3);
}

/* ShiftRows : rotation des lignes */
void shift_rows(uint8_t s[4][4]) {
    uint8_t t;
    
    /* Ligne 1 */
    t = s[1][0];
    s[1][0] = s[1][1];
    s[1][1] = s[1][2];
    s[1][2] = s[1][3];
    s[1][3] = t;
    
    /* Ligne 2 */
    t = s[2][0];
    s[2][0] = s[2][2];
    s[2][2] = t;
    t = s[2][1];
    s[2][1] = s[2][3];
    s[2][3] = t;
    
    /* Ligne 3 */
    t = s[3][3];
    s[3][3] = s[3][2];
    s[3][2] = s[3][1];
    s[3][1] = s[3][0];
    s[3][0] = t;
}

/* Inverse ShiftRows */
void inv_shift_rows(uint8_t s[4][4]) {
    uint8_t t;
    
    /* Ligne 1 inverse */
    t = s[1][3];
    s[1][3] = s[1][2];
    s[1][2] = s[1][1];
    s[1][1] = s[1][0];
    s[1][0] = t;
    
    /* Ligne 2 inverse (même que shift_rows) */
    t = s[2][0];
    s[2][0] = s[2][2];
    s[2][2] = t;
    t = s[2][1];
    s[2][1] = s[2][3];
    s[2][3] = t;
    
    /* Ligne 3 inverse */
    t = s[3][0];
    s[3][0] = s[3][1];
    s[3][1] = s[3][2];
    s[3][2] = s[3][3];
    s[3][3] = t;
}

/* MixColumns : XOR simple */
void mix_columns(uint8_t s[4][4]) {
    for(int c=0; c<4; c++) {
        uint8_t a=s[0][c], b=s[1][c], c1=s[2][c], d=s[3][c];
        s[0][c] = b ^ c1 ^ d;
        s[1][c] = a ^ c1 ^ d;
        s[2][c] = a ^ b ^ d;
        s[3][c] = a ^ b ^ c1;
    }
}

/* Inverse MixColumns (identique car réversible) */
void inv_mix_columns(uint8_t s[4][4]) {
    mix_columns(s);  /* Même fonction car XOR est auto-inverse */
}

/* AddRoundKey : XOR */
void add_key(uint8_t s[4][4], uint8_t k[4][4]) {
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            s[i][j] ^= k[i][j];
}

/* Expansion clé simple */
void expand_key(uint8_t key[4][4], uint8_t rk[11][4][4]) {
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            rk[0][i][j] = key[i][j];
    
    for(int r=1; r<11; r++) {
        uint8_t t[4] = {rk[r-1][0][3], rk[r-1][1][3], rk[r-1][2][3], rk[r-1][3][3]};
        uint8_t tmp = t[0];
        t[0]=t[1]; t[1]=t[2]; t[2]=t[3]; t[3]=tmp;
        t[0] ^= r;
        
        for(int i=0; i<4; i++) rk[r][i][0] = rk[r-1][i][0] ^ t[i];
        for(int j=1; j<4; j++)
            for(int i=0; i<4; i++)
                rk[r][i][j] = rk[r-1][i][j] ^ rk[r][i][j-1];
    }
}

/* Chiffrement */
void encrypt(uint8_t in[16], uint8_t out[16], uint8_t rk[11][4][4]) {
    uint8_t s[4][4];
    
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            s[j][i] = in[i*4+j];
    
    add_key(s, rk[0]);
    
    for(int r=1; r<10; r++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_key(s, rk[r]);
    }
    
    sub_bytes(s);
    shift_rows(s);
    add_key(s, rk[10]);
    
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            out[i*4+j] = s[j][i];
}

/* Déchiffrement */
void decrypt(uint8_t in[16], uint8_t out[16], uint8_t rk[11][4][4]) {
    uint8_t s[4][4];
    
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            s[j][i] = in[i*4+j];
    
    add_key(s, rk[10]);
    inv_shift_rows(s);
    inv_sub_bytes(s);
    
    for(int r=9; r>=1; r--) {
        add_key(s, rk[r]);
        inv_mix_columns(s);
        inv_shift_rows(s);
        inv_sub_bytes(s);
    }
    
    add_key(s, rk[0]);
    
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            out[i*4+j] = s[j][i];
}

/* Binaire vers octets */
void bin_to_bytes(char *bin, uint8_t *bytes, int *len) {
    *len = strlen(bin)/8;
    for(int i=0; i<*len; i++) {
        bytes[i]=0;
        for(int j=0; j<8; j++)
            if(bin[i*8+j]=='1')
                bytes[i] |= (1<<(7-j));
    }
}

/* Main */
int main() {
    char bin[256];
    uint8_t data[256], enc[256], dec[256];
    int len;
    
    uint8_t key[4][4] = {
        {1,2,3,4}, {5,6,7,8}, {9,10,11,12}, {13,14,15,16}
    };
    uint8_t rk[11][4][4];
    
    printf("Entrez bits: ");
    scanf("%s", bin);
    
    bin_to_bytes(bin, data, &len);
    
    /* Padding simple */
    int pad = 16 - (len%16);
    for(int i=len; i<len+pad; i++) data[i]=pad;
    len += pad;
    
    expand_key(key, rk);
    
    /* Chiffrer */
    for(int i=0; i<len; i+=16)
        encrypt(data+i, enc+i, rk);
    
    printf("Chiffre: ");
    for(int i=0; i<len; i++) {
        for(int j=7; j>=0; j--)
            printf("%d", (enc[i]>>j)&1);
        printf(" ");
    }
    printf("\n");
    
    /* Déchiffrer */
    for(int i=0; i<len; i+=16)
        decrypt(enc+i, dec+i, rk);
    
    /* Enlever padding */
    len -= dec[len-1];
    
    printf("Dechiffre: ");
    for(int i=0; i<len; i++) {
        for(int j=7; j>=0; j--)
            printf("%d", (dec[i]>>j)&1);
    }
    printf("\n");
    
    return 0;
}
