/*******************************************************************************
 * SIMPLE-BLOCK-CIPHER - Chiffrement par bloc simplifié inspiré d'AES
 * 
 * Caractéristiques:
 * - Bloc de 128 bits (16 octets)
 * - Clé de 128 bits (16 octets)
 * - 10 tours de transformation
 * - Opérations simples: XOR, rotation, addition
 * - Structure matricielle 4x4 comme AES
 * 
 * Usage éducatif seulement - PAS pour la sécurité réelle
 ******************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/*******************************************************************************
 * FONCTIONS DE BASE - Opérations mathématiques simples
 ******************************************************************************/

/**
 * Rotation à gauche de bits
 * @param x L'octet à faire tourner
 * @param n Nombre de positions à tourner (1-7)
 * @return L'octet tourné
 */
uint8_t rotate_left(uint8_t x, int n) {
    return (x << n) | (x >> (8 - n));
}

/**
 * Rotation à droite de bits
 * @param x L'octet à faire tourner
 * @param n Nombre de positions à tourner (1-7)
 * @return L'octet tourné
 */
uint8_t rotate_right(uint8_t x, int n) {
    return (x >> n) | (x << (8 - n));
}

/*******************************************************************************
 * TRANSFORMATIONS DU BLOC - Opérations sur l'état 4x4
 ******************************************************************************/

/**
 * Substitution des octets (remplace S-box d'AES)
 * Applique une transformation simple à chaque octet du bloc
 * @param state Matrice 4x4 représentant l'état courant
 */
void substitute_bytes(uint8_t state[4][4]) {
    int row, col;
    for(row = 0; row < 4; row++) {
        for(col = 0; col < 4; col++) {
            /* Transformation simple: XOR avec rotation */
            state[row][col] ^= rotate_left(state[row][col], 3);
        }
    }
}

/**
 * Substitution inverse (pour le déchiffrement)
 * Annule la transformation de substitute_bytes
 * @param state Matrice 4x4 représentant l'état courant
 */
void inverse_substitute_bytes(uint8_t state[4][4]) {
    int row, col;
    for(row = 0; row < 4; row++) {
        for(col = 0; col < 4; col++) {
            /* Transformation inverse: XOR avec rotation inverse */
            state[row][col] ^= rotate_right(state[row][col], 3);
        }
    }
}

/**
 * Décalage des lignes (similaire à ShiftRows d'AES)
 * Décale chaque ligne de la matrice d'un nombre différent de positions
 * @param state Matrice 4x4 représentant l'état courant
 */
void shift_rows(uint8_t state[4][4]) {
    uint8_t temp_value;
    
    /* Ligne 1: décalage de 1 position vers la gauche */
    temp_value = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp_value;
    
    /* Ligne 2: décalage de 2 positions (échanges simples) */
    temp_value = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp_value;
    
    temp_value = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp_value;
    
    /* Ligne 3: décalage de 3 positions (1 vers la droite) */
    temp_value = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp_value;
}

/**
 * Décalage inverse des lignes (pour déchiffrement)
 * Annule le décalage effectué par shift_rows
 * @param state Matrice 4x4 représentant l'état courant
 */
void inverse_shift_rows(uint8_t state[4][4]) {
    uint8_t temp_value;
    
    /* Ligne 1 inverse: décalage de 1 position vers la droite */
    temp_value = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp_value;
    
    /* Ligne 2 inverse: même opération que shift_rows (auto-inverse) */
    temp_value = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp_value;
    
    temp_value = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp_value;
    
    /* Ligne 3 inverse: décalage de 3 positions vers la gauche */
    temp_value = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp_value;
}

/**
 * Mélange des colonnes (similaire à MixColumns d'AES)
 * Mélange les octets de chaque colonne avec des opérations XOR
 * @param state Matrice 4x4 représentant l'état courant
 */
void mix_columns(uint8_t state[4][4]) {
    int column;
    for(column = 0; column < 4; column++) {
        /* Extraire les 4 octets de la colonne */
        uint8_t byte1 = state[0][column];
        uint8_t byte2 = state[1][column];
        uint8_t byte3 = state[2][column];
        uint8_t byte4 = state[3][column];
        
        /* Mélange simple avec XOR */
        state[0][column] = byte2 ^ byte3 ^ byte4;
        state[1][column] = byte1 ^ byte3 ^ byte4;
        state[2][column] = byte1 ^ byte2 ^ byte4;
        state[3][column] = byte1 ^ byte2 ^ byte3;
    }
}

/**
 * Ajout de clé de tour (AddRoundKey)
 * Combine l'état avec la clé de tour par XOR
 * @param state Matrice 4x4 représentant l'état courant
 * @param round_key Clé de tour (matrice 4x4)
 */
void add_round_key(uint8_t state[4][4], uint8_t round_key[4][4]) {
    int row, col;
    for(row = 0; row < 4; row++) {
        for(col = 0; col < 4; col++) {
            state[row][col] ^= round_key[row][col];
        }
    }
}

/*******************************************************************************
 * GESTION DES CLÉS - Génération des clés de tour
 ******************************************************************************/

/**
 * Expansion de la clé principale en clés de tour
 * Génère 11 clés de tour à partir de la clé principale
 * @param main_key Clé principale (matrice 4x4)
 * @param round_keys Tableau pour stocker les 11 clés de tour
 */
void expand_key(uint8_t main_key[4][4], uint8_t round_keys[11][4][4]) {
    int round, row, column;
    
    /* La clé du tour 0 est la clé principale */
    for(row = 0; row < 4; row++) {
        for(column = 0; column < 4; column++) {
            round_keys[0][row][column] = main_key[row][column];
        }
    }
    
    /* Générer les clés pour les tours 1 à 10 */
    for(round = 1; round < 11; round++) {
        uint8_t temp_column[4];
        
        /* Récupérer la dernière colonne de la clé précédente */
        temp_column[0] = round_keys[round-1][0][3];
        temp_column[1] = round_keys[round-1][1][3];
        temp_column[2] = round_keys[round-1][2][3];
        temp_column[3] = round_keys[round-1][3][3];
        
        /* Rotation de la colonne vers le haut */
        uint8_t first_value = temp_column[0];
        temp_column[0] = temp_column[1];
        temp_column[1] = temp_column[2];
        temp_column[2] = temp_column[3];
        temp_column[3] = first_value;
        
        /* Ajouter la constante de tour */
        temp_column[0] ^= round;
        
        /* Générer la première colonne de la nouvelle clé */
        for(row = 0; row < 4; row++) {
            round_keys[round][row][0] = round_keys[round-1][row][0] ^ temp_column[row];
        }
        
        /* Générer les colonnes restantes */
        for(column = 1; column < 4; column++) {
            for(row = 0; row < 4; row++) {
                round_keys[round][row][column] = 
                    round_keys[round-1][row][column] ^ round_keys[round][row][column-1];
            }
        }
    }
}

/*******************************************************************************
 * CHIFFREMENT PRINCIPAL
 ******************************************************************************/

/**
 * Chiffre un bloc de 128 bits (16 octets)
 * @param plaintext Bloc en clair à chiffrer
 * @param ciphertext Bloc chiffré en sortie
 * @param round_keys Clés de tour générées par expand_key
 */
void encrypt_block(uint8_t plaintext[16], uint8_t ciphertext[16], 
                   uint8_t round_keys[11][4][4]) {
    uint8_t current_state[4][4];
    int row, column, round;
    
    /* Convertir le bloc linéaire en matrice 4x4 (colonne par colonne) */
    for(column = 0; column < 4; column++) {
        for(row = 0; row < 4; row++) {
            current_state[row][column] = plaintext[column * 4 + row];
        }
    }
    
    /* Tour initial - seulement ajout de clé */
    add_round_key(current_state, round_keys[0]);
    
    /* 9 tours principaux */
    for(round = 1; round < 10; round++) {
        substitute_bytes(current_state);
        shift_rows(current_state);
        mix_columns(current_state);
        add_round_key(current_state, round_keys[round]);
    }
    
    /* Tour final (sans mix_columns) */
    substitute_bytes(current_state);
    shift_rows(current_state);
    add_round_key(current_state, round_keys[10]);
    
    /* Convertir la matrice en bloc linéaire */
    for(column = 0; column < 4; column++) {
        for(row = 0; row < 4; row++) {
            ciphertext[column * 4 + row] = current_state[row][column];
        }
    }
}

/**
 * Déchiffre un bloc de 128 bits (16 octets)
 * @param ciphertext Bloc chiffré à déchiffrer
 * @param plaintext Bloc en clair en sortie
 * @param round_keys Clés de tour générées par expand_key
 */
void decrypt_block(uint8_t ciphertext[16], uint8_t plaintext[16],
                   uint8_t round_keys[11][4][4]) {
    uint8_t current_state[4][4];
    int row, column, round;
    
    /* Convertir le bloc linéaire en matrice 4x4 */
    for(column = 0; column < 4; column++) {
        for(row = 0; row < 4; row++) {
            current_state[row][column] = ciphertext[column * 4 + row];
        }
    }
    
    /* Tour initial inverse */
    add_round_key(current_state, round_keys[10]);
    inverse_shift_rows(current_state);
    inverse_substitute_bytes(current_state);
    
    /* 9 tours principaux inverses */
    for(round = 9; round >= 1; round--) {
        add_round_key(current_state, round_keys[round]);
        mix_columns(current_state);  /* Même fonction que pour le chiffrement */
        inverse_shift_rows(current_state);
        inverse_substitute_bytes(current_state);
    }
    
    /* Dernier tour */
    add_round_key(current_state, round_keys[0]);
    
    /* Convertir la matrice en bloc linéaire */
    for(column = 0; column < 4; column++) {
        for(row = 0; row < 4; row++) {
            plaintext[column * 4 + row] = current_state[row][column];
        }
    }
}

/*******************************************************************************
 * UTILITAIRES - Conversion et affichage
 ******************************************************************************/

/**
 * Convertit une chaîne binaire en tableau d'octets
 * @param binary_string Chaîne de caractères '0' et '1'
 * @param byte_array Tableau pour stocker les octets convertis
 * @param byte_count Nombre d'octets générés
 * @return 1 en cas de succès, 0 en cas d'erreur
 */
int convert_binary_to_bytes(const char *binary_string, 
                           uint8_t *byte_array, 
                           int *byte_count) {
    int binary_length = strlen(binary_string);
    int i, j;
    
    /* Vérifier que la longueur est multiple de 8 */
    if(binary_length % 8 != 0) {
        printf("Erreur: La chaîne binaire doit avoir une longueur multiple de 8 bits.\n");
        return 0;
    }
    
    *byte_count = binary_length / 8;
    
    /* Convertir chaque groupe de 8 bits en un octet */
    for(i = 0; i < *byte_count; i++) {
        byte_array[i] = 0;
        for(j = 0; j < 8; j++) {
            char current_bit = binary_string[i * 8 + j];
            if(current_bit == '1') {
                byte_array[i] |= (1 << (7 - j));
            }
            else if(current_bit != '0') {
                printf("Erreur: Caractère invalide '%c' dans la chaîne binaire.\n", 
                       current_bit);
                return 0;
            }
        }
    }
    
    return 1;
}

/**
 * Affiche un tableau d'octets en format binaire
 * @param label Étiquette à afficher avant les données
 * @param data Tableau d'octets à afficher
 * @param length Nombre d'octets à afficher
 */
void display_binary(const char *label, const uint8_t *data, int length) {
    int i, j;
    printf("%s (%d bits): ", label, length * 8);
    for(i = 0; i < length; i++) {
        for(j = 7; j >= 0; j--) {
            printf("%d", (data[i] >> j) & 1);
        }
        if(i < length - 1) {
            printf(" ");
        }
    }
    printf("\n");
}

/* PROGRAMME PRINCIPAL*/

int main() {
    char user_input[256];
    uint8_t plaintext_data[256];
    uint8_t ciphertext_data[256];
    uint8_t decrypted_data[256];
    int data_length;
    int i;
    
    /* Clé de chiffrement fixe (16 octets = 128 bits) */
    uint8_t encryption_key[4][4] = {
        {0x01, 0x02, 0x03, 0x04},  /* Première ligne */
        {0x05, 0x06, 0x07, 0x08},  /* Deuxième ligne */
        {0x09, 0x0A, 0x0B, 0x0C},  /* Troisième ligne */
        {0x0D, 0x0E, 0x0F, 0x10}   /* Quatrième ligne */
    };
    
    /* Clés de tour pour les 10 tours + tour initial */
    uint8_t all_round_keys[11][4][4];
    
    printf("=== CHIFFREMENT PAR BLOC SIMPLIFIE ===\n\n");
    printf("Entrez les donnees binaires (ex: 0100100001100101 pour 'He'): ");
    
    if(scanf("%255s", user_input) != 1) {
        printf("Erreur de lecture de l'entree.\n");
        return 1;
    }
    
    /* Conversion de la chaîne binaire en octets */
    if(!convert_binary_to_bytes(user_input, plaintext_data, &data_length)) {
        return 1;
    }
    
    printf("\n--- Etape 1: Donnees originales ---\n");
    display_binary("Texte clair", plaintext_data, data_length);
    
    /* Padding pour que la longueur soit multiple de 16 octets */
    int padding_needed = 16 - (data_length % 16);
    if(padding_needed == 0) padding_needed = 16;
    
    /* Ajouter le padding (méthode PKCS#7 simple) */
    for(i = data_length; i < data_length + padding_needed; i++) {
        plaintext_data[i] = (uint8_t)padding_needed;
    }
    int padded_length = data_length + padding_needed;
    
    printf("\n--- Etape 2: Preparation ---\n");
    display_binary("Avec padding", plaintext_data, padded_length);
    printf("Padding ajoute: %d octets\n", padding_needed);
    
    /* Génération des clés de tour */
    expand_key(encryption_key, all_round_keys);
    
    /* Chiffrement de tous les blocs */
    for(i = 0; i < padded_length; i += 16) {
        encrypt_block(plaintext_data + i, ciphertext_data + i, all_round_keys);
    }
    
    printf("\n--- Etape 3: Chiffrement ---\n");
    display_binary("Texte chiffre", ciphertext_data, padded_length);
    
    /* Déchiffrement de tous les blocs */
    for(i = 0; i < padded_length; i += 16) {
        decrypt_block(ciphertext_data + i, decrypted_data + i, all_round_keys);
    }
    
    printf("\n--- Etape 4: Dechiffrement ---\n");
    display_binary("Avant suppression padding", decrypted_data, padded_length);
    
    /* Suppression du padding */
    int final_length = padded_length - decrypted_data[padded_length - 1];
    
    /* Vérification de la validité du padding */
    if(final_length < 0 || final_length > padded_length) {
        printf("Erreur: Padding invalide detecte.\n");
        return 1;
    }
    
    printf("\n--- Etape 5: Resultat final ---\n");
    printf("Texte dechiffre (%d bits): ", final_length * 8);
    for(i = 0; i < final_length; i++) {
        for(int j = 7; j >= 0; j--) {
            printf("%d", (decrypted_data[i] >> j) & 1);
        }
    }
    printf("\n");
    
    /* Vérification que le déchiffrement est correct */
    int decryption_correct = 1;
    for(i = 0; i < final_length; i++) {
        if(plaintext_data[i] != decrypted_data[i]) {
            decryption_correct = 0;
            break;
        }
    }
    
    if(decryption_correct) {
        printf("\nSUCCES: Le dechiffrement a produit les donnees originales.\n");
    }
    else {
        printf("\nERREUR: Le dechiffrement a produit un resultat incorrect.\n");
    }
    
    return 0;
}
