/* Explain how you generate cryptographic keys:
I am getting password with 10 characters. Using EVP_BytesToKey with 
Cipher type: AES 256 CBC
Salt: fixed one
digest: md5
count: 10 iterations to slow brute force attack
to create IV and key from entered pass.
D_i = HASH^count(D_(i-1) || data || salt) according to https://www.openssl.org/docs/man1.0.2/crypto/EVP_BytesToKey.html

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>

#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER_UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEW -4

/* Key size */
#define AES_256_KEY_SIZE 32
/* IV size */
#define AES_BLOCK_SIZE 16
#define BUFSIZE 1024

/* Keeping all cryptographic fields in a struct */
typedef struct _cipher_params_t {
    unsigned char *key;
    unsigned char *iv;
	const unsigned char *salt;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
} cipher_params_t;

char *output_file = NULL;
/* In case of emergency, dealloc memory, close the files and exit */
void cleanup(cipher_params_t *params, FILE *ifp, FILE *ofp, int rc) {
	FILE *f_out;
    free(params);
    fclose(ifp);
    fclose(ofp);
	/* Clear the contents of output file */
	f_out = fopen(output_file, "wb");
    if (!f_out) {
        /* Unable to open file for writing */
        printf("ERROR:cleanup fopen error: %s\n", strerror(errno));
    }
	fclose(f_out);
    exit(rc);
}
/* Encryption/decryption handler
 * Inspired by int do_crypt(FILE *in, FILE *out, int do_encrypt) example in
 * https://www.openssl.org/docs/man1.0.2/crypto/EVP_CipherFinal_ex.html
 */
void do_file_encrypt_decrypt(cipher_params_t *params, FILE *ifp, FILE *ofp){
    /* Allow enough space in output buffer for additional block */
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type); /* Get block size of chosen cipher type */
	/* According to open ssl wiki:
	 * The amount of data written depends on the block alignment of the encrypted data: 
	 * as a result the amount of data written may be anything from zero bytes to 
	 * (inl + cipher_block_size - 1) so out should contain sufficient room.*/
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];
    int inl = 0, out_len;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        printf("ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n", 
                ERR_error_string(ERR_get_error(), NULL));
        cleanup(params, ifp, ofp, ERR_EVP_CTX_NEW);
    }

    /* Check the lengths of key and IV before setting */
    if(!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)){
        printf("ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", 
                ERR_error_string(ERR_get_error(), NULL));
        cleanup(params, ifp, ofp, ERR_EVP_CIPHER_INIT);
    }

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);

    /* Now we can set key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)){
        fprintf(stderr,"ERROR: EVP_CipherInit_ex failed. Maybe your password is wrong. OpenSSL error: %s\n", 
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp, ERR_EVP_CIPHER_INIT);
    }

	/* Infinite loop reading and ciphering until the end of file is reached */
	for(;;){
        inl = fread(in_buf, sizeof(unsigned char), BUFSIZE, ifp);
        if (ferror(ifp)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp, errno);
        }
		//printf("Ciphering... inl : %d\n", inl);
        if (inl <= 0) {
            //printf("EOF\n");
            break;
        }
		
        if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, inl)){
            fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", 
                    ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp, ERR_EVP_CIPHER_UPDATE);
        }
        fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
        if (ferror(ofp)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp, errno);
        }
	}
    /* cipher/decipher the final block and write it to file */
    if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)){
        fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. Maybe cipher text is modified. OpenSSL error: %s\n", 
                ERR_error_string(ERR_get_error(), NULL));
		printf("Something is wrong!!!! Regarding openssl errors, it may be because of: \n");
		printf("bad decrypt: invalid password!\n");
		printf("wrong final block length: modified cipher!\n");
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp, ERR_EVP_CIPHER_FINAL);
    }
    fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
    if (ferror(ofp)) {
        printf("ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp, errno);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
}

int main(int argc, char *argv[]) {
    FILE *f_input, *f_enc, *f_dec;
    char password[10];
	/*
    printf("You have entered %d arguments:\n", argc); 
    for (int i = 0; i < argc; ++i) 
        printf(" __%s__ \n", argv[i]); 
	*/
    /* Make sure user provides the input file */
    if (argc != 4) {
        printf("Usage: %s -enc/dec /path/to/file cipher/plaintext not 4\n", argv[0]);
        return -1;
    }

    cipher_params_t *params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
    if (!params) {
        /* Unable to allocate memory on heap*/
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return errno;
    }
	
    OpenSSL_add_all_algorithms();
	
	/* Get the pass from user by hiding stdin, with 10 characters limit to prevent stack smashing */
	printf("Enter the password <any 10 characters>: \n");
    struct termios oldtc, newtc;
	tcgetattr(STDIN_FILENO, &oldtc);
    newtc = oldtc;
    newtc.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newtc);
    scanf(" %10s", password); // Accept 10 input only
    tcsetattr(STDIN_FILENO, TCSANOW, &oldtc);
	
    /* Key */
    unsigned char key[AES_256_KEY_SIZE];
    /* IV */
    unsigned char iv[AES_BLOCK_SIZE];
	/* Method */
    params->cipher_type = EVP_aes_256_cbc();
	/* Add salt */
	params->salt = "1234554321";
	/* Generate key and IV from the password with salt and md5 digest */
    if(!EVP_BytesToKey(params->cipher_type, EVP_md5(), params->salt, (unsigned char *) password, strlen(password), 10, key, iv)) {
	    fprintf(stderr, "EVP_BytesToKey failed\n");
	    return errno;
    }
	/* Check key and IV */
	/*
	int i;
	printf("Password: "); for(i=0; i<8; ++i) { printf("%s", &password[i]); } printf("\n"); 
	printf("Key: "); for(i=0; i<AES_256_KEY_SIZE; ++i) { printf("%02x", key[i]); } printf("\n");
	printf("IV: "); for(i=0; i<AES_256_KEY_SIZE; ++i) { printf("%02x", iv[i]); } printf("\n");
	*/
	/* Set the keys generated */
	params->key = key;
	params->iv = iv;
    fflush(stdin);
	output_file = argv[3];
    if (strncmp(argv[1],"-enc",4) == 0) {
		/* Encrypt the file */
		/* Indicate that we want to encrypt */
    	params->encrypt = 1;

    	/* Open the input file for reading in binary ("rb" mode) */
    	f_input = fopen(argv[2], "rb");
    	if (!f_input) {
        	/* Unable to open file for reading */
        	printf("ERROR:1 fopen error: %s\n", strerror(errno));
        	return errno;
    	}

    	/* Open and truncate file to zero length or create ciphertext file for writing */
    	f_enc = fopen(argv[3], "wb");
    	if (!f_enc) {
        	/* Unable to open file for writing */
        	printf("ERROR:2 fopen error: %s\n", strerror(errno));
        	return errno;
    	}

    	/* Encrypt the given file */
    	do_file_encrypt_decrypt(params, f_input, f_enc);
		printf("Encryption done, closing the file descriptors\n");
    	/* Encryption done, close the file descriptors */
    	fclose(f_input);
    	fclose(f_enc);
    } else if (strncmp(argv[1],"-dec",4) == 0){
	    /* Decrypt the file */
    	/* Indicate that we want to decrypt */
    	params->encrypt = 0;
    	/* Open the encrypted file for reading in binary ("rb" mode) */
    	f_input = fopen(argv[2], "rb");
    	if (!f_input) {
        	/* Unable to open file for reading */
        	printf("ERROR:3 fopen error: %s\n", strerror(errno));
        	return errno;
    	}

    	/* Open and truncate file to zero length or create decrypted file for writing */
    	f_dec = fopen(argv[3], "wb");
    	if (!f_dec) {
        	/* Unable to open file for writing */
        	printf("ERROR:4 fopen error: %s\n", strerror(errno));
        	return errno;
    	}

    	/* Decrypt the given file */
    	do_file_encrypt_decrypt(params, f_input, f_dec);
		printf("Decryption done, closing files.\n");
    	/* Close the open file descriptors */
    	fclose(f_input);
    	fclose(f_dec);
    } else {
	printf("Usage: %s -enc/dec \n", argv[0]);
    }
    /* Free the memory allocated to params struct */
    free(params);
	/* Clear stdin */
	fflush(stdin);

    return 0;
}
