# zlodejina-zlodejska

*
 ============================================================================
 Name        : myPassword.c
 Author      : BPC-VBA
 Version     :
 Copyright   : 2024 (c) VUT v Brně
 Description : OpenSSL in C, Ansi-style
 ============================================================================
 */

#ifndef __linux__
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

// Klíč a inicializační vektor by měly být odpovídající délky pro použitý šifrovací algoritmus
const unsigned char iv[EVP_MAX_IV_LENGTH] = "loginname";
unsigned char key[EVP_MAX_KEY_LENGTH] = "bpcvba";
// Šifrované heslo
const unsigned char cipherpass[] = { 0xc7, 0x08, 0x4b, 0x43, 0xf1, 0x16, 0xfd,
		0xb6, 0x0e, 0x47, 0x60, 0x3b, 0xbc, 0x7c, 0x74, 0x98 };

//TODO 31 Zpětně volaná funkce pro výpis informací o šifrovací funkci
void vypis(const EVP_CIPHER *md, const char *from, const char *to, void *arg) {
    EVP_CIPHER *cpCurrent;

    printf("\n%d: %s", ++(*((int*) arg)), from);
    // Kontrola dostupnosti šifrovacího algoritmu u poskytovatele 'default'
    cpCurrent = EVP_CIPHER_fetch(NULL, from, "provider=default");

    if ( NULL != cpCurrent) {
        printf(" @ default");
        EVP_CIPHER_free(cpCurrent);
    } else {
        ERR_get_error();
        printf(" @   ");
    }

    // Kontrola dostupnosti šifrovacího algoritmu u poskytovatele 'legacy'
    md = EVP_CIPHER_fetch(NULL, from, "provider=legacy");
    if ( NULL != md) {
        printf(" @ legacy");
        EVP_CIPHER_free(cpCurrent);
    } else {
        ERR_get_error();
        printf(" @   ");
    }


}
//TODO 41 Doplňte funkci pro zadání hesla bez zobrazení stisknutých kláves
#ifndef __linux__
int cbPassword(char *buf, int size, int rwflag, void *u) {
	return strlen(buf);
}
#else
int cbPassword(char *buf, int size, int rwflag, void *u) {
	struct termios old_termios, new_termios;

	printf("\nEnter private key password: ");
	fflush(stdout);

	tcgetattr(STDIN_FILENO, &old_termios);
	new_termios = old_termios;
	new_termios.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);

	if (fgets(buf, size, stdin) == NULL) {
		tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
		return 0;
	}

	tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);

	size_t len = strlen(buf);
	if (buf[len - 1] == '\n') {
		buf[len - 1] = '\0';
		len--;
	}

	printf("\n");

	return strlen(buf);
}
#endif

// Zpětně volaná funkce pro zadávání hesla
void getPassword(char *password) {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;

    // Získání aktuálního nastavení konzole
    GetConsoleMode(hStdin, &mode);

    // Vypnutí ENABLE_ECHO_INPUT
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);

    // Načtení hesla z příkazové řádky
    printf("Enter password: ");
    fflush(stdout);
    fgets(password, 100, stdin);

    // Odstranění případného znaku konce řádku
    char *pos;
    if ((pos = strchr(password, '\n')) != NULL)
        *pos = '\0';

    // Obnovení nastavení konzole
    SetConsoleMode(hStdin, mode);
}

// Funkce pro dešifrování s parametrem pro heslo
void desifrovani(const char *password) {
    // pole pro uložení dešifrovaného hesla minimálně
	// stejné délky jako je globální pole cipherpass se šifrovanými daty
    unsigned char decryptedtext[sizeof(cipherpass)];
    int decryptedtext_len, len;

    // alokace šifrovacího algoritmu z předchozího výpisu poskytovatele default nebo legacy
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "aes-256-cbc", "provider=default");
    if (!cipher) {
        fprintf(stderr, "Nepodařilo se načíst šifrovací algoritmus.\n");
        return;
    }

    // alokace kontextu pro dešifrování
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Nepodařilo se vytvořit kontext pro dešifrování.\n");
        EVP_CIPHER_free(cipher);
        return;
    }

    // Inicializace dešifrování
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        fprintf(stderr, "Inicializace dešifrování selhala.\n");
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher);
        return;
    }

    // Dešifrování
    if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, cipherpass, sizeof(cipherpass))) {
        fprintf(stderr, "Dešifrování selhalo.\n");
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher);
        return;
    }
    decryptedtext_len = len;

    // Dokončení dešifrování
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) {
        fprintf(stderr, "Dokončení dešifrování selhalo.\n");
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher);
        return;
    }
    decryptedtext_len += len;

    // Výpis dešifrovaného hesla
    printf("\nDešifrované heslo je  ");
    for (int i = 0; i < decryptedtext_len; i++) {
        printf("%c", decryptedtext[i]);
    }
    printf("\n");

    // Uvolnění zdrojů
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);

    // Smazání obsahu hesla
    memset((void *) password, 0, strlen(password));
 }

//TODO 35 Funkce pro dešifrování


//TODO 42 Doplňte bezpečné zadávání a mazání hesla


//TODO 43 Příklad  hashování
void hashovani() {
    // Příprava soli a hesla
    const char *sul = "sul";
    const char *heslo = "heslo";

    // Pole pro uložení výsledného hashe
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    // Alokace algoritmu SHA-256
    const EVP_MD *md = EVP_MD_fetch(NULL, "sha256", NULL);
    if (!md) {
        fprintf(stderr, "Nepodařilo se načíst algoritmus.\n");
        return;
    }

    // Alokace kontextu pro hashování
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Nepodařilo se vytvořit kontext pro hashování.\n");
        EVP_MD_free((EVP_MD *) md); // Uvolnění algoritmu
        return;
    }

    // Inicializace hashování
    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        fprintf(stderr, "Inicializace hashování selhala.\n");
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free((EVP_MD *) md); // Uvolnění algoritmu
        return;
    }

    // Hashování soli
    if (1 != EVP_DigestUpdate(mdctx, sul, strlen(sul))) {
        fprintf(stderr, "Hashování soli selhalo.\n");
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free((EVP_MD *) md); // Uvolnění algoritmu
        return;
    }

    // Hashování hesla
    if (1 != EVP_DigestUpdate(mdctx, heslo, strlen(heslo))) {
        fprintf(stderr, "Hashování hesla selhalo.\n");
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free((EVP_MD *) md); // Uvolnění algoritmu
        return;
    }

    // Získání výsledného otisku
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        fprintf(stderr, "Získání otisku selhalo.\n");
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free((EVP_MD *) md); // Uvolnění algoritmu
        return;
    }

    // Výpis vypočítaného hashe v hexadecimálním formátu
    printf("Vypočítaný hash: ");
    for (int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    // Uvolnění zdrojů
    EVP_MD_CTX_free(mdctx);
    EVP_MD_free((EVP_MD *) md);
}


int main(void) {
	char password[100]; // Pole pro uložení hesla

	    // Získání hesla
	    getPassword(password);

	    // Desifrování s heslem
	    desifrovani(password);

	    // Hashování
	    hashovani();

	//TODO 21 Kontrola verze knihovny
	unsigned long openssl_version = OpenSSL_version_num();
	if (openssl_version < 0x30000000L) {
		fprintf(stderr, "Verzia kniznice OpenSSL je nizsia nez 3.0.\n");
		return EXIT_FAILURE;
	}
	//TODO 22 Výpis verze
	printf("Verzia kniznice OpenSSL je: %s\n", OpenSSL_version(OPENSSL_VERSION));
	//TODO 23 Inicializace knihovny
	if (OPENSSL_init_crypto(
			OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)
			!= 1) {
		fprintf(stderr, "Nepodarilo sa inicializovat kniznicu OpenSSL.\n");
		return EXIT_FAILURE;
	}
	//TODO 24 Kontrola poskytovatele 'default'
	OSSL_PROVIDER *defProv;
		if(OSSL_PROVIDER_available(NULL,"default") == 1)
		{
			printf("Default workingst\n");
		}
		else
		{
			defProv = OSSL_PROVIDER_load(NULL,"default");
			if(defProv == NULL){
					printf("Default load workn't\n");
					return -1;
			}
			else{
				printf("Default workst\n");
				OSSL_PROVIDER_unload(defProv);
			}
		}
	//TODO 25 Kontrola poskytovatele 'legacy'
	OSSL_PROVIDER *legProv;
	if(OSSL_PROVIDER_available(NULL,"legacy") == 1)
	{
		printf("Legacy workntigst\n");
	}
	else
	{
		legProv = OSSL_PROVIDER_load(NULL,"legacy");
		if(legProv == NULL){
				printf("legacy load workn't\n");
				return -1;
		}
		else{
			printf("Legacy workst\n");
			OSSL_PROVIDER_unload(legProv);
		}
	}

	if (OSSL_PROVIDER_available(NULL, "fips")) {
			printf("Fips workn't.\n");
		} else {
			OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "fips");
			if (!prov) {
				fprintf(stderr, "Fips load workn't.\n");
			} else {
				printf("Fips workst.\n");
				OSSL_PROVIDER_unload(prov);
			}
		}
	//TODO 32 Proměnná pro počet algoritmů
	int pocet_algoritmu = 0;
	//TODO 33 Výpis všech algoritmů
	EVP_CIPHER_do_all_sorted(vypis, &pocet_algoritmu);
	//TODO 36 Volání funkce pro dešifrování

	//TODO 44 Volání příkladu hashování

	//TODO 26 Uvolnění zdrojů
	ERR_free_strings();
	OPENSSL_cleanup();
	return EXIT_SUCCESS;
}



/*
	//TODO 25 Kontrola poskytovatele 'legacy'
	OSSL_PROVIDER *legProv;
	if(OSSL_PROVIDER_available(NULL,"legacy") == 1)
	{
		printf("Legacy workntigst\n");
	}
	else
	{
		legProv = OSSL_PROVIDER_load(NULL,"legacy");
		if(legProv == NULL){
				printf("legacy load workn't\n");
				return -1;
		}
		else{
			printf("Legacy workst\n");
			OSSL_PROVIDER_unload(legProv);
		}
	}

	OSSL_PROVIDER *fipProv;
		if(OSSL_PROVIDER_available(NULL,"fips") == 1)
		{
			printf("Fips workingst\n");
		}
		else
		{
			fipProv = OSSL_PROVIDER_load(NULL,"fips\n");
			if(fipProv == NULL){
					printf("Fips workn't");
					return -1;
			}
			else{
			printf("Fips workst\n");
			OSSL_PROVIDER_unload(fipProv);
			}
		}
		*/
