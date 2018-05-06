#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_sha2.h"

//#include "common.h"

enum Algo {
        SKEIN = 0,
        BMW,
        BLAKE,
        SHA512,
        SHABAL,
        KECCAK,
        SHAVITE,
        WHIRLPOOL,
        CUBEHASH,
        JH,
        LUFFA,
        ECHO,
        SIMD,
        FUGUE,
        GROESTL,
        HAMSI,
	HASH_FUNC_COUNT = 8
};

static void getAlgoString(const uint8_t* prevblock, char *output)
{
	char *sptr = output;
	int j;
	int sumOfSeven;
	for (j = 0; j < HASH_FUNC_COUNT - 1; j++) {
		char b = (7 - j) >> 1; // 16 ascii hex chars, reversed
		uint8_t algoDigit = (j & 1) ? prevblock[b] & 0xF : prevblock[b] >> 4;
		sumOfSeven += algoDigit;
		if (algoDigit >= 10)
			sprintf(sptr, "%c", 'A' + (algoDigit - 10));
		else
			sprintf(sptr, "%u", (uint32_t) algoDigit);
		sptr++;
	}
	uint8_t algoDigit;
	if(sumOfSeven < 28)
   		algoDigit = 0;
	else if(sumOfSeven < 39)
   		algoDigit = 1;
	else if(sumOfSeven < 47)
    		algoDigit = 2;
	else if(sumOfSeven < 54)
   		algoDigit = 3;
	else if(sumOfSeven < 61)
   		algoDigit = 4;
	else if(sumOfSeven < 66)
   		algoDigit = 5;
	else if(sumOfSeven < 72)
   		algoDigit = 6;
	else if(sumOfSeven < 76)
   		algoDigit = 7;
	else if(sumOfSeven < 81)
   		algoDigit = 8;
	else if(sumOfSeven < 86)
   		algoDigit = 9;
	else if(sumOfSeven < 90)
   		algoDigit = 10;
	else if(sumOfSeven < 94)
   		algoDigit = 11;
	else if(sumOfSeven < 97)
   		algoDigit = 12;
	else if(sumOfSeven < 100)
		algoDigit = 13;
	else if(sumOfSeven < 103)
   		algoDigit = 14;
	else
   		algoDigit = 15;
	if (algoDigit >= 10)
      		sprintf(sptr, "%c", 'A' + (algoDigit - 10));
	else
   		sprintf(sptr, "%u", (uint32_t) algoDigit);
	sptr++;

	*sptr = '\0';
}

void x16r_hash(const char* input, char* output, uint32_t len)
{
	uint32_t hash[64/4];
	char hashOrder[HASH_FUNC_COUNT + 1] = { 0 };

	sph_skein512_context     ctx_skein;
	sph_bmw512_context       ctx_bmw;
	sph_blake512_context     ctx_blake;
	sph_sha512_context       ctx_sha512;
	sph_shabal512_context    ctx_shabal;
	sph_keccak512_context    ctx_keccak;
	sph_shavite512_context   ctx_shavite;
	sph_whirlpool_context    ctx_whirlpool;
	sph_cubehash512_context  ctx_cubehash;
	sph_jh512_context        ctx_jh;
	sph_luffa512_context     ctx_luffa;
	sph_echo512_context      ctx_echo;
	sph_simd512_context      ctx_simd;
	sph_fugue512_context     ctx_fugue;
	sph_groestl512_context   ctx_groestl;
	sph_hamsi512_context     ctx_hamsi;

	void *in = (void*) input;
	int size = len;
    int i;

	getAlgoString(&input[4], hashOrder);

	for (i = 0; i < 16; i++)
	{
		const char elem = hashOrder[i];
		const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

		switch (algo) {
                case SKEIN:
                        sph_skein512_init(&ctx_skein);
                        sph_skein512(&ctx_skein, in, size);
                        sph_skein512_close(&ctx_skein, hash);
                        break;
		case BMW:
			sph_bmw512_init(&ctx_bmw);
			sph_bmw512(&ctx_bmw, in, size);
			sph_bmw512_close(&ctx_bmw, hash);
			break;
                case BLAKE:
                        sph_blake512_init(&ctx_blake);
                        sph_blake512(&ctx_blake, in, size);
                        sph_blake512_close(&ctx_blake, hash);
                        break;
                case SHA512:
                        sph_sha512_init(&ctx_sha512);
                        sph_sha512(&ctx_sha512,(const void*) in, size);
                        sph_sha512_close(&ctx_sha512,(void*) hash);
                        break;
                case SHABAL:
                        sph_shabal512_init(&ctx_shabal);
                        sph_shabal512(&ctx_shabal, in, size);
                        sph_shabal512_close(&ctx_shabal, hash);
                        break;
                case KECCAK:
                        sph_keccak512_init(&ctx_keccak);
                        sph_keccak512(&ctx_keccak, in, size);
                        sph_keccak512_close(&ctx_keccak, hash);
                        break;
                case SHAVITE:
                        sph_shavite512_init(&ctx_shavite);
                        sph_shavite512(&ctx_shavite, in, size);
                        sph_shavite512_close(&ctx_shavite, hash);
                        break;
                case WHIRLPOOL:
                        sph_whirlpool_init(&ctx_whirlpool);
                        sph_whirlpool(&ctx_whirlpool, in, size);
                        sph_whirlpool_close(&ctx_whirlpool, hash);
                        break;
                case CUBEHASH:
                        sph_cubehash512_init(&ctx_cubehash);
                        sph_cubehash512(&ctx_cubehash, in, size);
                        sph_cubehash512_close(&ctx_cubehash, hash);
                        break;
                case JH:
                        sph_jh512_init(&ctx_jh);
                        sph_jh512(&ctx_jh, in, size);
                        sph_jh512_close(&ctx_jh, hash);
                        break;
		case LUFFA:
			sph_luffa512_init(&ctx_luffa);
			sph_luffa512(&ctx_luffa, in, size);
			sph_luffa512_close(&ctx_luffa, hash);
			break;
                case ECHO:
                        sph_echo512_init(&ctx_echo);
                        sph_echo512(&ctx_echo, in, size);
                        sph_echo512_close(&ctx_echo, hash);
                        break;
		case SIMD:
			sph_simd512_init(&ctx_simd);
			sph_simd512(&ctx_simd, in, size);
			sph_simd512_close(&ctx_simd, hash);
			break;
                case FUGUE:
                        sph_fugue512_init(&ctx_fugue);
                        sph_fugue512(&ctx_fugue, in, size);
                        sph_fugue512_close(&ctx_fugue, hash);
                        break;
                case GROESTL:
                        sph_groestl512_init(&ctx_groestl);
                        sph_groestl512(&ctx_groestl, in, size);
                        sph_groestl512_close(&ctx_groestl, hash);
                        break;
                case HAMSI:
                        sph_hamsi512_init(&ctx_hamsi);
                        sph_hamsi512(&ctx_hamsi, in, size);
                        sph_hamsi512_close(&ctx_hamsi, hash);
                        break;
		}
		in = (void*) hash;
		size = 64;
	}
	memcpy(output, hash, 32);
}
