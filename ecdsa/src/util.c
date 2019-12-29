#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "relic/relic.h"
#include "pari/pari.h"
#include "types.h"
#include "util.h"

int init() {
	if (core_init() != RLC_OK) {
    core_clean();
    return RLC_ERR;
  }

  if (ec_param_set_any() != RLC_OK) {
    core_clean();
    return RLC_ERR;
  }

	// Set the secp256k1 curve, which is used in Bitcoin.
	ep_param_set(SECG_K256);

	// Initialize the PARI stack (in bytes).
	pari_init(10000000, 2);
	
	return RLC_OK;
}

int clean() {
	return core_clean();
}

void memzero(void *ptr, size_t len) {
  typedef void *(*memset_t)(void *, int, size_t);
  static volatile memset_t memset_func = memset;
  memset_func(ptr, 0, len);
}

long long cpucycles(void) {
	unsigned long long cycles;
	asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
			: "=a" (cycles) ::  "%rdx");
	return cycles;
}

long long ttimer(void) {
	struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	return (long long) (time.tv_sec * CLOCK_PRECISION + time.tv_nsec);
}

void serialize_message(uint8_t **serialized,
											 const message_t message,
											 const unsigned msg_type_length,
											 const unsigned msg_data_length) {
	*serialized = malloc(msg_type_length + msg_data_length + (2 * sizeof(unsigned)));
	if (*serialized == NULL) {
		THROW(ERR_NO_MEMORY);
	}

	memcpy(*serialized, &msg_type_length, sizeof(unsigned));
	memcpy(*serialized + sizeof(unsigned), message->type, msg_type_length);
	
	if (msg_data_length > 0) {
		memcpy(*serialized + sizeof(unsigned) + msg_type_length, &msg_data_length, sizeof(unsigned));
		memcpy(*serialized + (2 * sizeof(unsigned)) + msg_type_length, message->data, msg_data_length);
	} else {
		memset(*serialized + sizeof(unsigned) + msg_type_length, 0, sizeof(unsigned));
	}
}

void deserialize_message(message_t *deserialized_message, const uint8_t *serialized) {
	unsigned msg_type_length;
	memcpy(&msg_type_length, serialized, sizeof(unsigned));
	unsigned msg_data_length;
	memcpy(&msg_data_length, serialized + sizeof(unsigned) + msg_type_length, sizeof(unsigned));

	message_null(*deserialized_message);
	message_new(*deserialized_message, msg_type_length, msg_data_length);

	memcpy((*deserialized_message)->type, serialized + sizeof(unsigned), msg_type_length);
	if (msg_data_length > 0) {
		memcpy((*deserialized_message)->data, serialized + (2 * sizeof(unsigned)) + msg_type_length, msg_data_length);
	}
}

int generate_keys_and_write_to_file(const cl_params_t params) {
	int result_status = RLC_OK;

	GEN cl_sk_alice, cl_pk_alice;
	GEN cl_sk_bob, cl_pk_bob;
	GEN cl_sk_tumbler, cl_pk_tumbler;

	cl_public_key_t pk_alice, pk_bob;
	cl_ciphertext_t ctx_ec_sk_alice, ctx_ec_sk_bob;

	bn_t q, ec_sk_alice, ec_sk_bob, ec_sk_tumbler;
	ec_t ec_pk_alice, ec_pk_bob, ec_pk_tumbler;
	ec_t ec_pk_alice_tumbler, ec_pk_bob_tumbler;

	uint8_t serialized_ec_sk[RLC_BN_SIZE];
	uint8_t serialized_ec_pk[RLC_EC_SIZE_COMPRESSED];

	cl_public_key_null(pk_alice);
	cl_public_key_null(pk_bob);
	cl_ciphertext_null(ctx_ec_sk_alice);
	cl_ciphertext_null(ctx_ec_sk_bob);

	bn_null(q);
	bn_null(ec_sk_alice);
	bn_null(ec_sk_bob);
	bn_null(ec_sk_tumbler);

	ec_null(ec_pk_alice);
	ec_null(ec_pk_bob);
	ec_null(ec_pk_tumbler);
	ec_null(ec_pk_alice_tumbler);
	ec_null(ec_pk_bob_tumbler);

	TRY {
		cl_public_key_new(pk_alice);
		cl_public_key_new(pk_bob);
		cl_ciphertext_new(ctx_ec_sk_alice);
		cl_ciphertext_new(ctx_ec_sk_bob);

		bn_new(q);
		bn_new(ec_sk_alice);
		bn_new(ec_sk_bob);
		bn_new(ec_sk_tumbler);

		ec_new(ec_pk_alice);
		ec_new(ec_pk_bob);
		ec_new(ec_pk_tumbler);
		ec_new(ec_pk_alice_tumbler);
		ec_new(ec_pk_bob_tumbler);

		// Compute EC public and secret keys.
		ec_curve_get_ord(q);
		bn_rand_mod(ec_sk_alice, q);
		bn_rand_mod(ec_sk_bob, q);
		bn_rand_mod(ec_sk_tumbler, q);

		ec_mul_gen(ec_pk_alice, ec_sk_alice);
		ec_mul_gen(ec_pk_bob, ec_sk_bob);
		ec_mul_gen(ec_pk_tumbler, ec_sk_tumbler);

		ec_mul(ec_pk_alice_tumbler, ec_pk_alice, ec_sk_tumbler);
		ec_norm(ec_pk_alice_tumbler, ec_pk_alice_tumbler);
		ec_mul(ec_pk_bob_tumbler, ec_pk_bob, ec_sk_tumbler);
		ec_norm(ec_pk_bob_tumbler, ec_pk_bob_tumbler);

		// Compute CL encryption public and secret keys.
		cl_sk_alice = randomi(params->bound);
		cl_pk_alice = nupow(params->g_q, cl_sk_alice, NULL);
		pk_alice->pk = cl_pk_alice;

		cl_sk_bob = randomi(params->bound);
		cl_pk_bob = nupow(params->g_q, cl_sk_bob, NULL);
		pk_bob->pk = cl_pk_bob;

		cl_sk_tumbler = randomi(params->bound);
		cl_pk_tumbler = nupow(params->g_q, cl_sk_tumbler, NULL);

		// Encrypt EC secret key of Alice and Bob.
		const unsigned plain_str_len = bn_size_str(ec_sk_alice, 10);
    char plain_str[plain_str_len];
    bn_write_str(plain_str, plain_str_len, ec_sk_alice, 10);

		GEN plain_ec_sk_alice = strtoi(plain_str);
		if (cl_enc(ctx_ec_sk_alice, plain_ec_sk_alice, pk_alice, params) != RLC_OK) {
			THROW(ERR_CAUGHT);
		}

		memzero(plain_str, plain_str_len);
		bn_write_str(plain_str, plain_str_len, ec_sk_bob, 10);

		GEN plain_ec_sk_bob = strtoi(plain_str);
		if (cl_enc(ctx_ec_sk_bob, plain_ec_sk_bob, pk_bob, params) != RLC_OK) {
			THROW(ERR_CAUGHT);
		}

		// Create the filenames for the keys.
		unsigned alice_key_file_length = strlen(ALICE_KEY_FILE_PREFIX) + strlen(KEY_FILE_EXTENSION) + 10;
		char *alice_key_file_name = malloc(alice_key_file_length);
		
		unsigned bob_key_file_length = strlen(BOB_KEY_FILE_PREFIX) + strlen(KEY_FILE_EXTENSION) + 10;
		char *bob_key_file_name = malloc(bob_key_file_length);
		
		unsigned tumbler_key_file_length = strlen(TUMBLER_KEY_FILE_PREFIX) + strlen(KEY_FILE_EXTENSION) + 10;
		char *tumbler_key_file_name = malloc(tumbler_key_file_length);
		
		if (alice_key_file_name == NULL || bob_key_file_name == NULL || tumbler_key_file_name == NULL) {
			THROW(ERR_CAUGHT);
		}

		snprintf(alice_key_file_name, alice_key_file_length, "../keys/%s.%s", ALICE_KEY_FILE_PREFIX, KEY_FILE_EXTENSION);
		snprintf(bob_key_file_name, bob_key_file_length, "../keys/%s.%s", BOB_KEY_FILE_PREFIX, KEY_FILE_EXTENSION);
		snprintf(tumbler_key_file_name, tumbler_key_file_length, "../keys/%s.%s", TUMBLER_KEY_FILE_PREFIX, KEY_FILE_EXTENSION);

		// Write Alice's keys to a file.
		FILE *file = fopen(alice_key_file_name, "wb");
		if (file == NULL) {
			THROW(ERR_NO_FILE);
		}

		bn_write_bin(serialized_ec_sk, RLC_BN_SIZE, ec_sk_alice);
		fwrite(serialized_ec_sk, sizeof(uint8_t), RLC_BN_SIZE, file);
		ec_write_bin(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED, ec_pk_alice_tumbler, 1);
		fwrite(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file);

		fwrite(GENtostr(cl_sk_alice), sizeof(char), RLC_CL_SECRET_KEY_SIZE, file);
    fwrite(GENtostr(cl_pk_alice), sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file);

		memzero(serialized_ec_sk, RLC_BN_SIZE);
		memzero(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);

		fclose(file);

		// Write Bob's keys to a file.
		file = fopen(bob_key_file_name, "wb");
		if (file == NULL) {
			THROW(ERR_NO_FILE);
		}

		bn_write_bin(serialized_ec_sk, RLC_BN_SIZE, ec_sk_bob);
		fwrite(serialized_ec_sk, sizeof(uint8_t), RLC_BN_SIZE, file);
		ec_write_bin(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED, ec_pk_bob_tumbler, 1);
		fwrite(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file);

		fwrite(GENtostr(cl_sk_bob), sizeof(char), RLC_CL_SECRET_KEY_SIZE, file);
    fwrite(GENtostr(cl_pk_bob), sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file);

		memzero(serialized_ec_sk, RLC_BN_SIZE);
		memzero(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);

		fclose(file);

		// Write Tumbler's keys to a file.
		file = fopen(tumbler_key_file_name, "wb");
		if (file == NULL) {
			THROW(ERR_NO_FILE);
		}

		// Tumbler has two EC public keys, one with Alice and one with Bob.
		bn_write_bin(serialized_ec_sk, RLC_BN_SIZE, ec_sk_tumbler);
		fwrite(serialized_ec_sk, sizeof(uint8_t), RLC_BN_SIZE, file);
		ec_write_bin(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED, ec_pk_alice_tumbler, 1);
		fwrite(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file);
		memzero(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);
		ec_write_bin(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED, ec_pk_bob_tumbler, 1);
		fwrite(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file);

		fwrite(GENtostr(cl_sk_tumbler), sizeof(char), RLC_CL_SECRET_KEY_SIZE, file);
    fwrite(GENtostr(cl_pk_tumbler), sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file);
		fwrite(GENtostr(cl_pk_alice), sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file);
		fwrite(GENtostr(cl_pk_bob), sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file);
		fwrite(GENtostr(ctx_ec_sk_alice->c1), sizeof(char), RLC_CL_CIPHERTEXT_SIZE, file);
		fwrite(GENtostr(ctx_ec_sk_alice->c2), sizeof(char), RLC_CL_CIPHERTEXT_SIZE, file);
		fwrite(GENtostr(ctx_ec_sk_bob->c1), sizeof(char), RLC_CL_CIPHERTEXT_SIZE, file);
		fwrite(GENtostr(ctx_ec_sk_bob->c2), sizeof(char), RLC_CL_CIPHERTEXT_SIZE, file);

		fclose(file);

		free(alice_key_file_name);
		free(bob_key_file_name);
		free(tumbler_key_file_name);
	} CATCH_ANY {
		result_status = RLC_ERR;
	} FINALLY {
		cl_public_key_free(pk_alice);
		cl_public_key_free(pk_bob);
		cl_ciphertext_free(ctx_ec_sk_alice);
		cl_ciphertext_free(ctx_ec_sk_bob);

		bn_free(q);
		bn_free(ec_sk_alice);
		bn_free(ec_sk_bob);
		bn_free(ec_sk_tumbler);
		
		ec_free(ec_pk_alice);
		ec_free(ec_pk_bob);
		ec_free(ec_pk_tumbler);
		ec_free(ec_pk_alice_tumbler);
		ec_free(ec_pk_bob_tumbler);
	}

	return result_status;
}

int read_keys_from_file_alice_bob(const char *name,
																	ec_secret_key_t ec_secret_key,
																	ec_public_key_t ec_public_key,
																	cl_secret_key_t cl_secret_key,
																	cl_public_key_t cl_public_key,
																	cl_public_key_t tumbler_cl_public_key) {
	int result_status = RLC_OK;

	uint8_t serialized_ec_sk[RLC_BN_SIZE];
	uint8_t serialized_ec_pk[RLC_EC_SIZE_COMPRESSED];
	char serialized_cl_sk[RLC_CL_SECRET_KEY_SIZE];
	char serialized_cl_pk[RLC_CL_PUBLIC_KEY_SIZE];

	TRY {
		unsigned key_file_length = strlen(name) + strlen(KEY_FILE_EXTENSION) + 10;
		char *key_file_name = malloc(key_file_length);
		
		if (key_file_name == NULL) {
			THROW(ERR_CAUGHT);
		}

		snprintf(key_file_name, key_file_length, "../keys/%s.%s", name, KEY_FILE_EXTENSION);
		
		FILE *file = fopen(key_file_name, "rb");
		if (file == NULL) {
			THROW(ERR_NO_FILE);
		}

		if (fread(serialized_ec_sk, sizeof(uint8_t), RLC_BN_SIZE, file) != RLC_BN_SIZE) {
			THROW(ERR_NO_READ);
		}
		bn_read_bin(ec_secret_key->sk, serialized_ec_sk, RLC_BN_SIZE);

		if (fread(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file) != RLC_EC_SIZE_COMPRESSED) {
			THROW(ERR_NO_READ);
		}
		ec_read_bin(ec_public_key->pk, serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);


		if (fread(serialized_cl_sk, sizeof(char), RLC_CL_SECRET_KEY_SIZE, file) != RLC_CL_SECRET_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		cl_secret_key->sk = gp_read_str(serialized_cl_sk);
		
		if (fread(serialized_cl_pk, sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file) != RLC_CL_PUBLIC_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		cl_public_key->pk = gp_read_str(serialized_cl_pk);
		memzero(serialized_cl_pk, RLC_CL_PUBLIC_KEY_SIZE);

		fclose(file);
		free(key_file_name);

		key_file_length = strlen(TUMBLER_KEY_FILE_PREFIX) + strlen(KEY_FILE_EXTENSION) + 10;
		key_file_name = malloc(key_file_length);
		
		if (key_file_name == NULL) {
			THROW(ERR_CAUGHT);
		}

		snprintf(key_file_name, key_file_length, "../keys/%s.%s", TUMBLER_KEY_FILE_PREFIX, KEY_FILE_EXTENSION);
		
		file = fopen(key_file_name, "rb");
		if (file == NULL) {
			THROW(ERR_NO_FILE);
		}

		fseek(file, RLC_BN_SIZE + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_CL_SECRET_KEY_SIZE, SEEK_SET);
		if (fread(serialized_cl_pk, sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file) != RLC_CL_PUBLIC_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		tumbler_cl_public_key->pk = gp_read_str(serialized_cl_pk);

		fclose(file);
		free(key_file_name);
	} CATCH_ANY {
		result_status = RLC_ERR;
	}

	return result_status;
}

int read_keys_from_file_tumbler(ec_secret_key_t ec_secret_key,
																ec_public_key_t ec_public_key_alice_tumbler,
																ec_public_key_t ec_public_key_bob_tumbler,
																cl_secret_key_t cl_secret_key,
																cl_public_key_t cl_public_key,
																cl_public_key_t cl_public_key_alice,
																cl_public_key_t cl_public_key_bob,
																cl_ciphertext_t cl_ctx_ec_sk_alice,
																cl_ciphertext_t cl_ctx_ec_sk_bob) {
	int result_status = RLC_OK;

	uint8_t serialized_ec_sk[RLC_BN_SIZE];
	uint8_t serialized_ec_pk[RLC_EC_SIZE_COMPRESSED];
	char serialized_cl_sk[RLC_CL_SECRET_KEY_SIZE];
	char serialized_cl_pk[RLC_CL_PUBLIC_KEY_SIZE];
	char serialized_cl_ct[RLC_CL_CIPHERTEXT_SIZE];

	TRY {
		unsigned key_file_length = strlen(TUMBLER_KEY_FILE_PREFIX) + strlen(KEY_FILE_EXTENSION) + 10;
		char *key_file_name = malloc(key_file_length);
		
		if (key_file_name == NULL) {
			THROW(ERR_CAUGHT);
		}

		snprintf(key_file_name, key_file_length, "../keys/%s.%s", TUMBLER_KEY_FILE_PREFIX, KEY_FILE_EXTENSION);
		
		FILE *file = fopen(key_file_name, "rb");
		if (file == NULL) {
			THROW(ERR_NO_FILE);
		}

		if (fread(serialized_ec_sk, sizeof(uint8_t), RLC_BN_SIZE, file) != RLC_BN_SIZE) {
			THROW(ERR_NO_READ);
		}
		bn_read_bin(ec_secret_key->sk, serialized_ec_sk, RLC_BN_SIZE);

		if (fread(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file) != RLC_EC_SIZE_COMPRESSED) {
			THROW(ERR_NO_READ);
		}
		ec_read_bin(ec_public_key_alice_tumbler->pk, serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);
		memzero(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);
		
		if (fread(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file) != RLC_EC_SIZE_COMPRESSED) {
			THROW(ERR_NO_READ);
		}
		ec_read_bin(ec_public_key_bob_tumbler->pk, serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);

		if (fread(serialized_cl_sk, sizeof(char), RLC_CL_SECRET_KEY_SIZE, file) != RLC_CL_SECRET_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		cl_secret_key->sk = gp_read_str(serialized_cl_sk);
		
		if (fread(serialized_cl_pk, sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file) != RLC_CL_PUBLIC_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		cl_public_key->pk = gp_read_str(serialized_cl_pk);
		memzero(serialized_cl_pk, RLC_CL_PUBLIC_KEY_SIZE);

		if (fread(serialized_cl_pk, sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file) != RLC_CL_PUBLIC_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		cl_public_key_alice->pk = gp_read_str(serialized_cl_pk);
		memzero(serialized_cl_pk, RLC_CL_PUBLIC_KEY_SIZE);

		if (fread(serialized_cl_pk, sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file) != RLC_CL_PUBLIC_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		cl_public_key_bob->pk = gp_read_str(serialized_cl_pk);

		if (fread(serialized_cl_ct, sizeof(char), RLC_CL_CIPHERTEXT_SIZE, file) != RLC_CL_CIPHERTEXT_SIZE) {
			THROW(ERR_CAUGHT);
		}
		cl_ctx_ec_sk_alice->c1 = gp_read_str(serialized_cl_ct);
		memzero(serialized_cl_ct, RLC_CL_CIPHERTEXT_SIZE);

		if (fread(serialized_cl_ct, sizeof(char), RLC_CL_CIPHERTEXT_SIZE, file) != RLC_CL_CIPHERTEXT_SIZE) {
			THROW(ERR_CAUGHT);
		}
		cl_ctx_ec_sk_alice->c2 = gp_read_str(serialized_cl_ct);
		memzero(serialized_cl_ct, RLC_CL_CIPHERTEXT_SIZE);
		
		if (fread(serialized_cl_ct, sizeof(char), RLC_CL_CIPHERTEXT_SIZE, file) != RLC_CL_CIPHERTEXT_SIZE) {
			THROW(ERR_CAUGHT);
		}
		cl_ctx_ec_sk_bob->c1 = gp_read_str(serialized_cl_ct);
		memzero(serialized_cl_ct, RLC_CL_CIPHERTEXT_SIZE);

		if (fread(serialized_cl_ct, sizeof(char), RLC_CL_CIPHERTEXT_SIZE, file) != RLC_CL_CIPHERTEXT_SIZE) {
			THROW(ERR_CAUGHT);
		}
		cl_ctx_ec_sk_bob->c2 = gp_read_str(serialized_cl_ct);
		
		fclose(file);
		free(key_file_name);
	} CATCH_ANY {
		result_status = RLC_ERR;
	}

	return result_status;
}

int generate_cl_params(cl_params_t params) {
	int result_status = RLC_OK;

	TRY {
		if (params == NULL) {
			THROW(ERR_CAUGHT);
		}

		// Parameters generated using HSM.sage script.
		params->Delta_K = negi(strtoi("7917297328878683784842235952488620683924100338715963369693275768732162831834859052302716918416013031853265985178593375655994934704463023676296364363803257769443921988228513012040548137047446483986199954435962221122006965317176921759968659376932101987729556148116190707955808747136944623277094531007901655971804163515065712136708172984834192213773138039179492400722665370317221867505959207212674207052581946756527848674480328854830559945140752059719739492686061412113598389028096554833252668553020964851121112531561161799093718416247246137641387797659"));
		// Bound for exponentiation, for uniform sampling to be at 2^{-40} from the unifom in <g_q>.
    params->bound = strtoi("25413151665722220203610173826311975594790577398151861612310606875883990655261658217495681782816066858410439979225400605895077952191850577877370585295070770312182177789916520342292660169492395314400288273917787194656036294620169343699612953311314935485124063580486497538161801803224580096");

    GEN g_q_a = strtoi("4008431686288539256019978212352910132512184203702279780629385896624473051840259706993970111658701503889384191610389161437594619493081376284617693948914940268917628321033421857293703008209538182518138447355678944124861126384966287069011522892641935034510731734298233539616955610665280660839844718152071538201031396242932605390717004106131705164194877377");
    GEN g_q_b = negi(strtoi("3117991088204303366418764671444893060060110057237597977724832444027781815030207752301780903747954421114626007829980376204206959818582486516608623149988315386149565855935873517607629155593328578131723080853521348613293428202727746191856239174267496577422490575311784334114151776741040697808029563449966072264511544769861326483835581088191752567148165409"));
    GEN g_q_c = strtoi("7226982982667784284607340011220616424554394853592495056851825214613723615410492468400146084481943091452495677425649405002137153382700126963171182913281089395393193450415031434185562111748472716618186256410737780813669746598943110785615647848722934493732187571819575328802273312361412673162473673367423560300753412593868713829574117975260110889575205719");

		// Order of the secp256k1 elliptic curve group and the group G^q.
		params->q = strtoi("115792089237316195423570985008687907852837564279074904382605163141518161494337");
		params->g_q = qfi(g_q_a, g_q_b, g_q_c);

		GEN A = strtoi("0");
		GEN B = strtoi("7");
		GEN p = strtoi("115792089237316195423570985008687907853269984665640564039457584007908834671663");
		GEN coeff = mkvecn(2, A, B);
		params->E = ellinit(coeff, p, 1);

		GEN Gx = strtoi("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
		GEN Gy = strtoi("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
		params->G = mkvecn(2, Gx, Gy);
	} CATCH_ANY {
		result_status = RLC_ERR;
	}

	return result_status;
}

int cl_enc(cl_ciphertext_t ciphertext,
					 const GEN plaintext,
					 const cl_public_key_t public_key,
					 const cl_params_t params) {
  int result_status = RLC_OK;

  TRY {
    ciphertext->r = randomi(params->bound);
    ciphertext->c1 = nupow(params->g_q, ciphertext->r, NULL);

    GEN L = Fp_inv(plaintext, params->q);
    if (!mpodd(L)) {
      L = subii(L, params->q);
    }

		// f^plaintext = (q^2, Lq, (L - Delta_k) / 4)
    GEN fm = qfi(sqri(params->q), mulii(L, params->q), shifti(subii(sqri(L), params->Delta_K), -2));
    ciphertext->c2 = gmul(nupow(public_key->pk, ciphertext->r, NULL), fm);
  } CATCH_ANY {
    result_status = RLC_ERR;
  }

  return result_status;
}

int cl_dec(GEN *plaintext,
					 const cl_ciphertext_t ciphertext,
					 const cl_secret_key_t secret_key,
					 const cl_params_t params) {
  int result_status = RLC_OK;

  TRY {
		// c2 * (c1^sk)^(-1)
    GEN fm = gmul(ciphertext->c2, ginv(nupow(ciphertext->c1, secret_key->sk, NULL)));
    GEN L = diviiexact(gel(fm, 2), params->q);
    *plaintext = Fp_inv(L, params->q);
  } CATCH_ANY {
    result_status = RLC_ERR;
  }

  return result_status;
}

int commit(commit_t com, const ec_t x) {
	int result_status = RLC_OK;

	const unsigned SERIALIZED_LEN = 2 * RLC_EC_SIZE_COMPRESSED;
	uint8_t serialized[SERIALIZED_LEN];
	uint8_t hash[RLC_MD_LEN];

	bn_t q;
	bn_null(q);

	TRY {
		bn_new(q);

		ec_curve_get_ord(q);
		ec_rand(com->r);

		ec_write_bin(serialized, RLC_EC_SIZE_COMPRESSED, x, 1);
		ec_write_bin(serialized + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, com->r, 1);
		md_map(hash, serialized, SERIALIZED_LEN);

		if (8 * RLC_MD_LEN > bn_bits(q)) {
			unsigned len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(com->c, hash, len);
			bn_rsh(com->c, com->c, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(com->c, hash, RLC_MD_LEN);
		}
		bn_mod(com->c, com->c, q);
	} CATCH_ANY {
		result_status = RLC_ERR;
	} FINALLY {
		bn_free(q);
	}

	return result_status;
}

int decommit(const commit_t com, const ec_t x) {
	int result_status = RLC_ERR;

	const unsigned SERIALIZED_LEN = 2 * RLC_EC_SIZE_COMPRESSED;
	uint8_t serialized[SERIALIZED_LEN];
	uint8_t hash[RLC_MD_LEN];

	bn_t c_prime, q;

	bn_null(c_prime);
	bn_null(q);

	TRY {
		bn_new(c_prime);
		bn_new(q);

		ec_curve_get_ord(q);

		ec_write_bin(serialized, RLC_EC_SIZE_COMPRESSED, x, 1);
		ec_write_bin(serialized + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, com->r, 1);
		md_map(hash, serialized, SERIALIZED_LEN);

		if (8 * RLC_MD_LEN > bn_bits(q)) {
			unsigned len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(c_prime, hash, len);
			bn_rsh(c_prime, c_prime, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(c_prime, hash, RLC_MD_LEN);
		}
		bn_mod(c_prime, c_prime, q);

		result_status = dv_cmp_const(com->c->dp, c_prime->dp, RLC_MIN(com->c->used, c_prime->used));
		result_status = (result_status == RLC_NE ? RLC_ERR : RLC_OK);

		if (com->c->used != c_prime->used) {
			result_status = RLC_ERR;
		}
	}	CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(c_prime);
		bn_free(q);
	}

	return result_status;
}

int zk_cldl_prove(zk_proof_cldl_t proof,
									const GEN x,
									const cl_ciphertext_t ciphertext,
									const cl_public_key_t public_key,
									const cl_params_t params) {
	int result_status = RLC_OK;

	bn_t rlc_k, rlc_r2, rlc_soundness;
	bn_null(rlc_k);
	bn_null(rlc_r2);
	bn_null(rlc_soundness);

	TRY {
		bn_new(rlc_k);
		bn_new(rlc_r2);
		bn_new(rlc_soundness);

		// [\tilde{A} \cdot C \cdot 2^40], we take C to be of size 2^40 as well.
		GEN soundness = shifti(gen_1, 40);
		GEN dist = mulii(mulii(params->bound, soundness), shifti(gen_1, 40));
		GEN r1 = randomi(dist);
		GEN r2 = randomi(params->q);

		bn_read_str(rlc_r2, GENtostr(r2), strlen(GENtostr(r2)), 10);
		bn_read_str(rlc_soundness, GENtostr(soundness), strlen(GENtostr(soundness)), 10);

		GEN L = Fp_inv(r2, params->q);
		if (!mpodd(L)) {
			L = subii(L, params->q);
		}
		// f^r_2 = (q^2, Lq, (L - Delta_k) / 4)
		GEN fr2 = qfi(sqri(params->q), mulii(L, params->q), shifti(subii(sqri(L), params->Delta_K), -2));

		proof->t1 = gmul(nupow(public_key->pk, r1, NULL), fr2); // pk^r_1 \cdot f^r_2
		ec_mul_gen(proof->t2, rlc_r2);													// g^r_2
		proof->t3 = nupow(params->g_q, r1, NULL);								// g_q^r_1

		const unsigned SERIALIZED_LEN = RLC_EC_SIZE_COMPRESSED + strlen(GENtostr(proof->t1)) + strlen(GENtostr(proof->t3));
		uint8_t serialized[SERIALIZED_LEN];
		uint8_t hash[RLC_MD_LEN];

		memcpy(serialized, (uint8_t *) GENtostr(proof->t1), strlen(GENtostr(proof->t1)));
		ec_write_bin(serialized + strlen(GENtostr(proof->t1)), RLC_EC_SIZE_COMPRESSED, proof->t2, 1);
		memcpy(serialized + strlen(GENtostr(proof->t1)) + RLC_EC_SIZE_COMPRESSED, 
					(uint8_t *) GENtostr(proof->t3), strlen(GENtostr(proof->t3)));
		md_map(hash, serialized, SERIALIZED_LEN);

		if (8 * RLC_MD_LEN > bn_bits(rlc_soundness)) {
			unsigned len = RLC_CEIL(bn_bits(rlc_soundness), 8);
			bn_read_bin(rlc_k, hash, len);
			bn_rsh(rlc_k, rlc_k, 8 * RLC_MD_LEN - bn_bits(rlc_soundness));
		} else {
			bn_read_bin(rlc_k, hash, RLC_MD_LEN);
		}

		bn_mod(rlc_k, rlc_k, rlc_soundness);

		const unsigned K_STR_LEN = bn_size_str(rlc_k, 10);
		char k_str[K_STR_LEN];
		bn_write_str(k_str, K_STR_LEN, rlc_k, 10);
		GEN k = strtoi(k_str);

		proof->u1 = addmulii(r1, ciphertext->r, k);	// r_1 + r \cdot k
		proof->u2 = Fp_addmul(r2, x, k, params->q); // r_2 + x \cdot k
	} CATCH_ANY {
		result_status = RLC_ERR;
	} FINALLY {
		bn_free(k);
		bn_free(rlc_r2);
		bn_free(rlc_soundness);
	}

	return result_status;
}

int zk_cldl_verify(const zk_proof_cldl_t proof,
									 const ec_t Q,
									 const cl_ciphertext_t ciphertext,
									 const cl_public_key_t public_key,
									 const cl_params_t params) {
	int result_status = RLC_ERR;

	bn_t rlc_k, rlc_u2, rlc_soundness;
	ec_t g_to_the_u2, Q_to_the_k;
	ec_t t2_times_Q_to_the_k;

	bn_null(rlc_k);
	bn_null(rlc_u2);
	bn_null(rlc_soundness);

	ec_null(g_to_the_u2);
	ec_null(Q_to_the_k);
	ec_null(t2_times_Q_to_the_k);

	TRY {
		bn_new(rlc_k);
		bn_new(rlc_u2);
		bn_new(rlc_soundness);

		ec_new(g_to_the_u2);
		ec_new(Q_to_the_k);
		ec_new(t2_times_Q_to_the_k);

		// Soundness is 2^-40.
		GEN soundness = shifti(gen_1, 40);
		bn_read_str(rlc_soundness, GENtostr(soundness), strlen(GENtostr(soundness)), 10);
		bn_read_str(rlc_u2, GENtostr(proof->u2), strlen(GENtostr(proof->u2)), 10);

		const unsigned SERIALIZED_LEN = RLC_EC_SIZE_COMPRESSED + strlen(GENtostr(proof->t1)) + strlen(GENtostr(proof->t3));
		uint8_t serialized[SERIALIZED_LEN];
		uint8_t hash[RLC_MD_LEN];

		memcpy(serialized, (uint8_t *) GENtostr(proof->t1), strlen(GENtostr(proof->t1)));
		ec_write_bin(serialized + strlen(GENtostr(proof->t1)), RLC_EC_SIZE_COMPRESSED, proof->t2, 1);
		memcpy(serialized + strlen(GENtostr(proof->t1)) + RLC_EC_SIZE_COMPRESSED, 
					(uint8_t *) GENtostr(proof->t3), strlen(GENtostr(proof->t3)));
		md_map(hash, serialized, SERIALIZED_LEN);

		if (8 * RLC_MD_LEN > bn_bits(rlc_soundness)) {
			unsigned len = RLC_CEIL(bn_bits(rlc_soundness), 8);
			bn_read_bin(rlc_k, hash, len);
			bn_rsh(rlc_k, rlc_k, 8 * RLC_MD_LEN - bn_bits(rlc_soundness));
		} else {
			bn_read_bin(rlc_k, hash, RLC_MD_LEN);
		}

		bn_mod(rlc_k, rlc_k, rlc_soundness);

		const unsigned K_STR_LEN = bn_size_str(rlc_k, 10);
		char k_str[K_STR_LEN];
		bn_write_str(k_str, K_STR_LEN, rlc_k, 10);
		GEN k = strtoi(k_str);

		GEN L = Fp_inv(proof->u2, params->q);
		if (!mpodd(L)) {
			L = subii(L, params->q);
		}
		// f^u_2 = (q^2, Lq, (L - Delta_k) / 4)
		GEN fu2 = qfi(sqri(params->q), mulii(L, params->q), shifti(subii(sqri(L), params->Delta_K), -2));

		ec_mul_gen(g_to_the_u2, rlc_u2);
		ec_mul(Q_to_the_k, Q, rlc_k);
		ec_add(t2_times_Q_to_the_k, proof->t2, Q_to_the_k);
		ec_norm(t2_times_Q_to_the_k, t2_times_Q_to_the_k);

		if (gequal(gmul(proof->t1, nupow(ciphertext->c2, k, NULL)), gmul(nupow(public_key->pk, proof->u1, NULL), fu2))
		&&  ec_cmp(g_to_the_u2, t2_times_Q_to_the_k) == RLC_EQ
		&&  gequal(gmul(proof->t3, nupow(ciphertext->c1, k, NULL)), nupow(params->g_q, proof->u1, NULL))) {
			result_status = RLC_OK;
		}
	} CATCH_ANY {
		result_status = RLC_ERR;
	} FINALLY {
		bn_free(rlc_k);
		bn_free(rlc_u2);
		bn_free(rlc_soundness);
		ec_free(g_to_the_u2);
		ec_free(Q_to_the_k);
		ec_free(t2_times_Q_to_the_k);
	}

	return result_status;
}

int zk_dlog_prove(zk_proof_t proof, const ec_t h, const bn_t w) {
	int result_status = RLC_OK;

	const unsigned SERIALIZED_LEN = 2 * RLC_EC_SIZE_COMPRESSED;
	uint8_t serialized[SERIALIZED_LEN];
	uint8_t hash[RLC_MD_LEN];
	
	bn_t e, r, q;

	bn_null(e);
	bn_null(r);
	bn_null(q);

	TRY {
		bn_new(e);
		bn_new(r);
		bn_new(q);

		ec_curve_get_ord(q);
		bn_rand_mod(r, q);

		ec_mul_gen(proof->a, r);
		ec_set_infty(proof->b);

		ec_write_bin(serialized, RLC_EC_SIZE_COMPRESSED, proof->a, 1);
		ec_write_bin(serialized + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, h, 1);
		md_map(hash, serialized, SERIALIZED_LEN);

		if (8 * RLC_MD_LEN > bn_bits(q)) {
			unsigned len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(e, hash, len);
			bn_rsh(e, e, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(e, hash, RLC_MD_LEN);
		}
		bn_mod(e, e, q);

		bn_mul(proof->z, e, w);
		bn_mod(proof->z, proof->z, q);
		bn_add(proof->z, proof->z, r);
		bn_mod(proof->z, proof->z, q);
	} CATCH_ANY {
		result_status = RLC_ERR;
	} FINALLY {
		bn_free(e);
		bn_free(r);
		bn_free(q);
	}

	return result_status;
}

int zk_dlog_verify(const zk_proof_t proof, const ec_t h) {
	int result_status = RLC_ERR;

	const unsigned SERIALIZED_LEN = 2 * RLC_EC_SIZE_COMPRESSED;
	uint8_t serialized[SERIALIZED_LEN];
	uint8_t hash[RLC_MD_LEN];
	
	bn_t e, q;
	ec_t g_to_the_z;
	ec_t h_to_the_e;
	ec_t a_times_h_to_the_e;

	bn_null(e);
	bn_null(q);

	ec_null(g_to_the_z);
	ec_null(h_to_the_e);
	ec_null(a_times_h_to_the_e);

	TRY {
		bn_new(e);
		bn_new(q);

		ec_new(g_to_the_z);
		ec_new(h_to_the_e);
		ec_new(a_times_h_to_the_e);

		ec_curve_get_ord(q);

		ec_write_bin(serialized, RLC_EC_SIZE_COMPRESSED, proof->a, 1);
		ec_write_bin(serialized + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, h, 1);
		md_map(hash, serialized, SERIALIZED_LEN);

		if (8 * RLC_MD_LEN > bn_bits(q)) {
			unsigned len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(e, hash, len);
			bn_rsh(e, e, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(e, hash, RLC_MD_LEN);
		}
		bn_mod(e, e, q);

		ec_mul_gen(g_to_the_z, proof->z);
		ec_mul(h_to_the_e, h, e);
		ec_add(a_times_h_to_the_e, proof->a, h_to_the_e);

		if (ec_cmp(g_to_the_z, a_times_h_to_the_e) == RLC_EQ) {
			result_status = RLC_OK;
		}
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(e);
		bn_free(q);
		ec_free(g_to_the_z);
		ec_free(h_to_the_e);
		ec_free(a_times_h_to_the_e);
	}

	return result_status;
}

int zk_dhtuple_prove(zk_proof_t proof, const ec_t h, const ec_t u, const ec_t v, const bn_t w) {
	int result_status = RLC_OK;
	
	const unsigned SERIALIZED_LEN = 4 * RLC_EC_SIZE_COMPRESSED;
	uint8_t serialized[SERIALIZED_LEN];
	uint8_t hash[RLC_MD_LEN];

	bn_t e, r, q;

	bn_null(e);
	bn_null(r);
	bn_null(q);

	TRY {
		bn_new(e);
		bn_new(r);
		bn_new(q);

		ec_curve_get_ord(q);
		bn_rand_mod(r, q);

		ec_mul_gen(proof->a, r);
		ec_mul(proof->b, h, r);

		ec_write_bin(serialized, RLC_EC_SIZE_COMPRESSED, proof->a, 1);
		ec_write_bin(serialized + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, proof->b, 1);
		ec_write_bin(serialized + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, u, 1);
		ec_write_bin(serialized + (3 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, v, 1);
		md_map(hash, serialized, SERIALIZED_LEN);

		if (8 * RLC_MD_LEN > bn_bits(q)) {
			unsigned len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(e, hash, len);
			bn_rsh(e, e, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(e, hash, RLC_MD_LEN);
		}
		bn_mod(e, e, q);

		bn_mul(proof->z, e, w);
		bn_mod(proof->z, proof->z, q);
		bn_add(proof->z, proof->z, r);
		bn_mod(proof->z, proof->z, q);
	} CATCH_ANY {
		result_status = RLC_ERR;
	} FINALLY {
		bn_free(e);
		bn_free(r);
		bn_free(q);
	}

	return result_status;
}

int zk_dhtuple_verify(const zk_proof_t proof, const ec_t h, const ec_t u, const ec_t v) {
	int result_status = RLC_ERR;

	const unsigned SERIALIZED_LEN = 4 * RLC_EC_SIZE_COMPRESSED;
	uint8_t serialized[SERIALIZED_LEN];
	uint8_t hash[RLC_MD_LEN];
	
	bn_t e, q;
	ec_t g_to_the_z;
	ec_t u_to_the_e;
	ec_t a_times_u_to_the_e;
	ec_t h_to_the_z;
	ec_t v_to_the_e;
	ec_t b_times_v_to_the_e;

	bn_null(e);
	bn_null(q);

	ec_null(g_to_the_z);
	ec_null(u_to_the_e);
	ec_null(a_times_u_to_the_e);
	ec_null(h_to_the_z);
	ec_null(v_to_the_e);
	ec_null(b_times_v_to_the_e);

	TRY {
		bn_new(e);
		bn_new(q);

		ec_new(g_to_the_z);
		ec_new(u_to_the_e);
		ec_new(a_times_u_to_the_e);
		ec_new(h_to_the_z);
		ec_new(v_to_the_e);
		ec_new(b_times_v_to_the_e);

		ec_curve_get_ord(q);

		ec_write_bin(serialized, RLC_EC_SIZE_COMPRESSED, proof->a, 1);
		ec_write_bin(serialized + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, proof->b, 1);
		ec_write_bin(serialized + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, u, 1);
		ec_write_bin(serialized + (3 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, v, 1);
		md_map(hash, serialized, SERIALIZED_LEN);

		if (8 * RLC_MD_LEN > bn_bits(q)) {
			unsigned len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(e, hash, len);
			bn_rsh(e, e, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(e, hash, RLC_MD_LEN);
		}
		bn_mod(e, e, q);

		ec_mul_gen(g_to_the_z, proof->z);
		ec_mul(u_to_the_e, u, e);
		ec_add(a_times_u_to_the_e, proof->a, u_to_the_e);

		ec_mul(h_to_the_z, h, proof->z);
		ec_mul(v_to_the_e, v, e);
		ec_add(b_times_v_to_the_e, proof->b, v_to_the_e);

		if (ec_cmp(g_to_the_z, a_times_u_to_the_e) == RLC_EQ
		&&	ec_cmp(h_to_the_z, b_times_v_to_the_e) == RLC_EQ) {
			result_status = RLC_OK;
		}
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(e);
		bn_free(q);
		ec_free(g_to_the_z);
		ec_free(u_to_the_e);
		ec_free(a_times_u_to_the_e);
		ec_free(h_to_the_z);
		ec_free(v_to_the_e);
		ec_free(b_times_v_to_the_e);
	}

	return result_status;
}