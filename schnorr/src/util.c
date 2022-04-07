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

	// Initialize the pairing and elliptic curve groups.
	if (pc_param_set_any() != RLC_OK) {
		core_clean();
		return RLC_ERR;
	}

	if (ec_param_set_any() != RLC_OK) {
		core_clean();
		return RLC_ERR;
	}

	// Set the secp256k1 curve, which is used in Bitcoin.
	ep_param_set(SECG_K256);

	// Initialize the PARI stack (in bytes) and randomness.
	pari_init(10000000, 2);
	setrand(getwalltime());
	
	return RLC_OK;
}

int clean() {
	pari_close();
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
		RLC_THROW(ERR_NO_MEMORY);
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

	GEN cl_sk_tumbler, cl_pk_tumbler;

	bn_t q, x, y, ec_sk_alice, ec_sk_bob, ec_sk_tumbler;
	ec_t ec_pk_alice, ec_pk_bob, ec_pk_tumbler;

	ps_secret_key_t ps_sk_tumbler;
	ps_public_key_t ps_pk_tumbler;

	uint8_t serialized_ec_sk[RLC_BN_SIZE];
	uint8_t serialized_ec_pk[RLC_EC_SIZE_COMPRESSED];
	uint8_t serialized_g1[RLC_G1_SIZE_COMPRESSED];
	uint8_t serialized_g2[RLC_G2_SIZE_COMPRESSED];

	bn_null(q);
	bn_null(x);
	bn_null(y);
	bn_null(ec_sk_alice);
	bn_null(ec_sk_bob);
	bn_null(ec_sk_tumbler);

	ec_null(ec_pk_alice);
	ec_null(ec_pk_bob);
	ec_null(ec_pk_tumbler);

	ps_secret_key_null(ps_sk_tumbler);
	ps_public_key_null(ps_pk_tumbler);

	RLC_TRY {
		bn_new(q);
		bn_new(x);
		bn_new(y);
		bn_new(ec_sk_alice);
		bn_new(ec_sk_bob);
		bn_new(ec_sk_tumbler);

		ec_new(ec_pk_alice);
		ec_new(ec_pk_bob);
		ec_new(ec_pk_tumbler);

		ps_secret_key_new(ps_sk_tumbler);
		ps_public_key_new(ps_pk_tumbler);

		// Compute EC secret/public key pairs.
		ec_curve_get_ord(q);
		bn_rand_mod(ec_sk_alice, q);
		bn_rand_mod(ec_sk_bob, q);
		bn_rand_mod(ec_sk_tumbler, q);

		ec_mul_gen(ec_pk_alice, ec_sk_alice);
		ec_mul_gen(ec_pk_bob, ec_sk_bob);
		ec_mul_gen(ec_pk_tumbler, ec_sk_tumbler);

		// Compute CL encryption secret/public key pair for the tumbler.
		cl_sk_tumbler = randomi(params->bound);
		cl_pk_tumbler = nupow(params->g_q, cl_sk_tumbler, NULL);

		// Compute PS secret/public key pair for the tumbler.
		pc_get_ord(q);
		bn_rand_mod(x, q);
		bn_rand_mod(y, q);

		g1_mul_gen(ps_sk_tumbler->X_1, x);
		g1_mul_gen(ps_pk_tumbler->Y_1, y);
		g2_mul_gen(ps_pk_tumbler->X_2, x);
		g2_mul_gen(ps_pk_tumbler->Y_2, y);

		// Create the filenames for the keys.
		unsigned alice_key_file_length = strlen(ALICE_KEY_FILE_PREFIX) + strlen(KEY_FILE_EXTENSION) + 10;
		char *alice_key_file_name = malloc(alice_key_file_length);
		
		unsigned bob_key_file_length = strlen(BOB_KEY_FILE_PREFIX) + strlen(KEY_FILE_EXTENSION) + 10;
		char *bob_key_file_name = malloc(bob_key_file_length);
		
		unsigned tumbler_key_file_length = strlen(TUMBLER_KEY_FILE_PREFIX) + strlen(KEY_FILE_EXTENSION) + 10;
		char *tumbler_key_file_name = malloc(tumbler_key_file_length);
		
		if (alice_key_file_name == NULL || bob_key_file_name == NULL || tumbler_key_file_name == NULL) {
			RLC_THROW(ERR_CAUGHT);
		}

		snprintf(alice_key_file_name, alice_key_file_length, "../keys/%s.%s", ALICE_KEY_FILE_PREFIX, KEY_FILE_EXTENSION);
		snprintf(bob_key_file_name, bob_key_file_length, "../keys/%s.%s", BOB_KEY_FILE_PREFIX, KEY_FILE_EXTENSION);
		snprintf(tumbler_key_file_name, tumbler_key_file_length, "../keys/%s.%s", TUMBLER_KEY_FILE_PREFIX, KEY_FILE_EXTENSION);

		// Write Alice's keys to a file.
		FILE *file = fopen(alice_key_file_name, "wb");
		if (file == NULL) {
			RLC_THROW(ERR_NO_FILE);
		}

		bn_write_bin(serialized_ec_sk, RLC_BN_SIZE, ec_sk_alice);
		fwrite(serialized_ec_sk, sizeof(uint8_t), RLC_BN_SIZE, file);
		ec_write_bin(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED, ec_pk_alice, 1);
		fwrite(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file);

		memzero(serialized_ec_sk, RLC_BN_SIZE);
		memzero(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);

		fclose(file);

		// Write Bob's keys to a file.
		file = fopen(bob_key_file_name, "wb");
		if (file == NULL) {
			RLC_THROW(ERR_NO_FILE);
		}

		bn_write_bin(serialized_ec_sk, RLC_BN_SIZE, ec_sk_bob);
		fwrite(serialized_ec_sk, sizeof(uint8_t), RLC_BN_SIZE, file);
		ec_write_bin(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED, ec_pk_bob, 1);
		fwrite(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file);

		memzero(serialized_ec_sk, RLC_BN_SIZE);
		memzero(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);

		fclose(file);

		// Write Tumbler's keys to a file.
		file = fopen(tumbler_key_file_name, "wb");
		if (file == NULL) {
			RLC_THROW(ERR_NO_FILE);
		}

		// Tumbler has two EC public keys, one with Alice and one with Bob.
		bn_write_bin(serialized_ec_sk, RLC_BN_SIZE, ec_sk_tumbler);
		fwrite(serialized_ec_sk, sizeof(uint8_t), RLC_BN_SIZE, file);
		ec_write_bin(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED, ec_pk_tumbler, 1);
		fwrite(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file);

		fwrite(GENtostr_raw(cl_sk_tumbler), sizeof(char), RLC_CL_SECRET_KEY_SIZE, file);
    	fwrite(GENtostr_raw(cl_pk_tumbler), sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file);

		g1_write_bin(serialized_g1, RLC_G1_SIZE_COMPRESSED, ps_sk_tumbler->X_1, 1);
		fwrite(serialized_g1, sizeof(uint8_t), RLC_G1_SIZE_COMPRESSED, file);
		memzero(serialized_g1, RLC_G1_SIZE_COMPRESSED);
		g1_write_bin(serialized_g1, RLC_G1_SIZE_COMPRESSED, ps_pk_tumbler->Y_1, 1);
		fwrite(serialized_g1, sizeof(uint8_t), RLC_G1_SIZE_COMPRESSED, file);
		g2_write_bin(serialized_g2, RLC_G2_SIZE_COMPRESSED, ps_pk_tumbler->X_2, 1);
		fwrite(serialized_g2, sizeof(uint8_t), RLC_G2_SIZE_COMPRESSED, file);
		memzero(serialized_g2, RLC_G2_SIZE_COMPRESSED);
		g2_write_bin(serialized_g2, RLC_G2_SIZE_COMPRESSED, ps_pk_tumbler->Y_2, 1);
		fwrite(serialized_g2, sizeof(uint8_t), RLC_G2_SIZE_COMPRESSED, file);

		fclose(file);

		free(alice_key_file_name);
		free(bob_key_file_name);
		free(tumbler_key_file_name);
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
		bn_free(q);
		bn_free(x);
		bn_free(y);
		bn_free(ec_sk_alice);
		bn_free(ec_sk_bob);
		bn_free(ec_sk_tumbler);
		
		ec_free(ec_pk_alice);
		ec_free(ec_pk_bob);
		ec_free(ec_pk_tumbler);

		ps_secret_key_free(ps_sk_tumbler);
		ps_public_key_free(ps_pk_tumbler);
	}

	return result_status;
}

int read_keys_from_file_alice_bob(const char *name,
								  ec_secret_key_t ec_sk,
								  ec_public_key_t ec_pk,
								  ec_public_key_t tumbler_ec_pk,
								  ps_public_key_t tumbler_ps_pk,
								  cl_public_key_t tumbler_cl_pk) {
	int result_status = RLC_OK;

	uint8_t serialized_ec_sk[RLC_BN_SIZE];
	uint8_t serialized_ec_pk[RLC_EC_SIZE_COMPRESSED];
	uint8_t serialized_g1[RLC_G1_SIZE_COMPRESSED];
	uint8_t serialized_g2[RLC_G2_SIZE_COMPRESSED];
	char serialized_cl_pk[RLC_CL_PUBLIC_KEY_SIZE];

	RLC_TRY {
		unsigned key_file_length = strlen(name) + strlen(KEY_FILE_EXTENSION) + 10;
		char *key_file_name = malloc(key_file_length);
		
		if (key_file_name == NULL) {
			RLC_THROW(ERR_CAUGHT);
		}

		snprintf(key_file_name, key_file_length, "../keys/%s.%s", name, KEY_FILE_EXTENSION);
		
		FILE *file = fopen(key_file_name, "rb");
		if (file == NULL) {
			RLC_THROW(ERR_NO_FILE);
		}

		if (fread(serialized_ec_sk, sizeof(uint8_t), RLC_BN_SIZE, file) != RLC_BN_SIZE) {
			RLC_THROW(ERR_NO_READ);
		}
		bn_read_bin(ec_sk->sk, serialized_ec_sk, RLC_BN_SIZE);

		if (fread(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file) != RLC_EC_SIZE_COMPRESSED) {
			RLC_THROW(ERR_NO_READ);
		}
		ec_read_bin(ec_pk->pk, serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);
		memzero(serialized_ec_sk, RLC_EC_SIZE_COMPRESSED);

		fclose(file);
		free(key_file_name);

		key_file_length = strlen(TUMBLER_KEY_FILE_PREFIX) + strlen(KEY_FILE_EXTENSION) + 10;
		key_file_name = malloc(key_file_length);
		
		if (key_file_name == NULL) {
			RLC_THROW(ERR_CAUGHT);
		}

		snprintf(key_file_name, key_file_length, "../keys/%s.%s", TUMBLER_KEY_FILE_PREFIX, KEY_FILE_EXTENSION);
		
		file = fopen(key_file_name, "rb");
		if (file == NULL) {
			RLC_THROW(ERR_NO_FILE);
		}

		fseek(file, RLC_BN_SIZE, SEEK_SET);
		if (fread(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file) != RLC_EC_SIZE_COMPRESSED) {
			RLC_THROW(ERR_NO_READ);
		}
		ec_read_bin(tumbler_ec_pk->pk, serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);

		fseek(file, RLC_CL_SECRET_KEY_SIZE, SEEK_CUR);
		if (fread(serialized_cl_pk, sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file) != RLC_CL_PUBLIC_KEY_SIZE) {
			RLC_THROW(ERR_NO_READ);
		}
		tumbler_cl_pk->pk = gp_read_str(serialized_cl_pk);

		fseek(file, RLC_G1_SIZE_COMPRESSED, SEEK_CUR);
		if (fread(serialized_g1, sizeof(uint8_t), RLC_G1_SIZE_COMPRESSED, file) != RLC_G1_SIZE_COMPRESSED) {
			RLC_THROW(ERR_NO_READ);
		}
		g1_read_bin(tumbler_ps_pk->Y_1, serialized_g1, RLC_G1_SIZE_COMPRESSED);

		if (fread(serialized_g2, sizeof(uint8_t), RLC_G2_SIZE_COMPRESSED, file) != RLC_G2_SIZE_COMPRESSED) {
			RLC_THROW(ERR_NO_READ);
		}
		g2_read_bin(tumbler_ps_pk->X_2, serialized_g2, RLC_G2_SIZE_COMPRESSED);
		memzero(serialized_g2, RLC_G2_SIZE_COMPRESSED);

		if (fread(serialized_g2, sizeof(uint8_t), RLC_G2_SIZE_COMPRESSED, file) != RLC_G2_SIZE_COMPRESSED) {
			RLC_THROW(ERR_NO_READ);
		}
		g2_read_bin(tumbler_ps_pk->Y_2, serialized_g2, RLC_G2_SIZE_COMPRESSED);

		fclose(file);
		free(key_file_name);
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	}

	return result_status;
}

int read_keys_from_file_tumbler(ec_secret_key_t tumbler_ec_sk,
								ec_public_key_t tumbler_ec_pk,
								ps_secret_key_t tumbler_ps_sk,
								ps_public_key_t tumbler_ps_pk,
								cl_secret_key_t tumbler_cl_sk,
								cl_public_key_t tumbler_cl_pk,
								ec_public_key_t alice_ec_pk,
								ec_public_key_t bob_ec_pk) {
	int result_status = RLC_OK;

	uint8_t serialized_ec_sk[RLC_BN_SIZE];
	uint8_t serialized_ec_pk[RLC_EC_SIZE_COMPRESSED];
	char serialized_cl_sk[RLC_CL_SECRET_KEY_SIZE];
	char serialized_cl_pk[RLC_CL_PUBLIC_KEY_SIZE];
	uint8_t serialized_g1[RLC_G1_SIZE_COMPRESSED];
	uint8_t serialized_g2[RLC_G2_SIZE_COMPRESSED];

	RLC_TRY {
		unsigned key_file_length = strlen(TUMBLER_KEY_FILE_PREFIX) + strlen(KEY_FILE_EXTENSION) + 10;
		char *key_file_name = malloc(key_file_length);
		
		if (key_file_name == NULL) {
			RLC_THROW(ERR_CAUGHT);
		}

		snprintf(key_file_name, key_file_length, "../keys/%s.%s", TUMBLER_KEY_FILE_PREFIX, KEY_FILE_EXTENSION);
		
		FILE *file = fopen(key_file_name, "rb");
		if (file == NULL) {
			RLC_THROW(ERR_NO_FILE);
		}

		if (fread(serialized_ec_sk, sizeof(uint8_t), RLC_BN_SIZE, file) != RLC_BN_SIZE) {
			RLC_THROW(ERR_NO_READ);
		}
		bn_read_bin(tumbler_ec_sk->sk, serialized_ec_sk, RLC_BN_SIZE);

		if (fread(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file) != RLC_EC_SIZE_COMPRESSED) {
			RLC_THROW(ERR_NO_READ);
		}
		ec_read_bin(tumbler_ec_pk->pk, serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);
		memzero(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);
		
		if (fread(serialized_cl_sk, sizeof(char), RLC_CL_SECRET_KEY_SIZE, file) != RLC_CL_SECRET_KEY_SIZE) {
			RLC_THROW(ERR_NO_READ);
		}
		tumbler_cl_sk->sk = gp_read_str(serialized_cl_sk);
		
		if (fread(serialized_cl_pk, sizeof(char), RLC_CL_PUBLIC_KEY_SIZE, file) != RLC_CL_PUBLIC_KEY_SIZE) {
			RLC_THROW(ERR_NO_READ);
		}
		tumbler_cl_pk->pk = gp_read_str(serialized_cl_pk);

		if (fread(serialized_g1, sizeof(uint8_t), RLC_G1_SIZE_COMPRESSED, file) != RLC_G1_SIZE_COMPRESSED) {
			RLC_THROW(ERR_NO_READ);
		}
		g1_read_bin(tumbler_ps_sk->X_1, serialized_g1, RLC_G1_SIZE_COMPRESSED);
		memzero(serialized_g1, RLC_G1_SIZE_COMPRESSED);

		if (fread(serialized_g1, sizeof(uint8_t), RLC_G1_SIZE_COMPRESSED, file) != RLC_G1_SIZE_COMPRESSED) {
			RLC_THROW(ERR_NO_READ);
		}
		g1_read_bin(tumbler_ps_pk->Y_1, serialized_g1, RLC_G1_SIZE_COMPRESSED);

		if (fread(serialized_g2, sizeof(uint8_t), RLC_G2_SIZE_COMPRESSED, file) != RLC_G2_SIZE_COMPRESSED) {
			RLC_THROW(ERR_NO_READ);
		}
		g2_read_bin(tumbler_ps_pk->X_2, serialized_g2, RLC_G2_SIZE_COMPRESSED);
		memzero(serialized_g2, RLC_G2_SIZE_COMPRESSED);

		if (fread(serialized_g2, sizeof(uint8_t), RLC_G2_SIZE_COMPRESSED, file) != RLC_G2_SIZE_COMPRESSED) {
			RLC_THROW(ERR_NO_READ);
		}
		g2_read_bin(tumbler_ps_pk->Y_2, serialized_g2, RLC_G2_SIZE_COMPRESSED);

		fclose(file);
		free(key_file_name);

		key_file_length = strlen(ALICE_KEY_FILE_PREFIX) + strlen(KEY_FILE_EXTENSION) + 10;
		key_file_name = malloc(key_file_length);
		if (key_file_name == NULL) {
			RLC_THROW(ERR_CAUGHT);
		}

		snprintf(key_file_name, key_file_length, "../keys/%s.%s", ALICE_KEY_FILE_PREFIX, KEY_FILE_EXTENSION);
		
		file = fopen(key_file_name, "rb");
		if (file == NULL) {
			RLC_THROW(ERR_NO_FILE);
		}

		fseek(file, RLC_BN_SIZE, SEEK_SET);
		if (fread(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file) != RLC_EC_SIZE_COMPRESSED) {
			RLC_THROW(ERR_NO_READ);
		}
		ec_read_bin(alice_ec_pk->pk, serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);
		memzero(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);

		fclose(file);
		free(key_file_name);

		key_file_length = strlen(BOB_KEY_FILE_PREFIX) + strlen(KEY_FILE_EXTENSION) + 10;
		key_file_name = malloc(key_file_length);
		if (key_file_name == NULL) {
			RLC_THROW(ERR_CAUGHT);
		}

		snprintf(key_file_name, key_file_length, "../keys/%s.%s", BOB_KEY_FILE_PREFIX, KEY_FILE_EXTENSION);
		
		file = fopen(key_file_name, "rb");
		if (file == NULL) {
			RLC_THROW(ERR_NO_FILE);
		}

		fseek(file, RLC_BN_SIZE, SEEK_SET);
		if (fread(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file) != RLC_EC_SIZE_COMPRESSED) {
			RLC_THROW(ERR_NO_READ);
		}
		ec_read_bin(bob_ec_pk->pk, serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);
		memzero(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);

		fclose(file);
		free(key_file_name);
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	}

	return result_status;
}

int generate_cl_params(cl_params_t params) {
	int result_status = RLC_OK;

	RLC_TRY {
		if (params == NULL) {
			RLC_THROW(ERR_CAUGHT);
		}

		// Parameters generated using SageMath script.
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
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	}

	return result_status;
}

int cl_enc(cl_ciphertext_t ciphertext,
					 const GEN plaintext,
					 const cl_public_key_t public_key,
					 const cl_params_t params) {
  int result_status = RLC_OK;

  RLC_TRY {
    ciphertext->r = randomi(params->bound);
    ciphertext->c1 = nupow(params->g_q, ciphertext->r, NULL);

    GEN L = Fp_inv(plaintext, params->q);
    if (!mpodd(L)) {
      	L = subii(L, params->q);
    }

		// f^plaintext = (q^2, Lq, (L - Delta_k) / 4)
    GEN fm = qfi(sqri(params->q), mulii(L, params->q), shifti(subii(sqri(L), params->Delta_K), -2));
    ciphertext->c2 = gmul(nupow(public_key->pk, ciphertext->r, NULL), fm);
  } RLC_CATCH_ANY {
    	result_status = RLC_ERR;
  }

  return result_status;
}

int cl_dec(GEN *plaintext,
					 const cl_ciphertext_t ciphertext,
					 const cl_secret_key_t secret_key,
					 const cl_params_t params) {
  int result_status = RLC_OK;

  RLC_TRY {
		// c2 * (c1^sk)^(-1)
    GEN fm = gmul(ciphertext->c2, ginv(nupow(ciphertext->c1, secret_key->sk, NULL)));
    GEN L = diviiexact(gel(fm, 2), params->q);
    *plaintext = Fp_inv(L, params->q);
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  }

  return result_status;
}

int adaptor_schnorr_sign(schnorr_signature_t signature,
												 uint8_t *msg,
												 size_t len,
												 const ec_t Y,
												 const ec_secret_key_t secret_key) {
	int result_status = RLC_OK;

	bn_t q, k, x, r;
	ec_t R;
	uint8_t hash[RLC_MD_LEN];
	uint8_t *m = RLC_ALLOCA(uint8_t, len + RLC_FC_BYTES);

	bn_null(q);
	bn_null(k);
	bn_null(x);
	bn_null(r);
	ec_null(R);

	RLC_TRY {
		bn_new(q);
		bn_new(k);
		bn_new(x);
		bn_new(r);
		ec_new(R);

		if (m == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}

		ec_curve_get_ord(q);
		do {
			bn_rand_mod(k, q);
			ec_mul_gen(R, k);
			ec_add(R, R, Y);
			ec_norm(R, R);
			ec_get_x(x, R);
			bn_mod(r, x, q);
		} while (bn_is_zero(r));

		memcpy(m, msg, len);
		bn_write_bin(m + len, RLC_FC_BYTES, r);
		md_map(hash, m, len + RLC_FC_BYTES);

		if (8 * RLC_MD_LEN > bn_bits(q)) {
			len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(signature->e, hash, len);
			bn_rsh(signature->e, signature->e, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(signature->e, hash, RLC_MD_LEN);
		}

		bn_mod(signature->e, signature->e, q);

		bn_mul(signature->s, secret_key->sk, signature->e);
		bn_mod(signature->s, signature->s, q);
		bn_sub(signature->s, q, signature->s);
		bn_add(signature->s, signature->s, k);
		bn_mod(signature->s, signature->s, q);
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
		bn_free(q);
		bn_free(k);
		bn_free(x);
		bn_free(r);
		ec_free(R);
		RLC_FREE(m);
	}

	return result_status;
}

int adaptor_schnorr_preverify(schnorr_signature_t signature,
															uint8_t *msg,
															size_t len,
															const ec_t Y,
															const ec_public_key_t public_key) {
	int result_status = 0;

	bn_t q, ev, rv;
	ec_t R;
	uint8_t hash[RLC_MD_LEN];
	uint8_t *m = RLC_ALLOCA(uint8_t, len + RLC_FC_BYTES);

	bn_null(q);
	bn_null(ev);
	bn_null(rv);
	ec_null(R);

	RLC_TRY {
		bn_new(q);
		bn_new(ev);
		bn_new(rv);
		ec_new(R);

		if (m == NULL) {
			RLC_THROW(ERR_NO_VALID);
		}
		
		ec_curve_get_ord(q);
		if (bn_sign(signature->e) == RLC_POS && bn_sign(signature->s) == RLC_POS && !bn_is_zero(signature->s)) {
			if (bn_cmp(signature->e, q) == RLC_LT && bn_cmp(signature->s, q) == RLC_LT) {
				ec_mul_sim_gen(R, signature->s, public_key->pk, signature->e);
				ec_add(R, R, Y);
				ec_norm(R, R);
				ec_get_x(rv, R);

				bn_mod(rv, rv, q);

				memcpy(m, msg, len);
				bn_write_bin(m + len, RLC_FC_BYTES, rv);
				md_map(hash, m, len + RLC_FC_BYTES);

				if (8 * RLC_MD_LEN > bn_bits(q)) {
					len = RLC_CEIL(bn_bits(q), 8);
					bn_read_bin(ev, hash, len);
					bn_rsh(ev, ev, 8 * RLC_MD_LEN - bn_bits(q));
				} else {
					bn_read_bin(ev, hash, RLC_MD_LEN);
				}

				bn_mod(ev, ev, q);

				result_status = dv_cmp_const(ev->dp, signature->e->dp, RLC_MIN(ev->used, signature->e->used));
				result_status = (result_status == RLC_NE ? 0 : 1);

				if (ev->used != signature->e->used) {
					result_status = 0;
				}
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(q);
		bn_free(ev);
		bn_free(rv);
		ec_free(R);
		RLC_FREE(m);
	}

	return result_status;
}

int ps_blind_sign(ps_signature_t signature,
									const pedersen_com_t com, 
									const ps_secret_key_t secret_key) {
	int result_status = RLC_OK;

	bn_t q, u;
	bn_null(q);
	bn_null(u);

	g1_t g1_gen, x_1_times_c;
	g1_null(g1_gen);
	g1_null(x_1_times_c);

	RLC_TRY {
		bn_new(q);
		bn_new(u);
		g1_new(g1_gen);
		g1_new(x_1_times_c);

		g1_get_gen(g1_gen);
		g1_get_ord(q);
		bn_rand_mod(u, q);

		g1_mul(signature->sigma_1, g1_gen, u);
		g1_add(x_1_times_c, secret_key->X_1, com->c);
		g1_norm(x_1_times_c, x_1_times_c);
		g1_mul(signature->sigma_2, x_1_times_c, u);
	}
	RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
		bn_free(q);
		bn_free(u);
		g1_free(g1_gen);
		g1_free(x_1_times_c);
	}

	return result_status;
}

int ps_unblind(ps_signature_t signature,
							 const pedersen_decom_t decom) {
	int result_status = RLC_OK;

	bn_t q, x, r_inverse;
	bn_null(q);
	bn_null(x);
	bn_null(r_inverse);

	g1_t sigma_1_to_the_r_inverse;
	g1_null(sigma_1_to_the_r_inverse);

	RLC_TRY {
		bn_new(q);
		bn_new(x);
		bn_new(r_inverse);
		g1_new(sigma_1_to_the_r_inverse);

		g1_get_ord(q);

		bn_gcd_ext(x, r_inverse, NULL, decom->r, q);
    if (bn_sign(r_inverse) == RLC_NEG) {
      bn_add(r_inverse, r_inverse, q);
    }

		g1_mul(sigma_1_to_the_r_inverse, signature->sigma_1, r_inverse);
		g1_add(signature->sigma_2, signature->sigma_2, sigma_1_to_the_r_inverse);
		g1_norm(signature->sigma_2, signature->sigma_2);
	}
	RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
		bn_free(q);
		bn_free(x);
		bn_free(r_inverse);
		g1_free(sigma_1_to_the_r_inverse);
	}

	return result_status;
}

int ps_verify(const ps_signature_t signature,
							bn_t message,
						 	const ps_public_key_t public_key) {
	int result_status = RLC_ERR;

	g2_t g2_gen, y_2_to_the_m;
	g2_t x_2_times_y_2_to_the_m;
	gt_t pairing_1, pairing_2;

	g2_null(g2_gen);
	g2_null(y_2_to_the_m);
	g2_null(x_2_times_y_2_to_the_m);
	gt_null(pairing_1);
	gt_null(pairing_2);

	RLC_TRY {
		g2_new(g2_gen);
		g2_new(y_2_to_the_m);
		g2_new(x_2_times_y_2_to_the_m);
		gt_new(pairing_1);
		gt_new(pairing_2);

		g2_get_gen(g2_gen);

		g2_mul(y_2_to_the_m, public_key->Y_2, message);
		g2_add(x_2_times_y_2_to_the_m, public_key->X_2, y_2_to_the_m);
		g2_norm(x_2_times_y_2_to_the_m, x_2_times_y_2_to_the_m);

		pc_map(pairing_1, signature->sigma_1, x_2_times_y_2_to_the_m);
		pc_map(pairing_2, signature->sigma_2, g2_gen);
		if (gt_cmp(pairing_1, pairing_2) == RLC_EQ) {
			result_status = RLC_OK;
		}
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
		g2_free(g2_gen);
		g2_free(y_2_to_the_m);
		g2_free(x_2_times_y_2_to_the_m);
		gt_free(pairing_1);
		gt_free(pairing_2);
	}

	return result_status;
}

int pedersen_commit(pedersen_com_t com,
										pedersen_decom_t decom,
										g1_t h,
										bn_t x) {
	int result_status = RLC_OK;

	bn_t q;
	bn_null(q);
	bn_null(r);

	g1_t g1_gen, g1_to_the_r;
	g1_t h_to_the_x;
	g1_null(g1_gen);
	g1_null(g1_to_the_r);
	g1_null(h_to_the_x);

	RLC_TRY {
		bn_new(q);
		g1_new(g1_gen);
		g1_new(g1_to_the_r);
		g1_new(h_to_the_x);

		g1_get_gen(g1_gen);
		g1_get_ord(q);
		bn_rand_mod(decom->r, q);
		bn_copy(decom->m, x);

		g1_mul(g1_to_the_r, g1_gen, decom->r);
		g1_mul(h_to_the_x, h, x);
		g1_add(com->c, g1_to_the_r, h_to_the_x);
		g1_norm(com->c, com->c);
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
		bn_free(q);
		g1_free(g1_gen);
		g1_free(g1_to_the_r);
		g1_free(h_to_the_x);
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

	RLC_TRY {
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
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
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

	RLC_TRY {
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
	}	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(c_prime);
		bn_free(q);
	}

	return result_status;
}

int zk_pedersen_com_prove(pedersen_com_zk_proof_t proof,
													g1_t h,
													const pedersen_com_t com,
													const pedersen_decom_t decom) {
	int result_status = RLC_OK;
	
	const unsigned SERIALIZED_LEN = 2 * RLC_G1_SIZE_COMPRESSED;
	uint8_t serialized[SERIALIZED_LEN];
	uint8_t hash[RLC_MD_LEN];

	bn_t q, k, s;
	bn_null(q);
	bn_null(k);
	bn_null(s);

	pedersen_decom_t decom_prime;
	pedersen_decom_null(decom_prime);

	RLC_TRY {
		bn_new(q);
		bn_new(k);
		bn_new(s);
		pedersen_decom_new(decom_prime);

		g1_get_ord(q);
		if (pedersen_commit(proof->c, decom_prime, h, s) != RLC_OK) {
			RLC_THROW(ERR_CAUGHT);
		}

		g1_write_bin(serialized, RLC_G1_SIZE_COMPRESSED, com->c, 1);
		g1_write_bin(serialized + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED, proof->c->c, 1);
		md_map(hash, serialized, SERIALIZED_LEN);

		if (8 * RLC_MD_LEN > bn_bits(q)) {
			unsigned len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(k, hash, len);
			bn_rsh(k, k, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(k, hash, RLC_MD_LEN);
		}
		bn_mod(k, k, q);

		bn_mul(proof->u, k, decom->r);
		bn_mod(proof->u, proof->u, q);
		bn_add(proof->u, proof->u, decom_prime->r);
		bn_mod(proof->u, proof->u, q);

		bn_mul(proof->v, k, decom->m);
		bn_mod(proof->v, proof->v, q);
		bn_add(proof->v, proof->v, s);
		bn_mod(proof->v, proof->v, q);
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
		bn_free(q);
		bn_free(k);
		bn_free(s);
		pedersen_decom_free(decom_prime);
	}

	return result_status;
}

int zk_pedersen_com_verify(const pedersen_com_zk_proof_t proof,
													 g1_t h,
													 const pedersen_com_t com) {
	int result_status = RLC_ERR;
	
	const unsigned SERIALIZED_LEN = 2 * RLC_G1_SIZE_COMPRESSED;
	uint8_t serialized[SERIALIZED_LEN];
	uint8_t hash[RLC_MD_LEN];

	bn_t q, k;
	g1_t g1_gen;
	g1_t g_to_the_u, h_to_the_v;
	g1_t g_to_the_u_times_h_to_the_v;
	g1_t com_to_the_k;
	g1_t com_prime_times_com_to_the_k;

	bn_null(q);
	bn_null(k);
	g1_null(g1_gen);
	g1_null(g_to_the_u);
	g1_null(h_to_the_v);
	g1_null(g_to_the_u_times_h_to_the_v);
	g1_null(com_to_the_k);
	g1_null(com_prime_times_com_to_the_k);

	RLC_TRY {
		bn_new(q);
		bn_new(k);
		g1_new(g1_gen);
		g1_new(g_to_the_u);
		g1_new(h_to_the_v);
		g1_new(g_to_the_u_times_h_to_the_v);
		g1_new(com_to_the_k);
		g1_new(com_prime_times_com_to_the_k);

		g1_get_gen(g1_gen);
		g1_get_ord(q);

		g1_write_bin(serialized, RLC_G1_SIZE_COMPRESSED, com->c, 1);
		g1_write_bin(serialized + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED, proof->c->c, 1);
		md_map(hash, serialized, SERIALIZED_LEN);

		if (8 * RLC_MD_LEN > bn_bits(q)) {
			unsigned len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(k, hash, len);
			bn_rsh(k, k, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(k, hash, RLC_MD_LEN);
		}
		bn_mod(k, k, q);

		g1_mul(g_to_the_u, g1_gen, proof->u);
		g1_mul(h_to_the_v, h, proof->v);
		g1_add(g_to_the_u_times_h_to_the_v, g_to_the_u, h_to_the_v);
		g1_norm(g_to_the_u_times_h_to_the_v, g_to_the_u_times_h_to_the_v);

		g1_mul(com_to_the_k, com->c, k);
		g1_add(com_prime_times_com_to_the_k, proof->c->c, com_to_the_k);
		g1_norm(com_prime_times_com_to_the_k, com_prime_times_com_to_the_k);

		if (g1_cmp(g_to_the_u_times_h_to_the_v, com_prime_times_com_to_the_k) == RLC_EQ) {
			result_status = RLC_OK;
		}
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
		bn_free(q);
		bn_free(k);
		g1_free(g1_gen);
		g1_free(g_to_the_u);
		g1_free(h_to_the_v);
		g1_free(g_to_the_u_times_h_to_the_v);
		g1_free(com_to_the_k);
		g1_free(com_prime_times_com_to_the_k);
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

	RLC_TRY {
		bn_new(rlc_k);
		bn_new(rlc_r2);
		bn_new(rlc_soundness);

		// [\tilde{A} \cdot C \cdot 2^40], we take C to be of size 2^40 as well.
		GEN soundness = shifti(gen_1, 40);
		GEN dist = mulii(params->bound, soundness);
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
		ec_mul_gen(proof->t2, rlc_r2);							// g^r_2
		proof->t3 = nupow(params->g_q, r1, NULL);				// g_q^r_1

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
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
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

	RLC_TRY {
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
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
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

	RLC_TRY {
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
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
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

	RLC_TRY {
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
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
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

	RLC_TRY {
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
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
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

	RLC_TRY {
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
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
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