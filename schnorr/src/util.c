#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "relic/relic.h"
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

long long timer(void) {
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

int generate_keys_and_write_to_file() {
	int result_status = RLC_OK;

	bn_t paillier_sk_alice, paillier_pk_alice;
	bn_t paillier_sk_bob, paillier_pk_bob;
	bn_t paillier_sk_tumbler, paillier_pk_tumbler;
	bn_t q, ec_sk_alice, ec_sk_bob, ec_sk_tumbler;
	ec_t ec_pk_alice, ec_pk_bob, ec_pk_tumbler;
	ec_t ec_pk_alice_tumbler, ec_pk_bob_tumbler;

	uint8_t serialized_ec_sk[RLC_BN_SIZE];
	uint8_t serialized_ec_pk[RLC_EC_SIZE_COMPRESSED];
	uint8_t serialized_paillier_sk[RLC_PAILLIER_KEY_SIZE];
	uint8_t serialized_paillier_pk[RLC_PAILLIER_KEY_SIZE];

	bn_null(paillier_sk_alice);
	bn_null(paillier_pk_alice);
	bn_null(paillier_sk_bob);
	bn_null(paillier_pk_bob);
	bn_null(paillier_sk_tumbler);
	bn_null(paillier_pk_tumbler);
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
		bn_new(paillier_sk_alice);
		bn_new(paillier_pk_alice);
		bn_new(paillier_sk_bob);
		bn_new(paillier_pk_bob);
		bn_new(paillier_sk_tumbler);
		bn_new(paillier_pk_tumbler);
		bn_new(q);
		bn_new(ec_sk_alice);
		bn_new(ec_sk_bob);
		bn_new(ec_sk_tumbler);

		ec_new(ec_pk_alice);
		ec_new(ec_pk_bob);
		ec_new(ec_pk_tumbler);
		ec_new(ec_pk_alice_tumbler);
		ec_new(ec_pk_bob_tumbler);

		// Compute Paillier public and secret keys.
		// Assumes that RLC_BN_BITS is set to 4096.
		if (cp_phpe_gen(paillier_pk_alice, paillier_sk_alice, RLC_BN_BITS / 2) != RLC_OK) {
			THROW(ERR_CAUGHT);
		}
		if (cp_phpe_gen(paillier_pk_bob, paillier_sk_bob, RLC_BN_BITS / 2) != RLC_OK) {
			THROW(ERR_CAUGHT);
		}
		if (cp_phpe_gen(paillier_pk_tumbler, paillier_sk_tumbler, RLC_BN_BITS / 2) != RLC_OK) {
			THROW(ERR_CAUGHT);
		}
		
		// Compute EC public and secret keys.
		ec_curve_get_ord(q);
		bn_rand_mod(ec_sk_alice, q);
		bn_rand_mod(ec_sk_bob, q);
		bn_rand_mod(ec_sk_tumbler, q);

		ec_mul_gen(ec_pk_alice, ec_sk_alice);
		ec_mul_gen(ec_pk_bob, ec_sk_bob);
		ec_mul_gen(ec_pk_tumbler, ec_sk_tumbler);

		ec_add(ec_pk_alice_tumbler, ec_pk_alice, ec_pk_tumbler);
		ec_norm(ec_pk_alice_tumbler, ec_pk_alice_tumbler);
		ec_add(ec_pk_bob_tumbler, ec_pk_bob, ec_pk_tumbler);
		ec_norm(ec_pk_bob_tumbler, ec_pk_bob_tumbler);

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
		bn_write_bin(serialized_paillier_sk, RLC_PAILLIER_KEY_SIZE, paillier_sk_alice);
		fwrite(serialized_paillier_sk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file);
		bn_write_bin(serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE, paillier_pk_alice);
		fwrite(serialized_paillier_pk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file);
		memzero(serialized_ec_sk, RLC_BN_SIZE);
		memzero(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);
		memzero(serialized_paillier_sk, RLC_PAILLIER_KEY_SIZE);
		memzero(serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE);

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
		bn_write_bin(serialized_paillier_sk, RLC_PAILLIER_KEY_SIZE, paillier_sk_bob);
		fwrite(serialized_paillier_sk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file);
		bn_write_bin(serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE, paillier_pk_bob);
		fwrite(serialized_paillier_pk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file);
		memzero(serialized_ec_sk, RLC_BN_SIZE);
		memzero(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);
		memzero(serialized_paillier_sk, RLC_PAILLIER_KEY_SIZE);
		memzero(serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE);

		fclose(file);

		// Write Tumbler's keys to a file.
		file = fopen(tumbler_key_file_name, "wb");
		if (file == NULL) {
			THROW(ERR_NO_FILE);
		}

		// NOTE: Tumbler has two EC public keys, one with Alice and one with Bob.
		bn_write_bin(serialized_ec_sk, RLC_BN_SIZE, ec_sk_tumbler);
		fwrite(serialized_ec_sk, sizeof(uint8_t), RLC_BN_SIZE, file);
		ec_write_bin(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED, ec_pk_alice_tumbler, 1);
		fwrite(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file);
		memzero(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED);
		ec_write_bin(serialized_ec_pk, RLC_EC_SIZE_COMPRESSED, ec_pk_bob_tumbler, 1);
		fwrite(serialized_ec_pk, sizeof(uint8_t), RLC_EC_SIZE_COMPRESSED, file);
		bn_write_bin(serialized_paillier_sk, RLC_PAILLIER_KEY_SIZE, paillier_sk_tumbler);
		fwrite(serialized_paillier_sk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file);
		bn_write_bin(serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE, paillier_pk_tumbler);
		fwrite(serialized_paillier_pk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file);
		memzero(serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE);
		bn_write_bin(serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE, paillier_pk_alice);
		fwrite(serialized_paillier_pk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file);
		memzero(serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE);
		bn_write_bin(serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE, paillier_pk_bob);
		fwrite(serialized_paillier_pk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file);

		fclose(file);

		free(alice_key_file_name);
		free(bob_key_file_name);
		free(tumbler_key_file_name);
	} CATCH_ANY {
		result_status = RLC_ERR;
	} FINALLY {
		bn_free(paillier_sk_alice);
		bn_free(paillier_pk_alice);
		bn_free(paillier_sk_bob);
		bn_free(paillier_pk_bob);
		bn_free(paillier_sk_tumbler);
		bn_free(paillier_pk_tumbler);
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
																	paillier_secret_key_t paillier_secret_key,
																	paillier_public_key_t paillier_public_key,
																	paillier_public_key_t tumbler_paillier_public_key) {
	int result_status = RLC_OK;

	uint8_t serialized_ec_sk[RLC_BN_SIZE];
	uint8_t serialized_ec_pk[RLC_EC_SIZE_COMPRESSED];
	uint8_t serialized_paillier_sk[RLC_PAILLIER_KEY_SIZE];
	uint8_t serialized_paillier_pk[RLC_PAILLIER_KEY_SIZE];

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

		if (fread(serialized_paillier_sk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file) != RLC_PAILLIER_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		bn_read_bin(paillier_secret_key->sk, serialized_paillier_sk, RLC_PAILLIER_KEY_SIZE);
		
		if (fread(serialized_paillier_pk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file) != RLC_PAILLIER_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		bn_read_bin(paillier_public_key->pk, serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE);
		memzero(serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE);

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

		fseek(file, RLC_BN_SIZE + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_PAILLIER_KEY_SIZE, SEEK_SET);
		if (fread(serialized_paillier_pk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file) != RLC_PAILLIER_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		bn_read_bin(tumbler_paillier_public_key->pk, serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE);

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
																paillier_secret_key_t paillier_secret_key,
																paillier_public_key_t paillier_public_key_tumbler,
																paillier_public_key_t paillier_public_key_alice,
																paillier_public_key_t paillier_public_key_bob) {
	int result_status = RLC_OK;

	uint8_t serialized_ec_sk[RLC_BN_SIZE];
	uint8_t serialized_ec_pk[RLC_EC_SIZE_COMPRESSED];
	uint8_t serialized_paillier_sk[RLC_PAILLIER_KEY_SIZE];
	uint8_t serialized_paillier_pk[RLC_PAILLIER_KEY_SIZE];

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

		if (fread(serialized_paillier_sk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file) != RLC_PAILLIER_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		bn_read_bin(paillier_secret_key->sk, serialized_paillier_sk, RLC_PAILLIER_KEY_SIZE);
		
		if (fread(serialized_paillier_pk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file) != RLC_PAILLIER_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		bn_read_bin(paillier_public_key_tumbler->pk, serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE);
		memzero(serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE);

		if (fread(serialized_paillier_pk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file) != RLC_PAILLIER_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		bn_read_bin(paillier_public_key_alice->pk, serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE);
		memzero(serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE);

		if (fread(serialized_paillier_pk, sizeof(uint8_t), RLC_PAILLIER_KEY_SIZE, file) != RLC_PAILLIER_KEY_SIZE) {
			THROW(ERR_NO_READ);
		}
		bn_read_bin(paillier_public_key_bob->pk, serialized_paillier_pk, RLC_PAILLIER_KEY_SIZE);

		fclose(file);
		free(key_file_name);
	} CATCH_ANY {
		result_status = RLC_ERR;
	}

	return result_status;
}

void print_ec_secret_key(const char* name, const ec_secret_key_t secret_key) {
	printf("\n%s's EC secret key\n", name);
	printf("sk:\n");
	bn_print(secret_key->sk);
}

void print_ec_public_key(const char* name, const ec_public_key_t public_key) {
	printf("\n%s's EC public key\n", name);
	printf("pk:\n");
	ec_print(public_key->pk);
}

void print_paillier_secret_key(const char* name, const paillier_secret_key_t secret_key) {
	printf("\n%s's Paillier secret key\n", name);
	printf("sk:\n");
	bn_print(secret_key->sk);
}

void print_paillier_public_key(const char* name, const paillier_public_key_t public_key) {
	printf("\n%s's Paillier public key\n", name);
	printf("pk:\n");
	bn_print(public_key->pk);
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