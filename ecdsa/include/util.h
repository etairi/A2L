#ifndef TRILERO_ECDSA_INCLUDE_UTIL
#define TRILERO_ECDSA_INCLUDE_UTIL

#include <stddef.h>
#include "relic/relic.h"
#include "types.h"

#define RLC_EC_SIZE_COMPRESSED 33
#define RLC_PAILLIER_CTX_SIZE (RLC_BN_BITS / 8 + 1)
#define RLC_PAILLIER_KEY_SIZE 256

#define CLOCK_PRECISION 1E9

#define ALICE_KEY_FILE_PREFIX "alice"
#define BOB_KEY_FILE_PREFIX "bob"
#define TUMBLER_KEY_FILE_PREFIX "tumbler"
#define KEY_FILE_EXTENSION "key"

int init();
int clean();

void memzero(void *ptr, size_t len);
long long cpucycles(void);
long long timer(void);

void serialize_message(uint8_t **serialized,
											 const message_t message,
											 const unsigned msg_type_length,
											 const unsigned msg_data_length);
void deserialize_message(message_t *deserialized_message, const uint8_t *serialized);

int generate_keys_and_write_to_file();
int read_keys_from_file_alice_bob(const char *name,
																	ec_secret_key_t ec_secret_key,
																	ec_public_key_t ec_public_key,
																	paillier_secret_key_t paillier_secret_key,
																	paillier_public_key_t paillier_public_key,
																	paillier_public_key_t tumbler_paillier_public_key);
int read_keys_from_file_tumbler(ec_secret_key_t ec_secret_key,
																ec_public_key_t ec_public_key_alice_tumbler,
																ec_public_key_t ec_public_key_bob_tumbler,
																paillier_secret_key_t paillier_secret_key,
																paillier_public_key_t paillier_public_key_tumbler,
																paillier_public_key_t paillier_public_key_alice,
																paillier_public_key_t paillier_public_key_bob,
																bn_t paillier_ctx_ec_sk_alice,
																bn_t paillier_ctx_ec_sk_bob);

void print_ec_secret_key(const char* name, const ec_secret_key_t secret_key);
void print_ec_public_key(const char* name, const ec_public_key_t public_key);
void print_paillier_secret_key(const char* name, const paillier_secret_key_t secret_key);
void print_paillier_public_key(const char* name, const paillier_public_key_t public_key);

int commit(commit_t com, const ec_t x);
int decommit(const commit_t com, const ec_t x);

int zk_dlog_prove(zk_proof_t proof, const ec_t h, const bn_t w);
int zk_dlog_verify(const zk_proof_t proof, const ec_t h);

int zk_dhtuple_prove(zk_proof_t proof, const ec_t h, const ec_t u, const ec_t v, const bn_t w);
int zk_dhtuple_verify(const zk_proof_t proof, const ec_t h, const ec_t u, const ec_t v);

#endif // TRILERO_ECDSA_INCLUDE_UTIL