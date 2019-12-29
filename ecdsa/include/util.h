#ifndef TRILERO_ECDSA_INCLUDE_UTIL
#define TRILERO_ECDSA_INCLUDE_UTIL

#include <stddef.h>
#include "relic/relic.h"
#include "types.h"

#define RLC_EC_SIZE_COMPRESSED 33
#define RLC_CL_SECRET_KEY_SIZE 290
#define RLC_CL_PUBLIC_KEY_SIZE 1070
#define RLC_CL_CIPHERTEXT_SIZE 1550
#define RLC_CLDL_PROOF_T1_SIZE 1070
#define RLC_CLDL_PROOF_T2_SIZE 33
#define RLC_CLDL_PROOF_T3_SIZE 1070
#define RLC_CLDL_PROOF_U1_SIZE 315
#define RLC_CLDL_PROOF_U2_SIZE 80

#define RLC_PAILLIER_CTX_SIZE 10

#define CLOCK_PRECISION 1E9

#define ALICE_KEY_FILE_PREFIX "alice"
#define BOB_KEY_FILE_PREFIX "bob"
#define TUMBLER_KEY_FILE_PREFIX "tumbler"
#define KEY_FILE_EXTENSION "key"

int init();
int clean();

void memzero(void *ptr, size_t len);
long long cpucycles(void);
long long ttimer(void);

void serialize_message(uint8_t **serialized,
											 const message_t message,
											 const unsigned msg_type_length,
											 const unsigned msg_data_length);
void deserialize_message(message_t *deserialized_message, const uint8_t *serialized);

int generate_keys_and_write_to_file(const cl_params_t params);
int read_keys_from_file_alice_bob(const char *name,
																	ec_secret_key_t ec_secret_key,
																	ec_public_key_t ec_public_key,
																	cl_secret_key_t cl_secret_key,
																	cl_public_key_t cl_public_key,
																	cl_public_key_t tumbler_cl_public_key);
int read_keys_from_file_tumbler(ec_secret_key_t ec_secret_key,
																ec_public_key_t ec_public_key_alice_tumbler,
																ec_public_key_t ec_public_key_bob_tumbler,
																cl_secret_key_t cl_secret_key,
																cl_public_key_t cl_public_key_tumbler,
																cl_public_key_t cl_public_key_alice,
																cl_public_key_t cl_public_key_bob,
																cl_ciphertext_t cl_ctx_ec_sk_alice,
																cl_ciphertext_t cl_ctx_ec_sk_bob);

int generate_cl_params(cl_params_t params);
int cl_enc(cl_ciphertext_t ciphertext,
					 const GEN plaintext,
					 const cl_public_key_t public_key,
					 const cl_params_t params);
int cl_dec(GEN *plaintext,
					 const cl_ciphertext_t ciphertext,
					 const cl_secret_key_t secret_key,
					 const cl_params_t params);

int commit(commit_t com, const ec_t x);
int decommit(const commit_t com, const ec_t x);

int zk_cldl_prove(zk_proof_cldl_t proof,
									const GEN x,
									const cl_ciphertext_t ciphertext,
									const cl_public_key_t public_key,
									const cl_params_t params);
int zk_cldl_verify(const zk_proof_cldl_t proof,
									 const ec_t Q,
									 const cl_ciphertext_t ciphertext,
									 const cl_public_key_t public_key,
									 const cl_params_t params);
int zk_dlog_prove(zk_proof_t proof, const ec_t h, const bn_t w);
int zk_dlog_verify(const zk_proof_t proof, const ec_t h);

int zk_dhtuple_prove(zk_proof_t proof, const ec_t h, const ec_t u, const ec_t v, const bn_t w);
int zk_dhtuple_verify(const zk_proof_t proof, const ec_t h, const ec_t u, const ec_t v);

#endif // TRILERO_ECDSA_INCLUDE_UTIL
