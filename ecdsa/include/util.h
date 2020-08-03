#ifndef A2L_ECDSA_INCLUDE_UTIL
#define A2L_ECDSA_INCLUDE_UTIL

#include <stddef.h>
#include "relic/relic.h"
#include "types.h"

#define RLC_EC_SIZE_COMPRESSED 33
#define RLC_G1_SIZE_COMPRESSED 33
#define RLC_G2_SIZE_COMPRESSED 65
#define RLC_CL_SECRET_KEY_SIZE 290
#define RLC_CL_PUBLIC_KEY_SIZE 1070
#define RLC_CL_CIPHERTEXT_SIZE 1070
#define RLC_CLDL_PROOF_T1_SIZE 1070
#define RLC_CLDL_PROOF_T2_SIZE 33
#define RLC_CLDL_PROOF_T3_SIZE 1070
#define RLC_CLDL_PROOF_U1_SIZE 315
#define RLC_CLDL_PROOF_U2_SIZE 80

#define CLOCK_PRECISION 1E9

#define ALICE_KEY_FILE_PREFIX "alice"
#define BOB_KEY_FILE_PREFIX "bob"
#define TUMBLER_KEY_FILE_PREFIX "tumbler"
#define KEY_FILE_EXTENSION "key"

static uint8_t tx[2] = { 116, 120 }; // "tx"

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
																	ec_secret_key_t ec_sk,
																	ec_public_key_t ec_pk,
																	ec_public_key_t tumbler_ec_pk,
																	ps_public_key_t tumbler_ps_pk,
																	cl_public_key_t tumbler_cl_pk);
int read_keys_from_file_tumbler(ec_secret_key_t tumbler_ec_sk,
																ec_public_key_t tumbler_ec_pk,
																ps_secret_key_t tumbler_ps_sk,
																ps_public_key_t tumbler_ps_pk,
																cl_secret_key_t tumbler_cl_sk,
																cl_public_key_t tumbler_cl_pk,
																ec_public_key_t alice_ec_pk,
																ec_public_key_t bob_ec_pk);

int generate_cl_params(cl_params_t params);
int cl_enc(cl_ciphertext_t ciphertext,
					 const GEN plaintext,
					 const cl_public_key_t public_key,
					 const cl_params_t params);
int cl_dec(GEN *plaintext,
					 const cl_ciphertext_t ciphertext,
					 const cl_secret_key_t secret_key,
					 const cl_params_t params);

int ps_blind_sign(ps_signature_t signature,
									const pedersen_com_t com, 
									const ps_secret_key_t secret_key);
int ps_unblind(ps_signature_t signature,
							 const pedersen_decom_t decom);
int ps_verify(const ps_signature_t signature,
							bn_t message,
						 	const ps_public_key_t public_key);

int adaptor_ecdsa_sign(ecdsa_signature_t signature,
											 uint8_t *msg,
											 size_t len,
											 const ec_t Y,
											 const ec_secret_key_t secret_key);
int adaptor_ecdsa_preverify(ecdsa_signature_t signature,
														uint8_t *msg,
														size_t len,
														const ec_t Y,
														const ec_public_key_t public_key);

int pedersen_commit(pedersen_com_t com,
										pedersen_decom_t decom,
										g1_t h,
										bn_t x);
int commit(commit_t com, const ec_t x);
int decommit(const commit_t com, const ec_t x);

int zk_pedersen_com_prove(pedersen_com_zk_proof_t proof,
													g1_t h,
													const pedersen_com_t com,
													const pedersen_decom_t decom);
int zk_pedersen_com_verify(const pedersen_com_zk_proof_t proof,
													 g1_t h,
													 const pedersen_com_t com);
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

#endif // A2L_ECDSA_INCLUDE_UTIL