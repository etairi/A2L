#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "relic/relic.h"
#include "pari/pari.h"
#include "zmq.h"
#include "tumbler.h"
#include "types.h"
#include "util.h"

int get_message_type(char *key) {
  for (size_t i = 0; i < TOTAL_MESSAGES; i++) {
    symstruct_t sym = msg_lookuptable[i];
    if (strcmp(sym.key, key) == 0) {
      return sym.code;
    }
  }
  return -1;
}

msg_handler_t get_message_handler(char *key) {
  switch (get_message_type(key))
  {
    case PROMISE_INIT:
      return promise_init_handler;

    case PROMISE_SIGN:
      return promise_sign_handler;

    case PROMISE_END:
      return promise_end_handler;

    case PAYMENT_INIT:
      return payment_init_handler;

    case PAYMENT_SIGN:
      return payment_sign_handler;

    case PAYMENT_END:
      return payment_end_handler;

    default:
      fprintf(stderr, "Error: invalid message type.\n");
      exit(1);
  }
}

int handle_message(tumbler_state_t state, void *socket, zmq_msg_t message) {
  int result_status = RLC_OK;

  message_t msg;
  message_null(msg);

  TRY {
    printf("Received message size: %ld bytes\n", zmq_msg_size(&message));
    deserialize_message(&msg, (uint8_t *) zmq_msg_data(&message));

    printf("Executing %s...\n", msg->type);
    msg_handler_t msg_handler = get_message_handler(msg->type);
    if (msg_handler(state, socket, msg->data) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }
    printf("Finished executing %s.\n\n", msg->type);
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    if (msg != NULL) message_free(msg);
  }

  return result_status;
}

int receive_message(tumbler_state_t state, void *socket) {
  int result_status = RLC_OK;

  zmq_msg_t message;

  TRY {
    int rc = zmq_msg_init(&message);
    if (rc != 0) {
      fprintf(stderr, "Error: could not initialize the message.\n");
      THROW(ERR_CAUGHT);
    }

    rc = zmq_msg_recv(&message, socket, ZMQ_DONTWAIT);
    if (rc != -1 && handle_message(state, socket, message) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    zmq_msg_close(&message);
  }

  return result_status;
}

int promise_init_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  message_t promise_init_msg;
  uint8_t *serialized_message = NULL;

  bn_t q;
  ec_t x;
  commit_t com;
  zk_proof_cldl_t pi_cldl;
  
  message_null(promise_init_msg);
  bn_null(q);
  ec_null(x);
  commit_null(com);
  zk_proof_cldl_null(pi_cldl);
  
  TRY {
    bn_new(q);
    ec_new(x);
    commit_new(com);
    zk_proof_cldl_new(pi_cldl);

    ec_curve_get_ord(q);

    bn_rand_mod(state->alpha, q);
    ec_mul_gen(state->g_to_the_alpha, state->alpha);

    bn_rand_mod(state->k_2_prime, q);
    ec_mul_gen(state->R_2_prime, state->k_2_prime);
    
    if (zk_dlog_prove(state->pi_2_prime, state->R_2_prime, state->k_2_prime) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    const unsigned alpha_str_len = bn_size_str(state->alpha, 10);
    char alpha_str[alpha_str_len];
    bn_write_str(alpha_str, alpha_str_len, state->alpha, 10);

    GEN plain_alpha = strtoi(alpha_str);
    if (cl_enc(state->ctx_alpha, plain_alpha, state->keys->cl_pk, state->cl_params) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    if (zk_cldl_prove(pi_cldl, plain_alpha, state->ctx_alpha, state->keys->cl_pk, state->cl_params) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    ec_add(x, state->R_2_prime, state->pi_2_prime->a);
    if (commit(com, x) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "promise_init_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE) 
    + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T2_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_init_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(promise_init_msg->data, RLC_EC_SIZE_COMPRESSED, state->g_to_the_alpha, 1);
    bn_write_bin(promise_init_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_BN_SIZE, com->c);
    ec_write_bin(promise_init_msg->data + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, com->r, 1);
    memcpy(promise_init_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE,
           GENtostr(state->ctx_alpha->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_init_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + RLC_CL_CIPHERTEXT_SIZE,
           GENtostr(state->ctx_alpha->c2), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_init_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE),
           GENtostr(pi_cldl->t1), RLC_CLDL_PROOF_T1_SIZE);
    ec_write_bin(promise_init_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE) 
              + RLC_CLDL_PROOF_T1_SIZE, RLC_EC_SIZE_COMPRESSED, pi_cldl->t2, 1);
    memcpy(promise_init_msg->data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE, GENtostr(pi_cldl->t3), RLC_CLDL_PROOF_T3_SIZE);
    memcpy(promise_init_msg->data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE, GENtostr(pi_cldl->u1), RLC_CLDL_PROOF_U1_SIZE);
    memcpy(promise_init_msg->data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE, GENtostr(pi_cldl->u2), RLC_CLDL_PROOF_U2_SIZE);

    memcpy(promise_init_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_init_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_init;
    int rc = zmq_msg_init_size(&promise_init, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_init), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_init, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    bn_free(q);
    ec_free(x);
    commit_free(com);
    zk_proof_cldl_free(pi_cldl);
    if (promise_init_msg != NULL) message_free(promise_init_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int promise_sign_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  unsigned tx_len = sizeof(tx);
  uint8_t *tx_msg = malloc(tx_len + RLC_FC_BYTES);
  uint8_t hash[RLC_MD_LEN];
  uint8_t *serialized_message = NULL;
  message_t promise_sign_done_msg;

  bn_t q, r, x, s_2_prime;
  ec_t R_prime;
  zk_proof_t pi_1_prime;

  bn_null(q);
  bn_null(r);
  bn_null(x);
  bn_null(s_2_prime);
  ec_null(R_prime);
  zk_proof_null(pi_1_prime);
  message_null(promise_sign_done_msg);

  TRY {
    bn_new(q);
    bn_new(r);
    bn_new(x);
    bn_new(s_2_prime);
    ec_new(R_prime);
    zk_proof_new(pi_1_prime);

    // Deserialize the data from the message.
    ec_read_bin(state->R_1_prime, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_1_prime->a, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_1_prime->z, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);

    // Verify ZK proof.
    if (zk_dlog_verify(pi_1_prime, state->R_1_prime) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    // Compute the half Schnorr signature.
    ec_add(R_prime, state->R_1_prime, state->R_2_prime);
    ec_norm(R_prime, R_prime);
    ec_add(R_prime, R_prime, state->g_to_the_alpha);
    ec_norm(R_prime, R_prime);

    ec_curve_get_ord(q);
    ec_get_x(x, R_prime);
    bn_mod(r, x, q);
    if (bn_is_zero(r)) {
      THROW(ERR_CAUGHT);
    }

		memcpy(tx_msg, tx, tx_len);
		bn_write_bin(tx_msg + tx_len, RLC_FC_BYTES, r);
		md_map(hash, tx_msg, tx_len + RLC_FC_BYTES);

		if (8 * RLC_MD_LEN > bn_bits(q)) {
			tx_len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(state->e_prime, hash, tx_len);
			bn_rsh(state->e_prime, state->e_prime, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(state->e_prime, hash, RLC_MD_LEN);
		}

		bn_mod(state->e_prime, state->e_prime, q);

		bn_mul(s_2_prime, state->keys->ec_sk->sk, state->e_prime);
		bn_mod(s_2_prime, s_2_prime, q);
		bn_sub(s_2_prime, q, s_2_prime);
		bn_add(s_2_prime, s_2_prime, state->k_2_prime);
		bn_mod(s_2_prime, s_2_prime, q);

    // Build and define the message.
    char *msg_type = "promise_sign_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_sign_done_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(promise_sign_done_msg->data, RLC_EC_SIZE_COMPRESSED, state->R_2_prime, 1);
    ec_write_bin(promise_sign_done_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, state->pi_2_prime->a, 1);
    bn_write_bin(promise_sign_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, state->pi_2_prime->z);
    bn_write_bin(promise_sign_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE, s_2_prime);

    memcpy(promise_sign_done_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_sign_done_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_sign;
    int rc = zmq_msg_init_size(&promise_sign, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_sign), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_sign, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    bn_free(q);
    bn_free(r);
    bn_free(x);
    bn_free(s_2_prime);
    ec_free(R_prime);
    zk_proof_free(pi_1_prime);
    free(tx_msg);
    if (serialized_message != NULL) free(serialized_message);
    if (promise_sign_done_msg != NULL) message_free(promise_sign_done_msg);
  }

  return result_status;
}

int promise_end_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  message_t promise_end_done_msg;
  message_null(promise_end_done_msg);

  bn_t s_prime;
  bn_t neg_e_prime;
  ec_t g_to_the_s_prime;
  ec_t pk_to_the_neg_e_prime;
  ec_t R_1_prime_times_R_2_prime;
  ec_t R_1_prime_times_R_2_prime_times_pk;

  bn_null(s_prime);
  bn_null(neg_e_prime);
  ec_null(g_to_the_s_prime);
  ec_null(pk_to_the_neg_e_prime);
  ec_null(R_1_prime_times_R_2_prime);
  ec_null(R_1_prime_times_R_2_prime_times_pk);

  TRY {
    bn_new(s_prime);
    bn_new(neg_e_prime);
    ec_new(g_to_the_s_prime);
    ec_new(pk_to_the_neg_e_prime);
    ec_new(R_1_prime_times_R_2_prime);
    ec_new(R_1_prime_times_R_2_prime_times_pk);

    // Deserialize the data from the message.
    bn_read_bin(s_prime, data, RLC_BN_SIZE);

    // Check correctness of the "almost" signature received.
    ec_mul_gen(g_to_the_s_prime, s_prime);
    bn_neg(neg_e_prime, state->e_prime);
    ec_mul(pk_to_the_neg_e_prime, state->ec_pk_tumbler_bob->pk, neg_e_prime);
    ec_add(R_1_prime_times_R_2_prime, state->R_1_prime, state->R_2_prime);
    ec_add(R_1_prime_times_R_2_prime_times_pk, R_1_prime_times_R_2_prime, pk_to_the_neg_e_prime);
    
    if (ec_cmp(g_to_the_s_prime, R_1_prime_times_R_2_prime_times_pk) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "promise_end_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = 0;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_end_done_msg, msg_type_length, msg_data_length);

    // Serialize the message.
    memcpy(promise_end_done_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_end_done_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_end_done;
    int rc = zmq_msg_init_size(&promise_end_done, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_end_done), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_end_done, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    bn_free(s_prime);
    bn_free(neg_e_prime);
    ec_free(g_to_the_s_prime);
    ec_free(pk_to_the_neg_e_prime);
    ec_free(R_1_prime_times_R_2_prime);
    ec_free(R_1_prime_times_R_2_prime_times_pk);
    if (promise_end_done_msg != NULL) message_free(promise_end_done_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int payment_init_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  message_t payment_init_msg;

  bn_t q;
  ec_t x;
  commit_t com;

  bn_null(q);
  ec_null(x);
  commit_null(com);
  message_null(payment_init_msg);

  TRY {
    bn_new(q);
    ec_new(x);
    commit_new(com);

    ec_curve_get_ord(q);

    bn_rand_mod(state->k_2, q);
    ec_mul_gen(state->R_2, state->k_2);
    
    if (zk_dlog_prove(state->pi_2, state->R_2, state->k_2) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    ec_add(x, state->R_2, state->pi_2->a);
    if (commit(com, x) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "payment_init_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE + RLC_EC_SIZE_COMPRESSED;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_init_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    bn_write_bin(payment_init_msg->data, RLC_BN_SIZE, com->c);
    ec_write_bin(payment_init_msg->data + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, com->r, 1);

    memcpy(payment_init_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_init_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_init;
    int rc = zmq_msg_init_size(&payment_init, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_init), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_init, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    commit_free(com);
    bn_free(q);
    ec_free(x);
    if (payment_init_msg != NULL) message_free(payment_init_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int payment_sign_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  unsigned tx_len = sizeof(tx);
  uint8_t *tx_msg = malloc(tx_len + RLC_FC_BYTES);
  uint8_t hash[RLC_MD_LEN];

  uint8_t *serialized_message = NULL;

  message_t payment_sign_done_msg;
  message_null(payment_sign_done_msg);

  cl_ciphertext_t ctx_alpha_times_beta_times_tau;
  bn_t q, r, x, s_2;
  ec_t R_1, R, g_to_the_gamma;
  zk_proof_t pi_1;

  cl_ciphertext_null(ctx_alpha_times_beta_times_tau);
  bn_null(q);
  bn_null(r);
  bn_null(x);
  bn_null(s_2);
  ec_null(R_1);
  ec_null(R);
  ec_null(g_to_the_gamma);
  zk_proof_null(pi_1);

  TRY {
    cl_ciphertext_new(ctx_alpha_times_beta_times_tau);
    bn_new(q);
    bn_new(r);
    bn_new(x);
    bn_new(s_2);
    ec_new(R_1);
    ec_new(R);
    ec_new(g_to_the_gamma);
    zk_proof_new(pi_1);

    // Deserialize the data from the message.
    ec_read_bin(R_1, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_1->a, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_1->z, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);

    char ct_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ct_str, data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx_alpha_times_beta_times_tau->c1 = gp_read_str(ct_str);
    memcpy(ct_str, data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx_alpha_times_beta_times_tau->c2 = gp_read_str(ct_str);

    // Verify ZK proof.
    if (zk_dlog_verify(pi_1, R_1) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    // Decrypt the ciphertext.
    GEN gamma;
    if (cl_dec(&gamma, ctx_alpha_times_beta_times_tau, state->keys->cl_sk, state->cl_params) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }
    bn_read_str(state->gamma, GENtostr(gamma), strlen(GENtostr(gamma)), 10);

    // Compute the half Schnorr signature.
    ec_mul_gen(g_to_the_gamma, state->gamma);
    ec_add(R, R_1, state->R_2);
    ec_norm(R, R);
    ec_add(R, R, g_to_the_gamma);
    ec_norm(R, R);

    ec_curve_get_ord(q);
    ec_get_x(x, R);
    bn_mod(r, x, q);
    if (bn_is_zero(r)) {
      THROW(ERR_CAUGHT);
    }

		memcpy(tx_msg, tx, tx_len);
		bn_write_bin(tx_msg + tx_len, RLC_FC_BYTES, r);
		md_map(hash, tx_msg, tx_len + RLC_FC_BYTES);

		if (8 * RLC_MD_LEN > bn_bits(q)) {
			tx_len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(state->e, hash, tx_len);
			bn_rsh(state->e, state->e, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(state->e, hash, RLC_MD_LEN);
		}

		bn_mod(state->e, state->e, q);

		bn_mul(s_2, state->keys->ec_sk->sk, state->e);
		bn_mod(s_2, s_2, q);
		bn_sub(s_2, q, s_2);
		bn_add(s_2, s_2, state->k_2);
		bn_mod(s_2, s_2, q);

    // Build and define the message.
    char *msg_type = "payment_sign_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (3 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_sign_done_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(payment_sign_done_msg->data, RLC_EC_SIZE_COMPRESSED, state->R_2, 1);
    ec_write_bin(payment_sign_done_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, state->pi_2->a, 1);
    bn_write_bin(payment_sign_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, state->pi_2->z);
    bn_write_bin(payment_sign_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE, s_2);
    ec_write_bin(payment_sign_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED, g_to_the_gamma, 1);

    memcpy(payment_sign_done_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_sign_done_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_sign_done;
    int rc = zmq_msg_init_size(&payment_sign_done, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_sign_done), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_sign_done, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    cl_ciphertext_free(ctx_alpha_times_beta_times_tau);
    bn_free(q);
    bn_free(r);
    bn_free(x);
    bn_free(s_2);
    ec_free(R_1);
    ec_free(R);
    ec_free(g_to_the_gamma);
    zk_proof_free(pi_1);
    free(tx_msg);
    if (payment_sign_done_msg != NULL) message_free(payment_sign_done_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int payment_end_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  int verif_status = RLC_ERR;

  unsigned tx_len = sizeof(tx);
  uint8_t *tx_msg = malloc(tx_len + RLC_FC_BYTES);
  uint8_t hash[RLC_MD_LEN];
  uint8_t *serialized_message = NULL;

  message_t puzzle_solve_msg;
  message_null(puzzle_solve_msg);

  bn_t q, s_hat;
  bn_t ev, rv;
  ec_t p;

  bn_null(q);
  bn_null(s_hat);
  bn_null(ev);
  bn_null(rv);
  ec_null(p);

  TRY {
    bn_new(q);
    bn_new(s_hat);
    bn_new(ev);
    bn_new(rv);
    ec_new(p);

    ec_curve_get_ord(q);

    // Deserialize the data from the message.
    bn_read_bin(s_hat, data, RLC_BN_SIZE);

    // Complete the "almost" signature.
    bn_add(state->s, s_hat, state->gamma);
    bn_mod(state->s, state->s, q);

    // Verify the completed signature.
    if (bn_sign(state->e) == RLC_POS && bn_sign(state->s) == RLC_POS && !bn_is_zero(state->s)) {
			if (bn_cmp(state->e, q) == RLC_LT && bn_cmp(state->s, q) == RLC_LT) {
				ec_mul_sim_gen(p, state->s, state->ec_pk_tumbler_alice->pk, state->e);
				ec_get_x(rv, p);

				bn_mod(rv, rv, q);

				memcpy(tx_msg, tx, tx_len);
				bn_write_bin(tx_msg + tx_len, RLC_FC_BYTES, rv);
				md_map(hash, tx_msg, tx_len + RLC_FC_BYTES);

				if (8 * RLC_MD_LEN > bn_bits(q)) {
					tx_len = RLC_CEIL(bn_bits(q), 8);
					bn_read_bin(ev, hash, tx_len);
					bn_rsh(ev, ev, 8 * RLC_MD_LEN - bn_bits(q));
				} else {
					bn_read_bin(ev, hash, RLC_MD_LEN);
				}

				bn_mod(ev, ev, q);

				verif_status = dv_cmp_const(ev->dp, state->e->dp, RLC_MIN(ev->used, state->e->used));
				verif_status = (verif_status == RLC_NE ? RLC_ERR : RLC_OK);

				if (ev->used != state->e->used) {
					verif_status = RLC_ERR;
				}

        if (verif_status != RLC_OK) {
          THROW(ERR_CAUGHT);
        }
			}
		}

    // Build and define the message.
    char *msg_type = "puzzle_solve";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(puzzle_solve_msg, msg_type_length, msg_data_length);
    
    // Serialize the data for the message.
    bn_write_bin(puzzle_solve_msg->data, RLC_BN_SIZE, state->s);

    // Serialize the message.
    memcpy(puzzle_solve_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, puzzle_solve_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t puzzle_solve;
    int rc = zmq_msg_init_size(&puzzle_solve, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&puzzle_solve), serialized_message, total_msg_length);
    rc = zmq_msg_send(&puzzle_solve, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    bn_free(q);
    bn_free(s_hat);
    bn_free(ev);
    bn_free(rv);
    ec_free(p);
    free(tx_msg);
    if (puzzle_solve_msg != NULL) message_free(puzzle_solve_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int main(void)
{
  init();
  int result_status = RLC_OK;

  tumbler_state_t state;
  tumbler_state_null(state);

  // Bind the socket to talk to clients.
  void *context = zmq_ctx_new();
  if (!context) {
    fprintf(stderr, "Error: could not create a context.\n");
    exit(1);
  }
  
  void *socket = zmq_socket(context, ZMQ_REP);
  if (!socket) {
    fprintf(stderr, "Error: could not create a socket.\n");
    exit(1);
  }

  int rc = zmq_bind(socket, TUMBLER_ENDPOINT);
  if (rc != 0) {
    fprintf(stderr, "Error: could not bind the socket.\n");
    exit(1);
  }

  TRY {
    tumbler_state_new(state);

    if (generate_cl_params(state->cl_params) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    if (read_keys_from_file_tumbler(state->keys->ec_sk,
                                    state->ec_pk_tumbler_alice,
                                    state->ec_pk_tumbler_bob,
                                    state->keys->cl_sk,
                                    state->keys->cl_pk,
                                    state->cl_pk_alice,
                                    state->cl_pk_bob) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    while (1) {
      if (receive_message(state, socket) != RLC_OK) {
        THROW(ERR_CAUGHT);
      }
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    tumbler_state_free(state);
  }

  rc = zmq_close(socket);
  if (rc != 0) {
    fprintf(stderr, "Error: could not close the socket.\n");
    exit(1);
  }

  rc = zmq_ctx_destroy(context);
  if (rc != 0) {
    fprintf(stderr, "Error: could not destroy the context.\n");
    exit(1);
  }

  clean();

  return result_status;
}