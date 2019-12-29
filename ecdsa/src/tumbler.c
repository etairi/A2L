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
    + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T2_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE;;
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

  int tx_len = sizeof(tx);
  uint8_t *tx_msg = NULL;
  uint8_t hash[RLC_MD_LEN];
  uint8_t *serialized_message = NULL;
  message_t promise_sign_done_msg;

  bn_t q, x, s, s_2_prime;
  bn_t k_2_prime_times_alpha;
  bn_t k_2_prime_inverse;
  bn_t k_2_times_r_times_ec_sk_2;
  bn_t k_2_times_e;
  bn_t r_times_ec_sk_2;
  ec_t R_prime, R_c_prime;
  
  zk_proof_t pi_1_prime;
  zk_proof_t pi_c_prime;
  zk_proof_t pi_a_prime;
  cl_ciphertext_t ctx_k_2_times_e;
  cl_ciphertext_t ctx_prime;

  bn_null(q);
  bn_null(x);
  bn_null(s);
  bn_null(s_2_prime);
  bn_null(k_2_prime_times_alpha);
  bn_null(k_2_prime_inverse);
  bn_null(k_2_times_r_times_ec_sk_2);
  bn_null(k_2_times_e);
  bn_null(r_times_ec_sk_2);
  ec_null(R_prime);
  ec_null(R_c_prime);

  zk_proof_null(pi_1_prime);
  zk_proof_null(pi_c_prime);
  zk_proof_null(pi_a_prime);
  cl_ciphertext_null(ctx_k_2_times_e);
  cl_ciphertext_null(ctx_prime);
  
  message_null(promise_sign_done_msg);

  TRY {
    bn_new(q);
    bn_new(x);
    bn_new(s);
    bn_new(s_2_prime);
    bn_new(k_2_prime_times_alpha);
    bn_new(k_2_prime_inverse);
    bn_new(k_2_times_r_times_ec_sk_2);
    bn_new(k_2_times_e);
    bn_new(r_times_ec_sk_2);
    ec_new(R_prime);
    ec_new(R_c_prime);

    zk_proof_new(pi_1_prime);
    zk_proof_new(pi_c_prime);
    zk_proof_new(pi_a_prime);
    cl_ciphertext_new(ctx_k_2_times_e);
    cl_ciphertext_new(ctx_prime);

    // Deserialize the data from the message.
    ec_read_bin(state->R_1_prime, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_1_prime->a, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_1_prime->z, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);

    // Verify ZK proof.
    if (zk_dlog_verify(pi_1_prime, state->R_1_prime) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    // Compute the half ECDSA signature and ZK proofs.
    ec_mul(R_c_prime, state->R_2_prime, state->alpha);
    ec_norm(R_c_prime, R_c_prime);

    ec_curve_get_ord(q);

    bn_mul(k_2_prime_times_alpha, state->k_2_prime, state->alpha);
    bn_mod(k_2_prime_times_alpha, k_2_prime_times_alpha, q);

    if (zk_dlog_prove(pi_c_prime, R_c_prime, k_2_prime_times_alpha) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    if (zk_dhtuple_prove(pi_a_prime, state->R_2_prime, state->g_to_the_alpha, R_c_prime, state->alpha) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    ec_mul(R_prime, state->R_1_prime, k_2_prime_times_alpha);
    ec_norm(R_prime, R_prime);

    ec_get_x(x, R_prime);
    bn_mod(state->r_prime, x, q);
    if (bn_is_zero(state->r_prime)) {
      THROW(ERR_CAUGHT);
    }

		md_map(hash, tx, tx_len);
    tx_msg = hash;
    tx_len = RLC_MD_LEN;

		if (8 * tx_len > bn_bits(q)) {
			tx_len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(state->e_prime, tx_msg, tx_len);
			bn_rsh(state->e_prime, state->e_prime, 8 * tx_len - bn_bits(q));
		} else {
			bn_read_bin(state->e_prime, tx_msg, tx_len);
		}

    bn_gcd_ext(x, k_2_prime_inverse, NULL, state->k_2_prime, q);
    if (bn_sign(k_2_prime_inverse) == RLC_NEG) {
      bn_add(k_2_prime_inverse, k_2_prime_inverse, q);
    }

    bn_mul(r_times_ec_sk_2, state->keys->ec_sk->sk, state->r_prime);
    bn_mod(r_times_ec_sk_2, r_times_ec_sk_2, q);
    bn_mul(k_2_times_r_times_ec_sk_2, r_times_ec_sk_2, k_2_prime_inverse);
    bn_mod(k_2_times_r_times_ec_sk_2, k_2_times_r_times_ec_sk_2, q);

    bn_mul(k_2_times_e, k_2_prime_inverse, state->e_prime);
    bn_mod(k_2_times_e, k_2_times_e, q);

    const unsigned plain_str_len = bn_size_str(k_2_times_e, 10);
    char plain_str[plain_str_len];
    bn_write_str(plain_str, plain_str_len, k_2_times_e, 10);

    GEN plain_k_2_times_e = strtoi(plain_str);
    if (cl_enc(ctx_k_2_times_e, plain_k_2_times_e, state->cl_pk_bob, state->cl_params) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    const unsigned v_str_len = bn_size_str(k_2_times_r_times_ec_sk_2, 10);
    char v_str[v_str_len];
    bn_write_str(v_str, v_str_len, k_2_times_r_times_ec_sk_2, 10);
    GEN v = strtoi(v_str);

    ctx_prime->c1 = nupow(state->ctx_ec_sk_bob->c1, v, NULL);
    ctx_prime->c2 = nupow(state->ctx_ec_sk_bob->c2, v, NULL);
    ctx_prime->c1 = gmul(ctx_k_2_times_e->c1, ctx_prime->c1);
    ctx_prime->c2 = gmul(ctx_k_2_times_e->c2, ctx_prime->c2);

    // Build and define the message.
    char *msg_type = "promise_sign_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (6 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_sign_done_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(promise_sign_done_msg->data, RLC_EC_SIZE_COMPRESSED, state->R_2_prime, 1);
    ec_write_bin(promise_sign_done_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, state->pi_2_prime->a, 1);
    bn_write_bin(promise_sign_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, state->pi_2_prime->z);
    ec_write_bin(promise_sign_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, R_c_prime, 1);
    ec_write_bin(promise_sign_done_msg->data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, pi_c_prime->a, 1);
    bn_write_bin(promise_sign_done_msg->data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE, pi_c_prime->z);
    ec_write_bin(promise_sign_done_msg->data + (4 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED, pi_a_prime->a, 1);
    ec_write_bin(promise_sign_done_msg->data + (5 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED, pi_a_prime->b, 1);
    bn_write_bin(promise_sign_done_msg->data + (6 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_BN_SIZE, pi_a_prime->z);
    memcpy(promise_sign_done_msg->data + (6 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), GENtostr(ctx_prime->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_sign_done_msg->data + (6 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE) + RLC_CL_CIPHERTEXT_SIZE, 
           GENtostr(ctx_prime->c2), RLC_CL_CIPHERTEXT_SIZE);

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
    bn_free(x);
    bn_free(s);
    bn_free(s_2_prime);
    bn_free(k_2_prime_times_alpha);
    bn_free(k_2_prime_inverse);
    bn_free(k_2_times_r_times_ec_sk_2);
    bn_free(k_2_times_e);
    bn_free(r_times_ec_sk_2);
    ec_free(R_prime);
    ec_free(R_c_prime);
    zk_proof_free(pi_1_prime);
    zk_proof_free(pi_c_prime);
    zk_proof_free(pi_a_prime);
    cl_ciphertext_free(ctx_k_2_times_e);
    cl_ciphertext_free(ctx_prime);
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

  bn_t s_prime, k_2_prime_times_s_prime;
  bn_t q, r_prime_times_e_prime;
  ec_t R_1_prime_to_the_k_2_times_s;
  ec_t g_to_the_e_prime;
  ec_t pk_to_the_r_prime;
  ec_t pk_to_the_r_times_go_to_the_e;

  bn_null(q);
  bn_null(s_prime);
  bn_null(k_2_prime_times_s_prime);
  bn_null(r_prime_times_e_prime);
  ec_null(R_1_prime_to_the_k_2_times_s);
  ec_null(g_to_the_e_prime);
  ec_null(pk_to_the_r_prime);
  ec_null(pk_to_the_r_times_go_to_the_e);

  TRY {
    bn_new(q);
    bn_new(s_prime);
    bn_new(k_2_prime_times_s_prime);
    bn_new(r_prime_times_e_prime);
    ec_new(R_1_prime_to_the_k_2_times_s);
    ec_new(g_to_the_e_prime);
    ec_new(pk_to_the_r_prime);
    ec_new(pk_to_the_r_times_go_to_the_e);

    // Deserialize the data from the message.
    bn_read_bin(s_prime, data, RLC_BN_SIZE);

    // Check correctness of the "almost" signature received.
    ec_curve_get_ord(q);

    bn_mul(k_2_prime_times_s_prime, state->k_2_prime, s_prime);
    bn_mod(k_2_prime_times_s_prime, k_2_prime_times_s_prime, q);
    ec_mul(R_1_prime_to_the_k_2_times_s, state->R_1_prime, k_2_prime_times_s_prime);
    ec_norm(R_1_prime_to_the_k_2_times_s, R_1_prime_to_the_k_2_times_s);

    ec_mul_gen(g_to_the_e_prime, state->e_prime);
    ec_mul(pk_to_the_r_prime, state->ec_pk_tumbler_bob->pk, state->r_prime);
    ec_add(pk_to_the_r_times_go_to_the_e, pk_to_the_r_prime, g_to_the_e_prime);
    ec_norm(pk_to_the_r_times_go_to_the_e, pk_to_the_r_times_go_to_the_e);

    if (ec_cmp(R_1_prime_to_the_k_2_times_s, pk_to_the_r_times_go_to_the_e) != RLC_EQ) {
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
    bn_free(q);
    bn_free(s_prime);
    bn_free(k_2_prime_times_s_prime);
    bn_free(r_prime_times_e_prime);
    ec_free(R_1_prime_to_the_k_2_times_s);
    ec_free(g_to_the_e_prime);
    ec_free(pk_to_the_r_prime);
    ec_free(pk_to_the_r_times_go_to_the_e);
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

  uint8_t *serialized_message = NULL;
  int tx_len = sizeof(tx);
  uint8_t *tx_msg = NULL;
  uint8_t hash[RLC_MD_LEN];

  message_t payment_sign_done_msg;
  message_null(payment_sign_done_msg);

  bn_t q, r, x, s, s_2, k_2_times_gamma;
  bn_t k_2_inverse, r_times_ec_sk_2;
  bn_t k_2_times_e, k_2_times_r_times_ec_sk_2;
  ec_t R_1, R_c, R, g_to_the_gamma;
  
  zk_proof_t pi_1, pi_c, pi_gamma;
  cl_ciphertext_t ctx_alpha_times_beta_times_tau;
  cl_ciphertext_t ctx_k_2_times_e, ctx;

  bn_null(q);
  bn_null(r);
  bn_null(x);
  bn_null(s);
  bn_null(s_2);
  bn_null(k_2_times_gamma);
  bn_null(k_2_inverse);
  bn_null(k_2_times_e);
  bn_null(k_2_times_r_times_ec_sk_2);
  bn_null(r_times_ec_sk_2);
  ec_null(R_1);
  ec_null(R_c);
  ec_null(R);
  ec_null(g_to_the_gamma);

  zk_proof_null(pi_1);
  zk_proof_null(pi_c);
  zk_proof_null(pi_gamma);
  cl_ciphertext_null(ctx_alpha_times_beta_times_tau);
  cl_ciphertext_null(ctx_k_2_times_e);
  cl_ciphertext_null(ctx);

  TRY {
    bn_new(q);
    bn_new(r);
    bn_new(x);
    bn_new(s);
    bn_new(s_2);
    bn_new(k_2_times_gamma);
    bn_new(k_2_times_e);
    bn_new(k_2_times_r_times_ec_sk_2);
    bn_new(r_times_ec_sk_2);
    bn_new(k_2_inverse);
    ec_new(R_1);
    ec_new(R_c);
    ec_new(R);
    ec_new(g_to_the_gamma);

    zk_proof_new(pi_1);
    zk_proof_new(pi_c);
    zk_proof_new(pi_gamma);
    cl_ciphertext_new(ctx_alpha_times_beta_times_tau);
    cl_ciphertext_new(ctx_k_2_times_e);
    cl_ciphertext_new(ctx);

    // Deserialize the data from the message.
    ec_read_bin(R_1, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_1->a, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_1->z, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);

    char ctx_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ctx_str, data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx_alpha_times_beta_times_tau->c1 = gp_read_str(ctx_str);
    memzero(ctx_str, RLC_CL_CIPHERTEXT_SIZE);
    memcpy(ctx_str, data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx_alpha_times_beta_times_tau->c2 = gp_read_str(ctx_str);

    // Verify ZK proof.
    if (zk_dlog_verify(pi_1, R_1) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    ec_curve_get_ord(q);

    // Decrypt the ciphertext.
    GEN gamma;
    if (cl_dec(&gamma, ctx_alpha_times_beta_times_tau, state->keys->cl_sk, state->cl_params) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }
    bn_read_str(state->gamma, GENtostr(gamma), strlen(GENtostr(gamma)), 10);

    // Compute the half ECDSA signature and ZK proofs.
    ec_mul_gen(g_to_the_gamma, state->gamma);
    ec_mul(R_c, state->R_2, state->gamma);
    ec_norm(R_c, R_c);

    bn_mul(k_2_times_gamma, state->k_2, state->gamma);
    bn_mod(k_2_times_gamma, k_2_times_gamma, q);
    if (zk_dlog_prove(pi_c, R_c, k_2_times_gamma) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    if (zk_dhtuple_prove(pi_gamma, state->R_2, g_to_the_gamma, R_c, state->gamma) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    ec_mul(R, R_1, k_2_times_gamma);
    ec_norm(R, R);

    ec_get_x(x, R);
    bn_mod(state->r, x, q);
    if (bn_is_zero(state->r)) {
      THROW(ERR_CAUGHT);
    }

		md_map(hash, tx, tx_len);
    tx_msg = hash;
    tx_len = RLC_MD_LEN;

		if (8 * tx_len > bn_bits(q)) {
			tx_len = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(state->e_prime, tx_msg, tx_len);
			bn_rsh(state->e_prime, state->e_prime, 8 * tx_len - bn_bits(q));
		} else {
			bn_read_bin(state->e_prime, tx_msg, tx_len);
		}

    bn_gcd_ext(x, k_2_inverse, NULL, state->k_2, q);
    if (bn_sign(k_2_inverse) == RLC_NEG) {
      bn_add(k_2_inverse, k_2_inverse, q);
    }

    bn_mul(r_times_ec_sk_2, state->keys->ec_sk->sk, state->r);
    bn_mod(r_times_ec_sk_2, r_times_ec_sk_2, q);
    bn_mul(k_2_times_r_times_ec_sk_2, r_times_ec_sk_2, k_2_inverse);
    bn_mod(k_2_times_r_times_ec_sk_2, k_2_times_r_times_ec_sk_2, q);

    bn_mul(k_2_times_e, k_2_inverse, state->e_prime);
    bn_mod(k_2_times_e, k_2_times_e, q);

    const unsigned plain_str_len = bn_size_str(k_2_times_e, 10);
    char plain_str[plain_str_len];
    bn_write_str(plain_str, plain_str_len, k_2_times_e, 10);

    GEN plain_k_2_times_e = strtoi(plain_str);
    if (cl_enc(ctx_k_2_times_e, plain_k_2_times_e, state->cl_pk_alice, state->cl_params) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    const unsigned v_str_len = bn_size_str(k_2_times_r_times_ec_sk_2, 10);
    char v_str[v_str_len];
    bn_write_str(v_str, v_str_len, k_2_times_r_times_ec_sk_2, 10);
    GEN v = strtoi(v_str);

    ctx->c1 = nupow(state->ctx_ec_sk_alice->c1, v, NULL);
    ctx->c2 = nupow(state->ctx_ec_sk_alice->c2, v, NULL);
    ctx->c1 = gmul(ctx_k_2_times_e->c1, ctx->c1);
    ctx->c2 = gmul(ctx_k_2_times_e->c2, ctx->c2);

    // Build and define the message.
    char *msg_type = "payment_sign_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (7 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_sign_done_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(payment_sign_done_msg->data, RLC_EC_SIZE_COMPRESSED, state->R_2, 1);
    ec_write_bin(payment_sign_done_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, state->pi_2->a, 1);
    bn_write_bin(payment_sign_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, state->pi_2->z);
    ec_write_bin(payment_sign_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, g_to_the_gamma, 1);
    ec_write_bin(payment_sign_done_msg->data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, R_c, 1);
    ec_write_bin(payment_sign_done_msg->data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, pi_c->a, 1);
    bn_write_bin(payment_sign_done_msg->data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE, pi_c->z);
    ec_write_bin(payment_sign_done_msg->data + (5 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED, pi_gamma->a, 1);
    ec_write_bin(payment_sign_done_msg->data + (6 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED, pi_gamma->b, 1);
    bn_write_bin(payment_sign_done_msg->data + (7 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_BN_SIZE, pi_gamma->z);
    memcpy(payment_sign_done_msg->data + (7 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), GENtostr(ctx->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(payment_sign_done_msg->data + (7 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE) + RLC_CL_CIPHERTEXT_SIZE, GENtostr(ctx->c2), 
           RLC_CL_CIPHERTEXT_SIZE);

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
    bn_free(q);
    bn_free(r);
    bn_free(x);
    bn_free(s);
    bn_free(s_2);
    bn_free(k_2_times_gamma);
    bn_free(k_2_inverse);
    bn_free(k_2_times_e);
    bn_free(k_2_times_r_times_ec_sk_2);
    bn_free(r_times_ec_sk_2);
    ec_free(R_1);
    ec_free(R_c);
    ec_free(R);
    ec_free(g_to_the_gamma);
    zk_proof_free(pi_1);
    zk_proof_free(pi_c);
    zk_proof_free(pi_gamma);
    cl_ciphertext_free(ctx_alpha_times_beta_times_tau);
    cl_ciphertext_free(ctx_k_2_times_e);
    cl_ciphertext_free(ctx);
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

  int tx_len = sizeof(tx);
  uint8_t *tx_msg = NULL;
  uint8_t hash[RLC_MD_LEN];
  uint8_t *serialized_message = NULL;

  message_t puzzle_solve_msg;
  message_null(puzzle_solve_msg);

  bn_t q, x, s_hat;
  bn_t k, e, v;
  bn_t gamma_inverse;
  ec_t p;

  bn_null(q);
  bn_null(x);
  bn_null(s_hat);
  bn_null(k);
  bn_null(e);
  bn_null(v);
  bn_null(gamma_inverse);
  ec_null(p);

  TRY {
    bn_new(q);
    bn_new(x);
    bn_new(s_hat);
    bn_new(k);
    bn_new(e);
    bn_new(v);
    bn_new(gamma_inverse);
    ec_new(p);

    ec_curve_get_ord(q);

    // Deserialize the data from the message.
    bn_read_bin(s_hat, data, RLC_BN_SIZE);

    // Complete the "almost" signature.
    bn_gcd_ext(x, gamma_inverse, NULL, state->gamma, q);
    if (bn_sign(gamma_inverse) == RLC_NEG) {
      bn_add(gamma_inverse, gamma_inverse, q);
    }

    bn_mul(state->s, s_hat, gamma_inverse);
    bn_mod(state->s, state->s, q);

    // Verify the completed signature.
    if (bn_sign(state->r) == RLC_POS && bn_sign(state->s) == RLC_POS && !bn_is_zero(state->s)) {
			if (bn_cmp(state->r, q) == RLC_LT && bn_cmp(state->s, q) == RLC_LT) {
				bn_gcd_ext(e, k, NULL, state->s, q);
        if (bn_sign(k) == RLC_NEG) {
          bn_add(k, k, q);
        }

				md_map(hash, tx, tx_len);
        tx_msg = hash;
        tx_len = RLC_MD_LEN;

				if (8 * tx_len > bn_bits(q)) {
					tx_len = RLC_CEIL(bn_bits(q), 8);
					bn_read_bin(e, tx_msg, tx_len);
					bn_rsh(e, e, 8 * tx_len - bn_bits(q));
				} else {
					bn_read_bin(e, tx_msg, tx_len);
				}

				bn_mul(e, e, k);
        bn_mod(e, e, q);
        bn_mul(v, state->r, k);
        bn_mod(v, v, q);

        ec_mul_sim_gen(p, e, state->ec_pk_tumbler_alice->pk, v);
        ec_get_x(v, p);
        bn_mod(v, v, q);

				verif_status = dv_cmp_const(v->dp, state->r->dp, RLC_MIN(v->used, state->r->used));
				verif_status = (verif_status == RLC_NE ? RLC_ERR : RLC_OK);

				if (v->used != state->r->used) {
					verif_status = RLC_ERR;
				}

        if (ec_is_infty(p)) {
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
    bn_free(x);
    bn_free(s_hat);
    bn_free(k);
    bn_free(e);
    bn_free(v);
    bn_free(gamma_inverse);
    ec_free(p);
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
                                    state->cl_pk_bob,
                                    state->ctx_ec_sk_alice,
                                    state->ctx_ec_sk_bob) != RLC_OK) {
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