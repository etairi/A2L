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
  ec_t pk_to_the_m;
  commit_t com;
  zk_proof_t pi_A;
  zk_proof_cldl_t pi_cldl;
  
  message_null(promise_init_msg);
  bn_null(q);
  ec_null(x);
  ec_null(pk_to_the_m);
  commit_null(com);
  zk_proof_null(pi_A);
  zk_proof_cldl_null(pi_cldl);
  
  TRY {
    bn_new(q);
    ec_new(x);
    ec_new(pk_to_the_m);
    commit_new(com);
    zk_proof_new(pi_A);
    zk_proof_cldl_new(pi_cldl);

    ec_curve_get_ord(q);

    bn_rand_mod(state->alpha, q);
    ec_mul_gen(state->A, state->alpha);

    ec_mul(pk_to_the_m, state->keys_bob->ec_pk0->pk, state->keys_bob->m);
    ec_mul(state->A_star, pk_to_the_m, state->alpha);

    for (size_t i = 0; i < RING_SIZE; i++) {
      bn_rand_mod(state->vec_s[i], q);
    }

    ec_mul(state->J_T, pk_to_the_m, state->keys_bob->ec_sk1->sk);
    ec_mul(state->J_T_tilde, pk_to_the_m, state->vec_s[0]);
    ec_mul_gen(state->R_T, state->vec_s[0]);

    const unsigned alpha_str_len = bn_size_str(state->alpha, 10);
    char alpha_str[alpha_str_len];
    bn_write_str(alpha_str, alpha_str_len, state->alpha, 10);

    GEN plain_alpha = strtoi(alpha_str);
    if (cl_enc(state->ctx_alpha, plain_alpha, state->keys_bob->cl_pk, state->cl_params) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    if (zk_cldl_prove(pi_cldl, plain_alpha, state->ctx_alpha, state->keys_bob->cl_pk, state->cl_params) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }
    if (zk_dhtuple_prove(pi_A, pk_to_the_m, state->A, state->A_star, state->alpha) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }
    if (zk_dhtuple_prove(state->pi_T, pk_to_the_m, state->R_T, state->J_T_tilde, state->vec_s[0]) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    ec_add(x, state->R_T, state->J_T_tilde);
    ec_add(x, x, state->J_T);
    ec_add(x, x, state->pi_T->a);
    ec_add(x, x, state->pi_T->b);
    ec_norm(x, x);
    for (size_t i = 1; i < RING_SIZE; i++) {
      ec_mul(x, x, state->vec_s[i]);
    }
    if (commit(com, x) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "promise_init_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (6 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE) 
    + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T2_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_init_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(promise_init_msg->data, RLC_EC_SIZE_COMPRESSED, state->A, 1);
    ec_write_bin(promise_init_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, state->A_star, 1);
    bn_write_bin(promise_init_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, com->c);
    ec_write_bin(promise_init_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, com->r, 1);
    memcpy(promise_init_msg->data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE,
           GENtostr(state->ctx_alpha->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_init_msg->data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + RLC_CL_CIPHERTEXT_SIZE,
           GENtostr(state->ctx_alpha->c2), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_init_msg->data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE),
           GENtostr(pi_cldl->t1), RLC_CLDL_PROOF_T1_SIZE);
    ec_write_bin(promise_init_msg->data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE) 
              + RLC_CLDL_PROOF_T1_SIZE, RLC_EC_SIZE_COMPRESSED, pi_cldl->t2, 1);
    memcpy(promise_init_msg->data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE, GENtostr(pi_cldl->t3), RLC_CLDL_PROOF_T3_SIZE);
    memcpy(promise_init_msg->data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE, GENtostr(pi_cldl->u1), RLC_CLDL_PROOF_U1_SIZE);
    memcpy(promise_init_msg->data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE, GENtostr(pi_cldl->u2), RLC_CLDL_PROOF_U2_SIZE);
    ec_write_bin(promise_init_msg->data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE, 
           RLC_EC_SIZE_COMPRESSED, pi_A->a, 1);
    ec_write_bin(promise_init_msg->data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE, 
           RLC_EC_SIZE_COMPRESSED, pi_A->b, 1);
    bn_write_bin(promise_init_msg->data + (6 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE, 
           RLC_BN_SIZE, pi_A->z);

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
    ec_free(pk_to_the_m);
    commit_free(com);
    zk_proof_free(pi_A);
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

  bn_t q, r, x, h_i;
  ec_t pk_to_the_m, pk_i_to_the_h_i;
  ec_t pk_i_to_the_s_i_times_m_i;
  ec_t L_i, R_i, J_T_J_B_tilde_A_star;
  ec_t R, R_B, R_prime, J_B, J_B_tilde;
  ec_t J_to_the_h_i_minus_1;
  zk_proof_t pi_B;

  bn_null(q);
  bn_null(r);
  bn_null(x);
  bn_null(h_i);
  ec_null(R_prime);
  ec_null(pk_to_the_m);
  ec_null(pk_i_to_the_h_i);
  ec_null(pk_i_to_the_s_i_times_m_i);
  ec_null(L_i);
  ec_null(R_i);
  ec_null(R);
  ec_null(R_B);
  ec_null(J_T_J_B_tilde_A_star);
  ec_null(J_B);
  ec_null(J_B_tilde);
  ec_null(J_to_the_h_i_minus_1);
  zk_proof_null(pi_B);
  message_null(promise_sign_done_msg);

  TRY {
    bn_new(q);
    bn_new(r);
    bn_new(x);
    bn_new(h_i);
    ec_new(R_prime);
    ec_new(pk_to_the_m);
    ec_new(pk_i_to_the_h_i);
    ec_new(pk_i_to_the_s_i_times_m_i);
    ec_new(L_i);
    ec_new(R_i);
    ec_new(R);
    ec_new(R_B);
    ec_new(J_T_J_B_tilde_A_star);
    ec_new(J_B);
    ec_new(J_B_tilde);
    ec_new(J_to_the_h_i_minus_1);
    zk_proof_new(pi_B);

    // Deserialize the data from the message.
    ec_read_bin(R_B, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(J_B, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(J_B_tilde, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_B->a, data + (3 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_B->b, data + (4 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_B->z, data + (5 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);

    // Verify ZK proof.
    ec_mul(pk_to_the_m, state->keys_bob->ec_pk0->pk, state->keys_bob->m);

    if (zk_dhtuple_verify(pi_B, pk_to_the_m, R_B, J_B_tilde) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    // Compute the half DLSAG signature.
    ec_add(R, state->R_T, R_B);
    ec_add(R, R, state->A);
    ec_norm(R, R);

    ec_add(J_T_J_B_tilde_A_star, state->J_T_tilde, J_B_tilde);
    ec_add(J_T_J_B_tilde_A_star, J_T_J_B_tilde_A_star, state->A_star);
    ec_norm(J_T_J_B_tilde_A_star, J_T_J_B_tilde_A_star);
    
    ec_add(R_prime, R, J_T_J_B_tilde_A_star);
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
			bn_read_bin(state->h0, hash, tx_len);
			bn_rsh(state->h0, state->h0, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(state->h0, hash, RLC_MD_LEN);
		}
		bn_mod(state->h0, state->h0, q);

    ec_add(state->J, state->J_T, J_B);
    ec_norm(state->J, state->J);

    bn_copy(h_i, state->h0);
		for (size_t i = 1; i < RING_SIZE; i++) {
      ec_mul_gen(L_i, state->vec_s[i]);
      ec_mul(pk_i_to_the_h_i, state->ring->pk_1[i], h_i);
      ec_add(L_i, L_i, pk_i_to_the_h_i);
      ec_norm(L_i, L_i);

      ec_mul(pk_i_to_the_s_i_times_m_i, state->ring->pk_0[i], state->vec_s[i]);
      ec_mul(pk_i_to_the_s_i_times_m_i, pk_i_to_the_s_i_times_m_i, state->ring->m[i]);
      ec_mul(J_to_the_h_i_minus_1, state->J, h_i);
      ec_add(R_i, pk_i_to_the_s_i_times_m_i, J_to_the_h_i_minus_1);
      ec_norm(R_i, R_i);

      ec_add(R_prime, L_i, R_i);
      ec_norm(R_prime, R_prime);

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
        bn_read_bin(h_i, hash, tx_len);
        bn_rsh(h_i, h_i, 8 * RLC_MD_LEN - bn_bits(q));
      } else {
        bn_read_bin(h_i, hash, RLC_MD_LEN);
      }
      bn_mod(h_i, h_i, q);
    }

    bn_mul(state->s0_T, h_i, state->keys_bob->ec_sk1->sk);
    bn_sub(state->s0_T, state->vec_s[0], state->s0_T);
    bn_mod(state->s0_T, state->s0_T, q);

    // Build and define the message.
    char *msg_type = "promise_sign_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (5 * RLC_EC_SIZE_COMPRESSED) + ((RING_SIZE + 2) * RLC_BN_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_sign_done_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(promise_sign_done_msg->data, RLC_EC_SIZE_COMPRESSED, state->R_T, 1);
    ec_write_bin(promise_sign_done_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, state->J_T, 1);
    ec_write_bin(promise_sign_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, state->J_T_tilde, 1);
    ec_write_bin(promise_sign_done_msg->data + (3 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, state->pi_T->a, 1);
    ec_write_bin(promise_sign_done_msg->data + (4 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, state->pi_T->b, 1);
    bn_write_bin(promise_sign_done_msg->data + (5 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, state->pi_T->z);
    bn_write_bin(promise_sign_done_msg->data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE, state->s0_T);
    
    for (size_t i = 1; i < RING_SIZE; i++) {
      bn_write_bin(promise_sign_done_msg->data + (5 * RLC_EC_SIZE_COMPRESSED) + ((i + 2) * RLC_BN_SIZE), RLC_BN_SIZE, state->vec_s[i]);
    }

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
    bn_free(h_i);
    ec_free(R_prime);
    ec_free(pk_to_the_m);
    ec_free(pk_i_to_the_h_i);
    ec_free(pk_i_to_the_s_i_times_m_i);
    ec_free(L_i);
    ec_free(R_i);
    ec_free(R);
    ec_free(R_B);
    ec_free(J_T_J_B_tilde_A_star);
    ec_free(J_B);
    ec_free(J_B_tilde);
    ec_free(J_to_the_h_i_minus_1);
    zk_proof_free(pi_B);
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

  unsigned tx_len = sizeof(tx);
  uint8_t *tx_msg = malloc(tx_len + RLC_FC_BYTES);
  uint8_t hash[RLC_MD_LEN];
  uint8_t *serialized_message = NULL;
  message_t promise_end_done_msg;
  message_null(promise_end_done_msg);

  bn_t x, r, q, s0_B, h_i;
  ec_t L_i, R_i, R_prime;
  ec_t J_to_the_h_i_minus_1;
  ec_t pk_i_to_the_h_i;
  ec_t pk_i_to_the_s_i_times_m_i;

  bn_null(x);
  bn_null(r);
  bn_null(q);
  bn_null(s0_B);
  bn_null(h_i);
  ec_null(L_i);
  ec_null(R_i);
  ec_null(R_prime);
  ec_null(J_to_the_h_i_minus_1);
  ec_null(pk_i_to_the_h_i);
  ec_null(pk_i_to_the_s_i_times_m_i);

  TRY {
    bn_new(x);
    bn_new(r);
    bn_new(q);
    bn_new(s0_B);
    bn_new(h_i);
    ec_new(L_i);
    ec_new(R_i);
    ec_new(R_prime);
    ec_new(J_to_the_h_i_minus_1);
    ec_new(pk_i_to_the_h_i);
    ec_new(pk_i_to_the_s_i_times_m_i);

    // Deserialize the data from the message.
    bn_read_bin(s0_B, data, RLC_BN_SIZE);

    // Complete the signature.
    ec_curve_get_ord(q);

    bn_add(state->s0, state->s0_T, s0_B);
    bn_add(state->s0, state->s0, state->alpha);
    bn_mod(state->s0, state->s0, q);

    // Check correctness of the completed signature.
    bn_copy(h_i, state->h0);
		for (size_t i = 1; i < RING_SIZE + 1; i++) {
      if (i == RING_SIZE) {
        ec_mul_gen(L_i, state->s0);
        ec_mul(pk_i_to_the_h_i, state->keys_bob->ec_pk1->pk, h_i);
      } else {
        ec_mul_gen(L_i, state->vec_s[i]);
        ec_mul(pk_i_to_the_h_i, state->ring->pk_1[i], h_i);
      }
      ec_add(L_i, L_i, pk_i_to_the_h_i);
      ec_norm(L_i, L_i);

      if (i == RING_SIZE) {
        ec_mul(pk_i_to_the_s_i_times_m_i, state->keys_bob->ec_pk0->pk, state->s0);
        ec_mul(pk_i_to_the_s_i_times_m_i, pk_i_to_the_s_i_times_m_i, state->keys_bob->m);
      } else {
        ec_mul(pk_i_to_the_s_i_times_m_i, state->ring->pk_0[i], state->vec_s[i]);
        ec_mul(pk_i_to_the_s_i_times_m_i, pk_i_to_the_s_i_times_m_i, state->ring->m[i]);
      }
      ec_mul(J_to_the_h_i_minus_1, state->J, h_i);
      ec_add(R_i, pk_i_to_the_s_i_times_m_i, J_to_the_h_i_minus_1);
      ec_norm(R_i, R_i);

      ec_add(R_prime, L_i, R_i);
      ec_norm(R_prime, R_prime);

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
        bn_read_bin(h_i, hash, tx_len);
        bn_rsh(h_i, h_i, 8 * RLC_MD_LEN - bn_bits(q));
      } else {
        bn_read_bin(h_i, hash, RLC_MD_LEN);
      }
      bn_mod(h_i, h_i, q);
    }

    if (bn_cmp(state->h0, h_i) != RLC_EQ) {
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
    bn_free(x);
    bn_free(r);
    bn_free(q);
    bn_free(s0_B);
    bn_free(h_i);
    ec_free(L_i);
    ec_free(R_i);
    ec_free(R_prime);
    ec_free(J_to_the_h_i_minus_1);
    ec_free(pk_i_to_the_h_i);
    ec_free(pk_i_to_the_s_i_times_m_i);
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
  ec_t x, pk_to_the_m;
  commit_t com;

  bn_null(q);
  ec_null(x);
  ec_null(pk_to_the_m);
  commit_null(com);
  message_null(payment_init_msg);

  TRY {
    bn_new(q);
    ec_new(x);
    ec_new(pk_to_the_m);
    commit_new(com);

    ec_curve_get_ord(q);

    for (size_t i = 0; i < RING_SIZE; i++) {
      bn_rand_mod(state->vec_s[i], q);
    }

    ec_mul(pk_to_the_m, state->keys_alice->ec_pk0->pk, state->keys_alice->m);
    ec_mul(state->J_T, pk_to_the_m, state->keys_alice->ec_sk1->sk);
    ec_mul(state->J_T_tilde, pk_to_the_m, state->vec_s[0]);

    ec_mul_gen(state->R_T, state->vec_s[0]);

    if (zk_dhtuple_prove(state->pi_T, pk_to_the_m, state->R_T, state->J_T_tilde, state->vec_s[0]) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    ec_add(x, state->R_T, state->J_T_tilde);
    ec_add(x, x, state->J_T);
    ec_add(x, x, state->pi_T->a);
    ec_add(x, x, state->pi_T->b);
    ec_norm(x, x);
    for (size_t i = 1; i < RING_SIZE; i++) {
      ec_mul(x, x, state->vec_s[i]);
    }
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
    ec_free(pk_to_the_m);
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
  bn_t q, r, x, h_i;
  ec_t A_pprime, A_star_pprime;
  ec_t pk_to_the_m, pk_i_to_the_h_i;
  ec_t pk_i_to_the_s_i_times_m_i;
  ec_t L_i, R_i, J_T_J_A_tilde_A_star;
  ec_t R, R_A, R_prime, J_A, J_A_tilde;
  ec_t J_to_the_h_i_minus_1;
  zk_proof_t pi_A;

  bn_null(q);
  bn_null(r);
  bn_null(x);
  bn_null(h_i);
  ec_null(A_pprime);
  ec_null(A_star_pprime);
  ec_null(R_prime);
  ec_null(pk_to_the_m);
  ec_null(pk_i_to_the_h_i);
  ec_null(pk_i_to_the_s_i_times_m_i);
  ec_null(L_i);
  ec_null(R_i);
  ec_null(R);
  ec_null(R_A);
  ec_null(J_T_J_A_tilde_A_star);
  ec_null(J_A);
  ec_null(J_A_tilde);
  ec_null(J_to_the_h_i_minus_1);
  zk_proof_null(pi_A);

  TRY {
    cl_ciphertext_new(ctx_alpha_times_beta_times_tau);
    bn_new(q);
    bn_new(r);
    bn_new(x);
    bn_new(h_i);
    ec_new(A_pprime);
    ec_new(A_star_pprime);
    ec_new(R_prime);
    ec_new(pk_to_the_m);
    ec_new(pk_i_to_the_h_i);
    ec_new(pk_i_to_the_s_i_times_m_i);
    ec_new(L_i);
    ec_new(R_i);
    ec_new(R);
    ec_new(R_A);
    ec_new(J_T_J_A_tilde_A_star);
    ec_new(J_A);
    ec_new(J_A_tilde);
    ec_new(J_to_the_h_i_minus_1);
    zk_proof_new(pi_A);

    // Deserialize the data from the message.
    ec_read_bin(R_A, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(J_A, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(J_A_tilde, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_A->a, data + (3 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_A->b, data + (4 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_A->z, data + (5 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);

    char ct_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ct_str, data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx_alpha_times_beta_times_tau->c1 = gp_read_str(ct_str);
    memcpy(ct_str, data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx_alpha_times_beta_times_tau->c2 = gp_read_str(ct_str);

    // Decrypt the ciphertext.
    GEN gamma;
    if (cl_dec(&gamma, ctx_alpha_times_beta_times_tau, state->keys_alice->cl_sk, state->cl_params) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }
    bn_read_str(state->gamma, GENtostr(gamma), strlen(GENtostr(gamma)), 10);

    // Verify ZK proof.
    ec_mul(pk_to_the_m, state->keys_alice->ec_pk0->pk, state->keys_alice->m);

    if (zk_dhtuple_verify(pi_A, pk_to_the_m, R_A, J_A_tilde) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    // Compute the half DLSAG signature.
    ec_mul_gen(A_pprime, state->gamma);
    ec_mul(A_star_pprime, pk_to_the_m, state->gamma);

    if (zk_dhtuple_prove(pi_A, pk_to_the_m, A_pprime, A_star_pprime, state->gamma) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    ec_add(R, state->R_T, R_A);
    ec_add(R, R, A_pprime);
    ec_norm(R, R);

    ec_add(J_T_J_A_tilde_A_star, state->J_T_tilde, J_A_tilde);
    ec_add(J_T_J_A_tilde_A_star, J_T_J_A_tilde_A_star, A_star_pprime);
    ec_norm(J_T_J_A_tilde_A_star, J_T_J_A_tilde_A_star);

    ec_add(R_prime, R, J_T_J_A_tilde_A_star);
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
			bn_read_bin(state->h0, hash, tx_len);
			bn_rsh(state->h0, state->h0, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(state->h0, hash, RLC_MD_LEN);
		}
		bn_mod(state->h0, state->h0, q);

    ec_add(state->J, state->J_T, J_A);
    ec_norm(state->J, state->J);

    bn_copy(h_i, state->h0);
		for (size_t i = 1; i < RING_SIZE; i++) {
      ec_mul_gen(L_i, state->vec_s[i]);
      ec_mul(pk_i_to_the_h_i, state->ring->pk_1[i], h_i);
      ec_add(L_i, L_i, pk_i_to_the_h_i);
      ec_norm(L_i, L_i);

      ec_mul(pk_i_to_the_s_i_times_m_i, state->ring->pk_0[i], state->vec_s[i]);
      ec_mul(pk_i_to_the_s_i_times_m_i, pk_i_to_the_s_i_times_m_i, state->ring->m[i]);
      ec_mul(J_to_the_h_i_minus_1, state->J, h_i);
      ec_add(R_i, pk_i_to_the_s_i_times_m_i, J_to_the_h_i_minus_1);
      ec_norm(R_i, R_i);

      ec_add(R_prime, L_i, R_i);
      ec_norm(R_prime, R_prime);

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
        bn_read_bin(h_i, hash, tx_len);
        bn_rsh(h_i, h_i, 8 * RLC_MD_LEN - bn_bits(q));
      } else {
        bn_read_bin(h_i, hash, RLC_MD_LEN);
      }
      bn_mod(h_i, h_i, q);
    }

    bn_mul(state->s0_T, h_i, state->keys_alice->ec_sk1->sk);
    bn_sub(state->s0_T, state->vec_s[0], state->s0_T);
    bn_mod(state->s0_T, state->s0_T, q);
   
    // Build and define the message.
    char *msg_type = "payment_sign_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (9 * RLC_EC_SIZE_COMPRESSED) + ((RING_SIZE + 4) * RLC_BN_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_sign_done_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(payment_sign_done_msg->data, RLC_EC_SIZE_COMPRESSED, state->R_T, 1);
    ec_write_bin(payment_sign_done_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, state->J_T, 1);
    ec_write_bin(payment_sign_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, state->J_T_tilde, 1);
    ec_write_bin(payment_sign_done_msg->data + (3 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, state->pi_T->a, 1);
    ec_write_bin(payment_sign_done_msg->data + (4 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, state->pi_T->b, 1);
    bn_write_bin(payment_sign_done_msg->data + (5 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, state->pi_T->z);
    bn_write_bin(payment_sign_done_msg->data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE, state->s0_T);
    bn_write_bin(payment_sign_done_msg->data + (5 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_BN_SIZE, state->h0);
    ec_write_bin(payment_sign_done_msg->data + (5 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED, A_pprime, 1);
    ec_write_bin(payment_sign_done_msg->data + (6 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED, A_star_pprime, 1);
    ec_write_bin(payment_sign_done_msg->data + (7 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED, pi_A->a, 1);
    ec_write_bin(payment_sign_done_msg->data + (8 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED, pi_A->b, 1);
    bn_write_bin(payment_sign_done_msg->data + (9 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), RLC_BN_SIZE, pi_A->z);

    for (size_t i = 1; i < RING_SIZE; i++) {
      bn_write_bin(payment_sign_done_msg->data + (9 * RLC_EC_SIZE_COMPRESSED) + ((i + 4) * RLC_BN_SIZE), RLC_BN_SIZE, state->vec_s[i]);
    }

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
    bn_free(h_i);
    ec_free(A_pprime);
    ec_free(A_star_pprime);
    ec_free(R_prime);
    ec_free(pk_to_the_m);
    ec_free(pk_i_to_the_h_i);
    ec_free(pk_i_to_the_s_i_times_m_i);
    ec_free(L_i);
    ec_free(R_i);
    ec_free(R);
    ec_free(R_A);
    ec_free(J_T_J_A_tilde_A_star);
    ec_free(J_A);
    ec_free(J_A_tilde);
    ec_free(J_to_the_h_i_minus_1);
    zk_proof_free(pi_A);
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

  unsigned tx_len = sizeof(tx);
  uint8_t *tx_msg = malloc(tx_len + RLC_FC_BYTES);
  uint8_t hash[RLC_MD_LEN];
  uint8_t *serialized_message = NULL;
  message_t puzzle_solve_msg;
  message_null(puzzle_solve_msg);

  bn_t x, r, q, s0_A, h_i;
  ec_t L_i, R_i, R_prime;
  ec_t J_to_the_h_i_minus_1;
  ec_t pk_i_to_the_h_i;
  ec_t pk_i_to_the_s_i_times_m_i;

  bn_null(x);
  bn_null(r);
  bn_null(q);
  bn_null(s0_A);
  bn_null(h_i);
  ec_null(L_i);
  ec_null(R_i);
  ec_null(R_prime);
  ec_null(J_to_the_h_i_minus_1);
  ec_null(pk_i_to_the_h_i);
  ec_null(pk_i_to_the_s_i_times_m_i);

  TRY {
    bn_new(x);
    bn_new(r);
    bn_new(q);
    bn_new(s0_A);
    bn_new(h_i);
    ec_new(L_i);
    ec_new(R_i);
    ec_new(R_prime);
    ec_new(J_to_the_h_i_minus_1);
    ec_new(pk_i_to_the_h_i);
    ec_new(pk_i_to_the_s_i_times_m_i);

    // Deserialize the data from the message.
    bn_read_bin(s0_A, data, RLC_BN_SIZE);

    // Complete the signature.
    ec_curve_get_ord(q);

    bn_add(state->s0, state->s0_T, s0_A);
    bn_add(state->s0, state->s0, state->gamma);
    bn_mod(state->s0, state->s0, q);

    // Check correctness of the completed signature.
    bn_copy(h_i, state->h0);
		for (size_t i = 1; i < RING_SIZE + 1; i++) {
      if (i == RING_SIZE) {
        ec_mul_gen(L_i, state->s0);
        ec_mul(pk_i_to_the_h_i, state->keys_alice->ec_pk1->pk, h_i);
      } else {
        ec_mul_gen(L_i, state->vec_s[i]);
        ec_mul(pk_i_to_the_h_i, state->ring->pk_1[i], h_i);
      }
      ec_add(L_i, L_i, pk_i_to_the_h_i);
      ec_norm(L_i, L_i);

      if (i == RING_SIZE) {
        ec_mul(pk_i_to_the_s_i_times_m_i, state->keys_alice->ec_pk0->pk, state->s0);
        ec_mul(pk_i_to_the_s_i_times_m_i, pk_i_to_the_s_i_times_m_i, state->keys_alice->m);
      } else {
        ec_mul(pk_i_to_the_s_i_times_m_i, state->ring->pk_0[i], state->vec_s[i]);
        ec_mul(pk_i_to_the_s_i_times_m_i, pk_i_to_the_s_i_times_m_i, state->ring->m[i]);
      }
      ec_mul(J_to_the_h_i_minus_1, state->J, h_i);
      ec_add(R_i, pk_i_to_the_s_i_times_m_i, J_to_the_h_i_minus_1);
      ec_norm(R_i, R_i);

      ec_add(R_prime, L_i, R_i);
      ec_norm(R_prime, R_prime);

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
        bn_read_bin(h_i, hash, tx_len);
        bn_rsh(h_i, h_i, 8 * RLC_MD_LEN - bn_bits(q));
      } else {
        bn_read_bin(h_i, hash, RLC_MD_LEN);
      }
      bn_mod(h_i, h_i, q);
    }

    if (bn_cmp(state->h0, h_i) != RLC_EQ) {
      THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "puzzle_solve";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(puzzle_solve_msg, msg_type_length, msg_data_length);
    
    // Serialize the data for the message.
    bn_write_bin(puzzle_solve_msg->data, RLC_BN_SIZE, state->s0);

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
    bn_free(x);
    bn_free(r);
    bn_free(q);
    bn_free(s0_A);
    bn_free(h_i);
    ec_free(L_i);
    ec_free(R_i);
    ec_free(R_prime);
    ec_free(J_to_the_h_i_minus_1);
    ec_free(pk_i_to_the_h_i);
    ec_free(pk_i_to_the_s_i_times_m_i);
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

    if (read_keys_from_file_tumbler(state->keys_alice,
                                    state->keys_bob,
                                    state->cl_pk_alice,
                                    state->cl_pk_bob,
                                    state->ring) != RLC_OK) {
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