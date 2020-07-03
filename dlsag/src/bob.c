#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "relic/relic.h"
#include "pari/pari.h"
#include "zmq.h"
#include "bob.h"
#include "types.h"
#include "util.h"

unsigned PROMISE_COMPLETED;
unsigned PUZZLE_SHARED;
unsigned PUZZLE_SOLVED;
unsigned TOKEN_RECEIVED;

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
    case TOKEN_SHARE:
      return token_share_handler;
    
    case PROMISE_INIT_DONE:
      return promise_init_done_handler;
    
    case PROMISE_SIGN_DONE:
      return promise_sign_done_handler;

    case PROMISE_END_DONE:
      return promise_end_done_handler;

    case PUZZLE_SHARE_DONE:
      return puzzle_share_done_handler;

    case PUZZLE_SOLUTION_SHARE:
      return puzzle_solution_share_handler;

    default:
      fprintf(stderr, "Error: invalid message type.\n");
      exit(1);
  }
}

int handle_message(bob_state_t state, void *socket, zmq_msg_t message) {
  int result_status = RLC_OK;

  message_t msg;
  message_null(msg);

  RLC_TRY {
    printf("Received message size: %ld bytes\n", zmq_msg_size(&message));
    deserialize_message(&msg, (uint8_t *) zmq_msg_data(&message));

    printf("Executing %s...\n", msg->type);
    msg_handler_t msg_handler = get_message_handler(msg->type);
    if (msg_handler(state, socket, msg->data) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    printf("Finished executing %s.\n\n", msg->type);
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (msg != NULL) message_free(msg);
  }

  return result_status;
}

int receive_message(bob_state_t state, void *socket) {
  int result_status = RLC_OK;

  zmq_msg_t message;

  RLC_TRY {
    int rc = zmq_msg_init(&message);
    if (rc != 0) {
      fprintf(stderr, "Error: could not initialize the message.\n");
      RLC_THROW(ERR_CAUGHT);
    }

    rc = zmq_msg_recv(&message, socket, ZMQ_DONTWAIT);
    if (rc != -1 && handle_message(state, socket, message) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    zmq_msg_close(&message);
  }

  return result_status;
}

int token_share_handler(bob_state_t state, void *socet, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  RLC_TRY {    
    // Deserialize the data from the message.
    bn_read_bin(state->tid, data, RLC_BN_SIZE);
    g1_read_bin(state->sigma->sigma_1, data + RLC_BN_SIZE, RLC_G1_SIZE_COMPRESSED);
    g1_read_bin(state->sigma->sigma_2, data + RLC_BN_SIZE + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED);

    TOKEN_RECEIVED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  }

  return result_status;
}

int promise_init(bob_state_t state, void *socket) {
  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;
  
  message_t promise_init_msg;
  message_null(promise_init_msg);

  RLC_TRY {
    // Build and define the message.
    char *msg_type = "promise_init";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_init_msg, msg_type_length, msg_data_length);
    
    // Serialize the message.
    bn_write_bin(promise_init_msg->data, RLC_BN_SIZE, state->tid);
    g1_write_bin(promise_init_msg->data + RLC_BN_SIZE, RLC_G1_SIZE_COMPRESSED, state->sigma->sigma_1, 1);
    g1_write_bin(promise_init_msg->data + RLC_BN_SIZE + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED, state->sigma->sigma_2, 1);

    memcpy(promise_init_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_init_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_init;
    int rc = zmq_msg_init_size(&promise_init, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_init), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_init, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    message_free(promise_init_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int promise_init_done_handler(bob_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  message_t promise_sign_msg;

  bn_t q;
  ec_t pk_to_the_m;
  zk_proof_t pi_A, pi_B;
  zk_proof_cldl_t pi_cldl;

  bn_null(q);
  ec_null(pk_to_the_m);
  zk_proof_null(pi_A);
  zk_proof_null(pi_B);
  zk_proof_cldl_null(pi_cldl);
  message_null(promise_sign_msg);

  RLC_TRY {
    bn_new(q);
    ec_new(pk_to_the_m);
    zk_proof_new(pi_A);
    zk_proof_new(pi_B);
    zk_proof_cldl_new(pi_cldl);

    // Deserialize the data from the message.
    ec_read_bin(state->A, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(state->A_star, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(state->com->c, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);
    ec_read_bin(state->com->r, data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED);

    char ctx_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ctx_str, data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha->c1 = gp_read_str(ctx_str);
    memzero(ctx_str, RLC_CL_CIPHERTEXT_SIZE);
    memcpy(ctx_str, data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha->c2 = gp_read_str(ctx_str);

    char pi_cldl_str[RLC_CLDL_PROOF_T1_SIZE];
    memcpy(pi_cldl_str, data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE),
           RLC_CLDL_PROOF_T1_SIZE);
    pi_cldl->t1 = gp_read_str(pi_cldl_str);
    ec_read_bin(pi_cldl->t2, data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE) 
              + RLC_CLDL_PROOF_T1_SIZE, RLC_EC_SIZE_COMPRESSED);
    memcpy(pi_cldl_str, data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE) 
         + RLC_CLDL_PROOF_T1_SIZE, RLC_CLDL_PROOF_T3_SIZE);
    pi_cldl->t3 = gp_read_str(pi_cldl_str);
    memcpy(pi_cldl_str, data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE) 
         + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE, RLC_CLDL_PROOF_U1_SIZE);
    pi_cldl->u1 = gp_read_str(pi_cldl_str);
    memcpy(pi_cldl_str, data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE) 
         + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE, RLC_CLDL_PROOF_U2_SIZE);
    pi_cldl->u2 = gp_read_str(pi_cldl_str);
    ec_read_bin(pi_A->a, data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE)
                + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_A->b, data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE)
                + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_A->z, data + (6 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE)
                + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE, RLC_BN_SIZE);

    // Verify ZK proof.
    if (zk_cldl_verify(pi_cldl, state->A, state->ctx_alpha, state->tumbler_cl_pk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    ec_mul(pk_to_the_m, state->keys->ec_pk0->pk, state->keys->m);
    if (zk_dhtuple_verify(pi_A, pk_to_the_m, state->A, state->A_star) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Compute R_B, J_B, J_B_tilde, and ZK proof.
    ec_curve_get_ord(q);
    bn_rand_mod(state->vec_s[0], q);
    ec_mul_gen(state->R_B, state->vec_s[0]);

    ec_mul(state->J_B, pk_to_the_m, state->keys->ec_sk1->sk);
    ec_mul(state->J_B_tilde, pk_to_the_m, state->vec_s[0]);

    if (zk_dhtuple_prove(pi_B, pk_to_the_m, state->R_B, state->J_B_tilde, state->vec_s[0]) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "promise_sign";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_sign_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(promise_sign_msg->data, RLC_EC_SIZE_COMPRESSED, state->R_B, 1);
    ec_write_bin(promise_sign_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, state->J_B, 1);
    ec_write_bin(promise_sign_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, state->J_B_tilde, 1);
    ec_write_bin(promise_sign_msg->data + (3 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, pi_B->a, 1);
    ec_write_bin(promise_sign_msg->data + (4 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, pi_B->b, 1);
    bn_write_bin(promise_sign_msg->data + (5 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, pi_B->z);

    memcpy(promise_sign_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_sign_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_sign;
    int rc = zmq_msg_init_size(&promise_sign, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_sign), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_sign, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    ec_free(pk_to_the_m);
    zk_proof_free(pi_A);
    zk_proof_free(pi_B);
    zk_proof_cldl_free(pi_cldl);
    if (promise_sign_msg != NULL) message_free(promise_sign_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int promise_sign_done_handler(bob_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  unsigned tx_len = sizeof(tx);
  uint8_t *tx_msg = malloc(tx_len + RLC_FC_BYTES);
  uint8_t hash[RLC_MD_LEN];
  uint8_t *serialized_message = NULL;
  message_t promise_end_msg;

  bn_t s0_T, h0, h_i;
  ec_t L_i, R_i, R_B_times_R_T, R, R_T;
  ec_t pk_to_the_hn_minus_1, R_B_times_R_T_over_pk;
  ec_t J_T, J_T_tilde, J_T_J_B_tilde_A_star;
  ec_t J_to_the_h_i_minus_1;
  ec_t pk_i_to_the_s_i_times_m_i;
  ec_t pk_i_to_the_h_i;
  ec_t pk_to_the_m;
  ec_t g_to_the_s0_B, g_to_the_s0_T;
  ec_t g_to_the_s0_B_times_s0_T;
  zk_proof_t pi_T;

  bn_t q, r, x;
  ec_t com_x, R_prime;

  bn_null(s0_T);
  bn_null(h0);
  bn_null(h_i);
  ec_null(L_i);
  ec_null(R_i);
  ec_null(R_B_times_R_T);
  ec_null(pk_to_the_hn_minus_1);
  ec_null(R_B_times_R_T_over_pk);
  ec_null(R);
  ec_null(R_T);
  ec_null(J_T);
  ec_null(J_T_tilde);
  ec_null(J_T_J_B_tilde_A_star);
  ec_null(J_to_the_h_i_minus_1);
  ec_null(pk_i_to_the_s_i_times_m_i);
  ec_null(pk_i_to_the_h_i);
  ec_null(pk_to_the_m);
  ec_null(g_to_the_s0_B);
  ec_null(g_to_the_s0_T);
  ec_null(g_to_the_s0_B_times_s0_T);
  zk_proof_null(pi_T);

  bn_null(q);
  bn_null(r);
  bn_null(x);
  ec_null(com_x);
  ec_null(R_prime);

  RLC_TRY {
    bn_new(s0_T);
    bn_new(h0);
    bn_new(h_i);
    ec_new(L_i);
    ec_new(R_i);
    ec_new(R_B_times_R_T);
    ec_new(pk_to_the_hn_minus_1);
    ec_new(R_B_times_R_T_over_pk);
    ec_new(R);
    ec_new(R_T);
    ec_new(J_T);
    ec_new(J_T_tilde);
    ec_new(J_T_J_B_tilde_A_star);
    ec_new(J_to_the_h_i_minus_1);
    ec_new(pk_i_to_the_s_i_times_m_i);
    ec_new(pk_i_to_the_h_i);
    ec_new(pk_to_the_m);
    ec_new(g_to_the_s0_B);
    ec_new(g_to_the_s0_T);
    ec_new(g_to_the_s0_B_times_s0_T);
    zk_proof_new(pi_T);

    bn_new(q);
    bn_new(r);
    bn_new(x);
    ec_new(com_x);
    ec_new(R_prime);

    // Deserialize the data from the message.
    ec_read_bin(R_T, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(J_T, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(J_T_tilde, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_T->a, data + (3 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_T->b, data + (4 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_T->z, data + (5 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);
    bn_read_bin(s0_T, data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE);
    
    for (size_t i = 1; i < RING_SIZE; i++) {
      bn_read_bin(state->vec_s[i], data + (5 * RLC_EC_SIZE_COMPRESSED) + ((i + 2) * RLC_BN_SIZE), RLC_BN_SIZE);
    }

    // Verify the commitment and ZK proof.
    ec_add(com_x, R_T, J_T_tilde);
    ec_add(com_x, com_x, J_T);
    ec_add(com_x, com_x, pi_T->a);
    ec_add(com_x, com_x, pi_T->b);
    ec_norm(com_x, com_x);
    for (size_t i = 1; i < RING_SIZE; i++) {
      ec_mul(com_x, com_x, state->vec_s[i]);
    }
    if (decommit(state->com, com_x) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    ec_mul(pk_to_the_m, state->keys->ec_pk0->pk, state->keys->m);

    if (zk_dhtuple_verify(pi_T, pk_to_the_m, R_T, J_T_tilde) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Compute the half DLSAG signature.
    ec_add(R_B_times_R_T, state->R_B, R_T);
    ec_norm(R_B_times_R_T, R_B_times_R_T);
    ec_add(R, R_B_times_R_T, state->A);
    ec_norm(R, R);

    ec_add(J_T_J_B_tilde_A_star, J_T_tilde, state->J_B_tilde);
    ec_add(J_T_J_B_tilde_A_star, J_T_J_B_tilde_A_star, state->A_star);
    ec_norm(J_T_J_B_tilde_A_star, J_T_J_B_tilde_A_star);
    
    ec_add(R_prime, R, J_T_J_B_tilde_A_star);
    ec_norm(R_prime, R_prime);

    ec_curve_get_ord(q);
    ec_get_x(x, R_prime);
    bn_mod(r, x, q);
    if (bn_is_zero(r)) {
      RLC_THROW(ERR_CAUGHT);
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

    ec_add(state->J, state->J_B, J_T);
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
        RLC_THROW(ERR_CAUGHT);
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

    bn_mul(state->s0_B, h_i, state->keys->ec_sk1->sk);
    bn_sub(state->s0_B, state->vec_s[0], state->s0_B);
    bn_mod(state->s0_B, state->s0_B, q);

    // Check correctness of the partial signature received.
    ec_mul_gen(g_to_the_s0_B, state->s0_B);
    ec_mul_gen(g_to_the_s0_T, s0_T);
    ec_add(g_to_the_s0_B_times_s0_T, g_to_the_s0_B, g_to_the_s0_T);
    ec_norm(g_to_the_s0_B_times_s0_T, g_to_the_s0_B_times_s0_T);

    ec_mul(pk_to_the_hn_minus_1, state->keys->ec_pk1->pk, h_i);
    ec_sub(R_B_times_R_T_over_pk, R_B_times_R_T, pk_to_the_hn_minus_1);
    ec_norm(R_B_times_R_T_over_pk, R_B_times_R_T_over_pk);

    // Compute the "almost" signature.
    bn_add(state->s0, state->s0_B, s0_T);
    bn_mod(state->s0, state->s0, q);
    
    // Build and define the message.
    char *msg_type = "promise_end";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_end_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    bn_write_bin(promise_end_msg->data, RLC_BN_SIZE, state->s0_B);

    memcpy(promise_end_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_end_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_end;
    int rc = zmq_msg_init_size(&promise_end, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_end), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_end, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(s0_T);
    bn_free(h0);
    bn_free(h_i);
    ec_free(L_i);
    ec_free(R_i);
    ec_free(R_B_times_R_T);
    ec_free(pk_to_the_hn_minus_1);
    ec_free(R_B_times_R_T_over_pk);
    ec_free(R);
    ec_free(R_T);
    ec_free(J_T);
    ec_free(J_T_tilde);
    ec_free(J_T_J_B_tilde_A_star);
    ec_free(J_to_the_h_i_minus_1);
    ec_free(pk_i_to_the_s_i_times_m_i);
    ec_free(pk_i_to_the_h_i);
    ec_free(pk_to_the_m);
    ec_free(g_to_the_s0_B);
    ec_free(g_to_the_s0_T);
    ec_free(g_to_the_s0_B_times_s0_T);
    zk_proof_free(pi_T);

    bn_free(q);
    bn_free(r);
    bn_free(x);
    ec_free(com_x);
    ec_free(R_prime);
    free(tx_msg);
    if (serialized_message != NULL) free(serialized_message);
    if (promise_end_msg != NULL) message_free(promise_end_msg);
  }

  return result_status;
}

int promise_end_done_handler(bob_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  PROMISE_COMPLETED = 1;
  return RLC_OK;
}

int puzzle_share(bob_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }
  
  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  
  message_t puzzle_share_msg;
  message_null(puzzle_share_msg);

  cl_ciphertext_t ctx_alpha_times_beta;
  bn_t q;
  ec_t A_prime;

  cl_ciphertext_null(ctx_alpha_times_beta);
  bn_null(q);
  ec_null(A_prime);

  RLC_TRY {
    cl_ciphertext_new(ctx_alpha_times_beta);
    bn_new(q);
    ec_new(A_prime);

    ec_curve_get_ord(q);

    // Randomize the promise challenge.
    GEN beta_prime = randomi(state->cl_params->bound);
    bn_read_str(state->beta, GENtostr(beta_prime), strlen(GENtostr(beta_prime)), 10);
    bn_mod(state->beta, state->beta, q);
    
    ec_mul(A_prime, state->A, state->beta);
    ec_norm(A_prime, A_prime);

    // Homomorphically randomize the challenge ciphertext.
    const unsigned beta_str_len = bn_size_str(state->beta, 10);
    char beta_str[beta_str_len];
    bn_write_str(beta_str, beta_str_len, state->beta, 10);

    GEN plain_beta = strtoi(beta_str);
    ctx_alpha_times_beta->c1 = nupow(state->ctx_alpha->c1, plain_beta, NULL);
    ctx_alpha_times_beta->c2 = nupow(state->ctx_alpha->c2, plain_beta, NULL);

    // Build and define the message.
    char *msg_type = "puzzle_share";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_EC_SIZE_COMPRESSED + (2 * RLC_CL_CIPHERTEXT_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(puzzle_share_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(puzzle_share_msg->data, RLC_EC_SIZE_COMPRESSED, A_prime, 1);
    memcpy(puzzle_share_msg->data + RLC_EC_SIZE_COMPRESSED, GENtostr(ctx_alpha_times_beta->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(puzzle_share_msg->data + RLC_EC_SIZE_COMPRESSED + RLC_CL_CIPHERTEXT_SIZE, GENtostr(ctx_alpha_times_beta->c2), RLC_CL_CIPHERTEXT_SIZE);
    
    // Serialize the message.
    memcpy(puzzle_share_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, puzzle_share_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t puzzle_share;
    int rc = zmq_msg_init_size(&puzzle_share, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&puzzle_share), serialized_message, total_msg_length);
    rc = zmq_msg_send(&puzzle_share, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    cl_ciphertext_free(ctx_alpha_times_beta);
    bn_free(q);
    ec_free(A_prime);
    if (puzzle_share_msg != NULL) message_free(puzzle_share_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int puzzle_share_done_handler(bob_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  PUZZLE_SHARED = 1;
  return RLC_OK;
}

int puzzle_solution_share_handler(bob_state_t state, void *socet, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  unsigned tx_len = sizeof(tx);
  uint8_t *tx_msg = malloc(tx_len + RLC_FC_BYTES);
  uint8_t hash[RLC_MD_LEN];

  bn_t x, r, q, h_i;
  bn_t alpha, alpha_hat, beta_inverse;
  ec_t L_i, R_i, R_prime;
  ec_t J_to_the_h_i_minus_1;
  ec_t pk_i_to_the_h_i;
  ec_t pk_i_to_the_s_i_times_m_i;

  bn_null(x);
  bn_null(r);
  bn_null(q);
  bn_null(alpha);
  bn_null(alpha_hat);
  bn_null(beta_inverse);
  bn_null(h_i);
  ec_null(L_i);
  ec_null(R_i);
  ec_null(R_prime);
  ec_null(J_to_the_h_i_minus_1);
  ec_null(pk_i_to_the_h_i);
  ec_null(pk_i_to_the_s_i_times_m_i);

  RLC_TRY {
    bn_new(x);
    bn_new(r);
    bn_new(q);
    bn_new(alpha);
    bn_new(alpha_hat);
    bn_new(beta_inverse);
    bn_new(h_i);
    ec_new(L_i);
    ec_new(R_i);
    ec_new(R_prime);
    ec_new(J_to_the_h_i_minus_1);
    ec_new(pk_i_to_the_h_i);
    ec_new(pk_i_to_the_s_i_times_m_i);
    
    // Deserialize the data from the message.
    bn_read_bin(alpha_hat, data, RLC_BN_SIZE);

    // Extract the secret alpha.
    ec_curve_get_ord(q);
    bn_gcd_ext(x, beta_inverse, NULL, state->beta, q);
    if (bn_sign(beta_inverse) == RLC_NEG) {
      bn_add(beta_inverse, beta_inverse, q);
    }

    bn_mul(alpha, alpha_hat, beta_inverse);
    bn_mod(alpha, alpha, q);

    // Complete the "almost" signature.
    bn_add(state->s0, state->s0, alpha);
    bn_mod(state->s0, state->s0, q);

    // Verify the completed signature.
    bn_copy(h_i, state->h0);
		for (size_t i = 1; i < RING_SIZE + 1; i++) {
      if (i == RING_SIZE) {
        ec_mul_gen(L_i, state->s0);
        ec_mul(pk_i_to_the_h_i, state->keys->ec_pk1->pk, h_i);
      } else {
        ec_mul_gen(L_i, state->vec_s[i]);
        ec_mul(pk_i_to_the_h_i, state->ring->pk_1[i], h_i);
      }
      ec_add(L_i, L_i, pk_i_to_the_h_i);
      ec_norm(L_i, L_i);

      if (i == RING_SIZE) {
        ec_mul(pk_i_to_the_s_i_times_m_i, state->keys->ec_pk0->pk, state->s0);
        ec_mul(pk_i_to_the_s_i_times_m_i, pk_i_to_the_s_i_times_m_i, state->keys->m);
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
        RLC_THROW(ERR_CAUGHT);
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
      RLC_THROW(ERR_CAUGHT);
    }

    PUZZLE_SOLVED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(x);
    bn_free(r);
    bn_free(q);
    bn_free(alpha)
    bn_free(alpha_hat);
    bn_free(beta_inverse);
    bn_free(h_i);
    ec_free(L_i);
    ec_free(R_i);
    ec_free(R_prime);
    ec_free(J_to_the_h_i_minus_1);
    ec_free(pk_i_to_the_h_i);
    ec_free(pk_i_to_the_s_i_times_m_i);
  }

  return result_status;
}

int main(void)
{
  init();
  int result_status = RLC_OK;
  PROMISE_COMPLETED = 0;
  PUZZLE_SHARED = 0;
  PUZZLE_SOLVED = 0;
  TOKEN_RECEIVED = 0;

  long long start_time, stop_time, total_time;

  bob_state_t state;
  bob_state_null(state);

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

  int rc = zmq_bind(socket, BOB_ENDPOINT);
  if (rc != 0) {
    fprintf(stderr, "Error: could not bind the socket.\n");
    exit(1);
  }

  RLC_TRY {
    bob_state_new(state);

    if (generate_cl_params(state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (read_keys_from_file_alice_bob(BOB_KEY_FILE_PREFIX,
                                      state->keys,
                                      state->tumbler_cl_pk,
                                      state->tumbler_ps_pk,
                                      state->ring) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    while (!TOKEN_RECEIVED) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      exit(1);
    }

    printf("Connecting to Tumbler...\n\n");
    socket = zmq_socket(context, ZMQ_REQ);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    rc = zmq_connect(socket, TUMBLER_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not connect to Alice.\n");
      exit(1);
    }

    start_time = ttimer();
    if (promise_init(state, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    while (!PROMISE_COMPLETED) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("\nPuzzle promise time: %.5f sec\n", total_time / CLOCK_PRECISION);

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      exit(1);
    }

    printf("Connecting to Alice...\n\n");
    socket = zmq_socket(context, ZMQ_REQ);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    rc = zmq_connect(socket, ALICE_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not connect to Alice.\n");
      exit(1);
    }

    if (puzzle_share(state, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    while (!PUZZLE_SHARED) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      exit(1);
    }

    socket = zmq_socket(context, ZMQ_REP);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    rc = zmq_bind(socket, BOB_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not bind the socket.\n");
      exit(1);
    }

    while (!PUZZLE_SOLVED) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }

    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("\nTotal time: %.5f sec\n", total_time / CLOCK_PRECISION);
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bob_state_free(state);
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

  return result_status;
}