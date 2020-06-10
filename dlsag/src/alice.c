#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "relic/relic.h"
#include "pari/pari.h"
#include "zmq.h"
#include "alice.h"
#include "types.h"
#include "util.h"

unsigned PUZZLE_SHARED;
unsigned PUZZLE_SOLVED;

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
    case PUZZLE_SHARE:
      return puzzle_share_handler;

    case PAYMENT_INIT_DONE:
      return payment_init_done_handler;

    case PAYMENT_SIGN_DONE:
      return payment_sign_done_handler;

    case PUZZLE_SOLVE:
      return puzzle_solve_handler;

    default:
      fprintf(stderr, "Error: invalid message type.\n");
      exit(1);
  }
}

int handle_message(alice_state_t state, void *socket, zmq_msg_t message) {
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

int receive_message(alice_state_t state, void *socket) {
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

int puzzle_share_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  message_t puzzle_share_done_msg;

  RLC_TRY {
    // Deserialize the data from the message.
    ec_read_bin(state->A_prime, data, RLC_EC_SIZE_COMPRESSED);
    
    char ctx_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ctx_str, data + RLC_EC_SIZE_COMPRESSED, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha_times_beta->c1 = gp_read_str(ctx_str);
    memzero(ctx_str, RLC_CL_CIPHERTEXT_SIZE);
    memcpy(ctx_str, data + RLC_EC_SIZE_COMPRESSED + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha_times_beta->c2 = gp_read_str(ctx_str);

    // Build and define the message.
    char *msg_type = "puzzle_share_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = 0;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(puzzle_share_done_msg, msg_type_length, msg_data_length);
    
    // Serialize the message.
    memcpy(puzzle_share_done_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, puzzle_share_done_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_share_done;
    int rc = zmq_msg_init_size(&promise_share_done, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_share_done), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_share_done, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    PUZZLE_SHARED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (puzzle_share_done_msg != NULL) message_free(puzzle_share_done_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int payment_init(void *socket) {
  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;
  
  message_t payment_init_msg;
  message_null(payment_init_msg);

  RLC_TRY {
    // Build and define the message.
    char *msg_type = "payment_init";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = 0;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_init_msg, msg_type_length, msg_data_length);
    
    // Serialize the message.
    memcpy(payment_init_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_init_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_init;
    int rc = zmq_msg_init_size(&payment_init, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_init), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_init, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      printf("%s\n", zmq_strerror(errno));
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    message_free(payment_init_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int payment_init_done_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;

  message_t payment_sign_msg;
  message_null(payment_sign_msg);

  cl_ciphertext_t ctx_alpha_times_beta_times_tau;
  bn_t q;
  ec_t pk_to_the_m;
  zk_proof_t pi_A;

  cl_ciphertext_null(ctx_alpha_times_beta_times_tau);
  bn_null(q);
  ec_null(pk_to_the_m);
  zk_proof_null(pi_A);

  RLC_TRY {
    cl_ciphertext_new(ctx_alpha_times_beta_times_tau);
    bn_new(q);
    ec_new(pk_to_the_m);
    zk_proof_new(pi_A);

    // Deserialize the data from the message.
    bn_read_bin(state->com->c, data, RLC_BN_SIZE);
    ec_read_bin(state->com->r, data + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED);

    // Homomorphically randomize the challenge ciphertext.
    ec_curve_get_ord(q);
    bn_rand_mod(state->tau, q);

    const unsigned tau_str_len = bn_size_str(state->tau, 10);
    char tau_str[tau_str_len];
    bn_write_str(tau_str, tau_str_len, state->tau, 10);

    GEN plain_tau = strtoi(tau_str);
    ctx_alpha_times_beta_times_tau->c1 = nupow(state->ctx_alpha_times_beta->c1, plain_tau, NULL);
    ctx_alpha_times_beta_times_tau->c2 = nupow(state->ctx_alpha_times_beta->c2, plain_tau, NULL);

    // Compute R_B, J_B, J_B_tilde, and ZK proof.
    bn_rand_mod(state->vec_s[0], q);
    ec_mul_gen(state->R_A, state->vec_s[0]);

    ec_mul(pk_to_the_m, state->keys->ec_pk0->pk, state->keys->m);
    ec_mul(state->J_A, pk_to_the_m, state->keys->ec_sk1->sk);
    ec_mul(state->J_A_tilde, pk_to_the_m, state->vec_s[0]);

    if (zk_dhtuple_prove(pi_A, pk_to_the_m, state->R_A, state->J_A_tilde, state->vec_s[0]) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "payment_sign";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_sign_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(payment_sign_msg->data, RLC_EC_SIZE_COMPRESSED, state->R_A, 1);
    ec_write_bin(payment_sign_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, state->J_A, 1);
    ec_write_bin(payment_sign_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, state->J_A_tilde, 1);
    ec_write_bin(payment_sign_msg->data + (3 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, pi_A->a, 1);
    ec_write_bin(payment_sign_msg->data + (4 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, pi_A->b, 1);
    bn_write_bin(payment_sign_msg->data + (5 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, pi_A->z);
    memcpy(payment_sign_msg->data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE,
           GENtostr(ctx_alpha_times_beta_times_tau->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(payment_sign_msg->data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + RLC_CL_CIPHERTEXT_SIZE,
           GENtostr(ctx_alpha_times_beta_times_tau->c2), RLC_CL_CIPHERTEXT_SIZE);

    // Serialize the message.
    memcpy(payment_sign_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_sign_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_sign;
    int rc = zmq_msg_init_size(&payment_sign, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_sign), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_sign, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    cl_ciphertext_free(ctx_alpha_times_beta_times_tau);
    bn_free(q);
    ec_free(pk_to_the_m);
    zk_proof_free(pi_A);
    if (payment_sign_msg != NULL) message_free(payment_sign_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int payment_sign_done_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  unsigned tx_len = sizeof(tx);
  uint8_t *tx_msg = malloc(tx_len + RLC_FC_BYTES);
  uint8_t hash[RLC_MD_LEN];
  uint8_t *serialized_message = NULL;

  message_t payment_end_msg;
  message_null(payment_end_msg);

  bn_t s0_T, h0, h_i;
  ec_t L_i, R_i, R, R_T, R_A_times_R_T; 
  ec_t R_A_times_R_T_over_pk, J_T, J_T_tilde;
  ec_t J_T_J_A_tilde_A_star;
  ec_t J_to_the_h_i_minus_1;
  ec_t pk_i_to_the_s_i_times_m_i;
  ec_t pk_i_to_the_h_i;
  ec_t pk_to_the_m;
  ec_t pk_to_the_hn_minus_1;
  ec_t g_to_the_s0_A, g_to_the_s0_T;
  ec_t g_to_the_s0_A_times_s0_T;
  ec_t A_prime_to_the_tau;
  ec_t A_pprime, A_star_pprime;
  zk_proof_t pi_A, pi_T;

  bn_t q, r, x;
  ec_t com_x, R_prime;

  bn_null(s0_T);
  bn_null(h0);
  bn_null(h_i);
  ec_null(L_i);
  ec_null(R_i);
  ec_null(R);
  ec_null(R_T);
  ec_null(R_A_times_R_T);
  ec_null(R_A_times_R_T_over_pk);
  ec_null(J_T);
  ec_null(J_T_tilde);
  ec_null(J_T_J_A_tilde_A_star);
  ec_null(J_to_the_h_i_minus_1);
  ec_null(pk_i_to_the_s_i_times_m_i);
  ec_null(pk_i_to_the_h_i);
  ec_null(pk_to_the_m);
  ec_null(pk_to_the_hn_minus_1);
  ec_null(g_to_the_s0_A);
  ec_null(g_to_the_s0_T);
  ec_null(g_to_the_s0_A_times_s0_T);
  ec_null(A_prime_to_the_tau);
  ec_null(A_pprime);
  ec_null(A_star_pprime);
  zk_proof_null(pi_A);
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
    ec_new(R);
    ec_new(R_T);
    ec_new(R_A_times_R_T);
    ec_new(R_A_times_R_T_over_pk);
    ec_new(J_T);
    ec_new(J_T_tilde);
    ec_new(J_T_J_A_tilde_A_star);
    ec_new(J_to_the_h_i_minus_1);
    ec_new(pk_i_to_the_s_i_times_m_i);
    ec_new(pk_i_to_the_h_i);
    ec_new(pk_to_the_m);
    ec_new(pk_to_the_hn_minus_1);
    ec_new(g_to_the_s0_A);
    ec_new(g_to_the_s0_T);
    ec_new(g_to_the_s0_A_times_s0_T);
    ec_new(A_prime_to_the_tau);
    ec_new(A_pprime);
    ec_new(A_star_pprime);
    zk_proof_new(pi_A);
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
    bn_read_bin(h0, data + (5 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_BN_SIZE);
    ec_read_bin(A_pprime, data + (5 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(A_star_pprime, data + (6 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_A->a, data + (7 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_A->b, data + (8 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_A->z, data + (9 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), RLC_BN_SIZE);

    for (size_t i = 1; i < RING_SIZE; i++) {
      bn_read_bin(state->vec_s[i], data + (9 * RLC_EC_SIZE_COMPRESSED) + ((i + 4) * RLC_BN_SIZE), RLC_BN_SIZE);
    }

    // Verify the commitment and ZK proofs.
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
    if (zk_dhtuple_verify(pi_A, pk_to_the_m, A_pprime, A_star_pprime) != RLC_OK) {
      printf("REACHED!\n");
      RLC_THROW(ERR_CAUGHT);
    }

    // Sanity check.
    ec_mul(A_prime_to_the_tau, state->A_prime, state->tau);
    ec_norm(A_prime_to_the_tau, A_prime_to_the_tau);
    if (ec_cmp(A_prime_to_the_tau, A_pprime) != RLC_EQ) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Compute the half DLSAG signature.
    ec_add(R_A_times_R_T, state->R_A, R_T);
    ec_norm(R_A_times_R_T, R_A_times_R_T);
    ec_add(R, R_A_times_R_T, A_pprime);
    ec_norm(R, R);

    ec_add(J_T_J_A_tilde_A_star, J_T_tilde, state->J_A_tilde);
    ec_add(J_T_J_A_tilde_A_star, J_T_J_A_tilde_A_star, A_star_pprime);
    ec_norm(J_T_J_A_tilde_A_star, J_T_J_A_tilde_A_star);
    
    ec_add(R_prime, R, J_T_J_A_tilde_A_star);
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

    ec_add(state->J, state->J_A, J_T);
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

    bn_mul(state->s0_A, h_i, state->keys->ec_sk1->sk);
    bn_sub(state->s0_A, state->vec_s[0], state->s0_A);
    bn_mod(state->s0_A, state->s0_A, q);
    
    // Check correctness of the partial signature received.
    ec_mul_gen(g_to_the_s0_A, state->s0_A);
    ec_mul_gen(g_to_the_s0_T, s0_T);
    ec_add(g_to_the_s0_A_times_s0_T, g_to_the_s0_A, g_to_the_s0_T);
    ec_norm(g_to_the_s0_A_times_s0_T, g_to_the_s0_A_times_s0_T);

    ec_mul(pk_to_the_hn_minus_1, state->keys->ec_pk1->pk, h_i);
    ec_sub(R_A_times_R_T_over_pk, R_A_times_R_T, pk_to_the_hn_minus_1);
    ec_norm(R_A_times_R_T_over_pk, R_A_times_R_T_over_pk);

    if (ec_cmp(g_to_the_s0_A_times_s0_T, R_A_times_R_T_over_pk) != RLC_EQ) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Compute the "almost" signature.
    bn_add(state->s0, state->s0_A, s0_T);
    bn_mod(state->s0, state->s0, q);

    // Build and define the message.
    char *msg_type = "payment_end";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_end_msg, msg_type_length, msg_data_length);
    
    // Serialize the data for the message.
    bn_write_bin(payment_end_msg->data, RLC_BN_SIZE, state->s0_A);

    // Serialize the message.
    memcpy(payment_end_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_end_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_end;
    int rc = zmq_msg_init_size(&payment_end, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_end), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_end, socket, ZMQ_DONTWAIT);
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
    ec_free(R);
    ec_free(R_T);
    ec_free(R_A_times_R_T);
    ec_free(R_A_times_R_T_over_pk);
    ec_free(J_T);
    ec_free(J_T_tilde);
    ec_free(J_T_J_A_tilde_A_star);
    ec_free(J_to_the_h_i_minus_1);
    ec_free(pk_i_to_the_s_i_times_m_i);
    ec_free(pk_i_to_the_h_i);
    ec_free(pk_to_the_m);
    ec_free(pk_to_the_hn_minus_1);
    ec_free(g_to_the_s0_A);
    ec_free(g_to_the_s0_T);
    ec_free(g_to_the_s0_A_times_s0_T);
    ec_free(A_prime_to_the_tau);
    ec_free(A_pprime);
    ec_free(A_star_pprime);
    zk_proof_free(pi_A);
    zk_proof_free(pi_T);

    bn_free(q);
    bn_free(r);
    bn_free(x);
    ec_free(com_x);
    ec_free(R_prime);
    free(tx_msg);
    if (payment_end_msg != NULL) message_free(payment_end_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int puzzle_solve_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  bn_t x, q, s0_final; 
  bn_t gamma, tau_inverse;

  bn_null(x);
  bn_null(q);
  bn_null(s0_final);
  bn_null(gamma);
  bn_null(tau_inverse);

  RLC_TRY {
    bn_new(x);
    bn_new(q);
    bn_new(s0_final);
    bn_new(gamma);
    bn_new(tau_inverse);
    
    // Deserialize the data from the message.
    bn_read_bin(s0_final, data, RLC_BN_SIZE);

    // Extract the randomized secret.
    ec_curve_get_ord(q);

    bn_sub(gamma, s0_final, state->s0);
    bn_mod(gamma, gamma, q);

    bn_gcd_ext(x, tau_inverse, NULL, state->tau, q);
    if (bn_sign(tau_inverse) == RLC_NEG) {
      bn_add(tau_inverse, tau_inverse, q);
    }

    bn_mul(state->alpha_hat, gamma, tau_inverse);
    bn_mod(state->alpha_hat, state->alpha_hat, q);

    PUZZLE_SOLVED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(x);
    bn_free(q);
    bn_free(s0_final);
    bn_free(gamma);
    bn_free(tau_inverse);
  }

  return result_status;
}

int puzzle_solution_send(alice_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;

  message_t puzzle_solution_send_msg;
  message_null(puzzle_solution_send_msg);

  RLC_TRY {
    // Build and define the message.
    char *msg_type = "puzzle_solution_share";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(puzzle_solution_send_msg, msg_type_length, msg_data_length);
    
    // Serialize the data for the message.
    bn_write_bin(puzzle_solution_send_msg->data, RLC_BN_SIZE, state->alpha_hat);

    // Serialize the message.
    memcpy(puzzle_solution_send_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, puzzle_solution_send_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t puzzle_solution_send;
    int rc = zmq_msg_init_size(&puzzle_solution_send, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&puzzle_solution_send), serialized_message, total_msg_length);
    rc = zmq_msg_send(&puzzle_solution_send, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    message_free(puzzle_solution_send_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int main(void)
{
  init();
  int result_status = RLC_OK;
  PUZZLE_SHARED = 0;
  PUZZLE_SOLVED = 0;

  long long start_time, stop_time, total_time;

  alice_state_t state;
  alice_state_null(state);

  // Socket to talk to other parties.
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

  int rc = zmq_bind(socket, ALICE_ENDPOINT);
  if (rc != 0) {
    fprintf(stderr, "Error: could not bind the socket.\n");
    exit(1);
  }

  RLC_TRY {
    alice_state_new(state);

    if (read_keys_from_file_alice_bob(ALICE_KEY_FILE_PREFIX,
                                      state->keys,
                                      state->tumbler_cl_pk,
                                      state->ring) != RLC_OK) {
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
      RLC_THROW(ERR_CAUGHT);
    }

    printf("Connecting to Tumbler...\n\n");
    socket = zmq_socket(context, ZMQ_REQ);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    rc = zmq_connect(socket, TUMBLER_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not connect to Tumbler.\n");
      RLC_THROW(ERR_CAUGHT);
    }

    start_time = ttimer();
    if (payment_init(socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    while (!PUZZLE_SOLVED) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("\nPuzzle solver time: %.5f sec\n", total_time / CLOCK_PRECISION);

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      RLC_THROW(ERR_CAUGHT);
    }

    printf("Connecting to Bob...\n\n");
    socket = zmq_socket(context, ZMQ_REQ);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    rc = zmq_connect(socket, BOB_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not connect to Bob.\n");
      RLC_THROW(ERR_CAUGHT);
    }

    if (puzzle_solution_send(state, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    alice_state_free(state);
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