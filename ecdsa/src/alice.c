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

int receive_message(alice_state_t state, void *socket) {
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

int puzzle_share_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  message_t puzzle_share_done_msg;

  TRY {
    // Deserialize the data from the message.
    ec_read_bin(state->g_to_the_alpha_times_beta, data, RLC_EC_SIZE_COMPRESSED);

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
      THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_share_done), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_share_done, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }

    PUZZLE_SHARED = 1;
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
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

  TRY {
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
      THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_init), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_init, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      printf("%s\n", zmq_strerror(errno));
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    message_free(payment_init_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int payment_init_done_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;

  message_t payment_sign_msg;
  message_null(payment_sign_msg);

  bn_t q, s;
  cl_ciphertext_t ctx_alpha_times_beta_times_tau;
  zk_proof_t pi_1;

  bn_null(q);
  bn_null(s);
  cl_ciphertext_null(ctx_alpha_times_beta_times_tau);
  zk_proof_null(pi_1);

  TRY {
    bn_new(q);
    bn_new(s);
    cl_ciphertext_new(ctx_alpha_times_beta_times_tau);
    zk_proof_new(pi_1);

    ec_curve_get_ord(q);

    bn_rand_mod(state->k_1, q);
    ec_mul_gen(state->R_1, state->k_1);

    if (zk_dlog_prove(pi_1, state->R_1, state->k_1) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    // Homomorphically randomize the challenge ciphertext.
    bn_rand_mod(state->tau, q);
    const unsigned tau_str_len = bn_size_str(state->tau, 10);
    char tau_str[tau_str_len];
    bn_write_str(tau_str, tau_str_len, state->tau, 10);

    GEN plain_tau = strtoi(tau_str);
    ctx_alpha_times_beta_times_tau->c1 = nupow(state->ctx_alpha_times_beta->c1, plain_tau, NULL);
    ctx_alpha_times_beta_times_tau->c2 = nupow(state->ctx_alpha_times_beta->c2, plain_tau, NULL);

    // Deserialize the data from the message.
    bn_read_bin(state->com->c, data, RLC_BN_SIZE);
    ec_read_bin(state->com->r, data + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED);

    // Build and define the message.
    char *msg_type = "payment_sign";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + (2 * RLC_CL_CIPHERTEXT_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_sign_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(payment_sign_msg->data, RLC_EC_SIZE_COMPRESSED, state->R_1, 1);
    ec_write_bin(payment_sign_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, pi_1->a, 1);
    bn_write_bin(payment_sign_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, pi_1->z);
    memcpy(payment_sign_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE,
           GENtostr(ctx_alpha_times_beta_times_tau->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(payment_sign_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE + RLC_CL_CIPHERTEXT_SIZE,
           GENtostr(ctx_alpha_times_beta_times_tau->c2), RLC_CL_CIPHERTEXT_SIZE);

    // Serialize the message.
    memcpy(payment_sign_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_sign_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_sign;
    int rc = zmq_msg_init_size(&payment_sign, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_sign), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_sign, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    bn_free(q);
    bn_free(s);
    cl_ciphertext_free(ctx_alpha_times_beta_times_tau);
    zk_proof_free(pi_1);
    if (payment_sign_msg != NULL) message_free(payment_sign_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int payment_sign_done_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  int tx_len = sizeof(tx);
  uint8_t *tx_msg = NULL;
  uint8_t hash[RLC_MD_LEN];
  uint8_t *serialized_message = NULL;

  message_t payment_end_msg;
  message_null(payment_end_msg);

  bn_t q, e, r, x;
  bn_t s_1, s_2, k_1_inverse;
  ec_t R_2, R_c, R, com_x, g_to_the_gamma;
  ec_t R_2_to_the_s_2, pk_to_the_r;
  ec_t A_prime_to_the_tau;
  ec_t g_to_the_e, pk_to_the_r_times_g_to_the_e;

  zk_proof_t pi_2;
  zk_proof_t pi_c;
  zk_proof_t pi_gamma;
  cl_ciphertext_t ctx;

  bn_null(q);
  bn_null(e);
  bn_null(r);
  bn_null(x);
  bn_null(s_1);
  bn_null(s_2);
  bn_null(k_1_inverse);
  ec_null(g_to_the_gamma);
  ec_null(g_to_the_e);
  ec_null(pk_to_the_r);
  ec_null(pk_to_the_r_times_g_to_the_e);
  ec_null(A_prime_to_the_tau);
  ec_null(R_2_to_the_s_2);
  ec_null(R_2);
  ec_null(R_c);
  ec_null(R);
  ec_null(com_x);

  zk_proof_null(pi_2);
  zk_proof_null(pi_c);
  zk_proof_null(pi_gamma);
  cl_ciphertext_null(ctx);

  TRY {
    bn_new(q);
    bn_new(e);
    bn_new(r);
    bn_new(x);
    bn_new(s_1);
    bn_new(s_2);
    bn_new(k_1_inverse);
    ec_new(g_to_the_gamma);
    ec_new(g_to_the_e);
    ec_new(pk_to_the_r);
    ec_new(pk_to_the_r_times_g_to_the_e);
    ec_new(A_prime_to_the_tau);
    ec_new(R_2_to_the_s_2);
    ec_new(R_2);
    ec_new(R_c);
    ec_new(R);
    ec_new(com_x);

    zk_proof_new(pi_2);
    zk_proof_new(pi_c);
    zk_proof_new(pi_gamma);
    cl_ciphertext_new(ctx);

    // Deserialize the data from the message.
    ec_read_bin(R_2, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_2->a, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_2->z, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);
    ec_read_bin(g_to_the_gamma, data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(R_c, data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_c->a, data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_c->z, data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE);
    ec_read_bin(pi_gamma->a, data + (5 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_gamma->b, data + (6 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_gamma->z, data + (7 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_BN_SIZE);

    char ctx_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ctx_str, data + (7 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), RLC_CL_CIPHERTEXT_SIZE);
    ctx->c1 = gp_read_str(ctx_str);
    memzero(ctx_str, RLC_CL_CIPHERTEXT_SIZE);
    memcpy(ctx_str, data + (7 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE) + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx->c2 = gp_read_str(ctx_str);

    // Verify the commitment and ZK proofs.
    ec_add(com_x, R_2, pi_2->a);
    if (decommit(state->com, com_x) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    if (zk_dlog_verify(pi_2, R_2) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }
    if (zk_dlog_verify(pi_c, R_c) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }
    if (zk_dhtuple_verify(pi_gamma, R_2, g_to_the_gamma, R_c) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    // Sanity check.
    ec_mul(A_prime_to_the_tau, state->g_to_the_alpha_times_beta, state->tau);
    ec_norm(A_prime_to_the_tau, A_prime_to_the_tau);
    if (ec_cmp(A_prime_to_the_tau, g_to_the_gamma) != RLC_EQ) {
      THROW(ERR_CAUGHT);
    }

    // Compute the half ECDSA signature.
    ec_mul(R, R_c, state->k_1);
    ec_norm(R, R);

    ec_curve_get_ord(q);
    ec_get_x(x, R);
    bn_mod(r, x, q);
    if (bn_is_zero(r)) {
      THROW(ERR_CAUGHT);
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

    GEN plain_s_2;
    if (cl_dec(&plain_s_2, ctx, state->keys->cl_sk, state->cl_params) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }
    bn_read_str(s_2, GENtostr(plain_s_2), strlen(GENtostr(plain_s_2)), 10);

    // Check correctness of the partial signature received.
    ec_mul(R_2_to_the_s_2, R_2, s_2);
    ec_norm(R_2_to_the_s_2, R_2_to_the_s_2);

    ec_mul(pk_to_the_r, state->keys->ec_pk->pk, r);
    ec_mul_gen(g_to_the_e, e);
    ec_add(pk_to_the_r_times_g_to_the_e, pk_to_the_r, g_to_the_e);
    ec_norm(pk_to_the_r_times_g_to_the_e, pk_to_the_r_times_g_to_the_e);
    if (ec_cmp(R_2_to_the_s_2, pk_to_the_r_times_g_to_the_e) != RLC_EQ) {
      THROW(ERR_CAUGHT);
    }

    bn_gcd_ext(x, k_1_inverse, NULL, state->k_1, q);
    if (bn_sign(k_1_inverse) == RLC_NEG) {
      bn_add(k_1_inverse, k_1_inverse, q);
    }

    // Compute the "almost" signature.
		bn_mul(state->s_hat, s_2, k_1_inverse);
    bn_mod(state->s_hat, state->s_hat, q);

    // Build and define the message.
    char *msg_type = "payment_end";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_end_msg, msg_type_length, msg_data_length);
    
    // Serialize the data for the message.
    bn_write_bin(payment_end_msg->data, RLC_BN_SIZE, state->s_hat);

    // Serialize the message.
    memcpy(payment_end_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_end_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_end;
    int rc = zmq_msg_init_size(&payment_end, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_end), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_end, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    bn_free(q);
    bn_free(e);
    bn_free(r);
    bn_free(x);
    bn_free(s_1);
    bn_free(s_2);
    bn_free(k_1_inverse);
    ec_free(g_to_the_gamma);
    ec_free(g_to_the_e);
    ec_free(pk_to_the_r);
    ec_free(pk_to_the_r_times_g_to_the_e);
    ec_free(A_prime_to_the_tau);
    ec_free(R_2_to_the_s_2);
    ec_free(R_2);
    ec_free(R_c);
    ec_free(R);
    ec_free(com_x);
    zk_proof_free(pi_2);
    zk_proof_free(pi_c);
    zk_proof_free(pi_gamma);
    cl_ciphertext_free(ctx);
    if (payment_end_msg != NULL) message_free(payment_end_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int puzzle_solve_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  bn_t q, x, gamma;
  bn_t gamma_inverse;
  bn_t tau_inverse;
  bn_t s_hat_inverse;

  bn_null(q);
  bn_null(x);
  bn_null(gamma);
  bn_null(gamma_inverse);
  bn_null(tau_inverse);
  bn_null(s_hat_inverse);

  TRY {
    bn_new(q);
    bn_new(x);
    bn_new(gamma);
    bn_new(gamma_inverse);
    bn_new(tau_inverse);
    bn_new(s_hat_inverse);

    // Deserialize the data from the message.
    bn_read_bin(state->s, data, RLC_BN_SIZE);

    // Extract the randomized secret.
    ec_curve_get_ord(q);

    bn_gcd_ext(x, s_hat_inverse, NULL, state->s_hat, q);
    if (bn_sign(s_hat_inverse) == RLC_NEG) {
      bn_add(s_hat_inverse, s_hat_inverse, q);
    }

    bn_mul(gamma_inverse, state->s, s_hat_inverse);
    bn_mod(gamma_inverse, gamma_inverse, q);

    bn_gcd_ext(x, gamma, NULL, gamma_inverse, q);
    if (bn_sign(gamma) == RLC_NEG) {
      bn_add(gamma, gamma, q);
    }

    bn_gcd_ext(x, tau_inverse, NULL, state->tau, q);
    if (bn_sign(tau_inverse) == RLC_NEG) {
      bn_add(tau_inverse, tau_inverse, q);
    }

    bn_mul(state->alpha_hat, gamma, tau_inverse);
    bn_mod(state->alpha_hat, state->alpha_hat, q);

    PUZZLE_SOLVED = 1;
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
    bn_free(q);
    bn_free(x);
    bn_free(gamma);
    bn_free(gamma_inverse);
    bn_free(tau_inverse);
    bn_free(s_hat_inverse);
  }

  return result_status;
}

int puzzle_solution_send(alice_state_t state, void *socket) {
  if (state == NULL) {
    THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;

  message_t puzzle_solution_send_msg;
  message_null(puzzle_solution_send_msg);

  TRY {
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
      THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&puzzle_solution_send), serialized_message, total_msg_length);
    rc = zmq_msg_send(&puzzle_solution_send, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      THROW(ERR_CAUGHT);
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
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

  unsigned long start_time, stop_time, total_time;

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

  TRY {
    alice_state_new(state);

    if (generate_cl_params(state->cl_params) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    if (read_keys_from_file_alice_bob(ALICE_KEY_FILE_PREFIX,
                                      state->keys->ec_sk,
                                      state->keys->ec_pk,
                                      state->keys->cl_sk,
                                      state->keys->cl_pk,
                                      state->tumbler_cl_pk) != RLC_OK) {
        THROW(ERR_CAUGHT);
    }

    while (!PUZZLE_SHARED) {
      if (receive_message(state, socket) != RLC_OK) {
        THROW(ERR_CAUGHT);
      }
    }

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      THROW(ERR_CAUGHT);
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
      THROW(ERR_CAUGHT);
    }

    start_time = ttimer();
    if (payment_init(socket) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }

    while (!PUZZLE_SOLVED) {
      if (receive_message(state, socket) != RLC_OK) {
        THROW(ERR_CAUGHT);
      }
    }

    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("\nPayment procedure time: %.5f sec\n", total_time / CLOCK_PRECISION);

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      THROW(ERR_CAUGHT);
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
      THROW(ERR_CAUGHT);
    }

    if (puzzle_solution_send(state, socket) != RLC_OK) {
      THROW(ERR_CAUGHT);
    }
  } CATCH_ANY {
    result_status = RLC_ERR;
  } FINALLY {
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