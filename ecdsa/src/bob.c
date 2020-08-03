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
    
    case PROMISE_DONE:
      return promise_done_handler;

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
    g1_read_bin(state->sigma_tid->sigma_1, data + RLC_BN_SIZE, RLC_G1_SIZE_COMPRESSED);
    g1_read_bin(state->sigma_tid->sigma_2, data + RLC_BN_SIZE + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED);

    TOKEN_RECEIVED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  }

  return result_status;
}

int promise_init(bob_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;
  
  message_t promise_init_msg;
  message_null(promise_init_msg);

  RLC_TRY {
    if (cp_ecdsa_sig(state->sigma_r->r, state->sigma_r->s, tx, sizeof(tx), 0, state->bob_ec_sk->sk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "promise_init";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (2 * RLC_G1_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_init_msg, msg_type_length, msg_data_length);
    
    // Serialize the message.
    bn_write_bin(promise_init_msg->data, RLC_BN_SIZE, state->tid);
    g1_write_bin(promise_init_msg->data + RLC_BN_SIZE, RLC_G1_SIZE_COMPRESSED, state->sigma_tid->sigma_1, 1);
    g1_write_bin(promise_init_msg->data + RLC_BN_SIZE + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED, state->sigma_tid->sigma_2, 1);
    bn_write_bin(promise_init_msg->data + RLC_BN_SIZE + (2 * RLC_G1_SIZE_COMPRESSED), RLC_BN_SIZE, state->sigma_r->r);
    bn_write_bin(promise_init_msg->data + (2 * RLC_BN_SIZE) + (2 * RLC_G1_SIZE_COMPRESSED), RLC_BN_SIZE, state->sigma_r->s);

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

int promise_done_handler(bob_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  zk_proof_cldl_t pi_cldl;
  zk_proof_cldl_null(pi_cldl);

  RLC_TRY {
    zk_proof_cldl_new(pi_cldl);

    // Deserialize the data from the message.
    ec_read_bin(state->g_to_the_alpha, data, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(state->sigma_t->r, data + RLC_EC_SIZE_COMPRESSED, RLC_BN_SIZE);
    bn_read_bin(state->sigma_t->s, data + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE, RLC_BN_SIZE);
    ec_read_bin(state->sigma_t->R, data + RLC_EC_SIZE_COMPRESSED + (2 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(state->sigma_t->pi->a, data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(state->sigma_t->pi->b, data + (3 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(state->sigma_t->pi->z, data + (4 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_BN_SIZE);

    char ctx_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ctx_str, data + (4 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE), RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha->c1 = gp_read_str(ctx_str);
    memzero(ctx_str, RLC_CL_CIPHERTEXT_SIZE);
    memcpy(ctx_str, data + (4 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE) + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha->c2 = gp_read_str(ctx_str);

    char pi_cldl_str[RLC_CLDL_PROOF_T1_SIZE];
    memcpy(pi_cldl_str, data + (4 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE),
           RLC_CLDL_PROOF_T1_SIZE);
    pi_cldl->t1 = gp_read_str(pi_cldl_str);
    ec_read_bin(pi_cldl->t2, data + (4 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE) 
              + RLC_CLDL_PROOF_T1_SIZE, RLC_EC_SIZE_COMPRESSED);
    memcpy(pi_cldl_str, data + (5 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE) 
         + RLC_CLDL_PROOF_T1_SIZE, RLC_CLDL_PROOF_T3_SIZE);
    pi_cldl->t3 = gp_read_str(pi_cldl_str);
    memcpy(pi_cldl_str, data + (5 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE) 
         + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE, RLC_CLDL_PROOF_U1_SIZE);
    pi_cldl->u1 = gp_read_str(pi_cldl_str);
    memcpy(pi_cldl_str, data + (5 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE) 
         + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE, RLC_CLDL_PROOF_U2_SIZE);
    pi_cldl->u2 = gp_read_str(pi_cldl_str);

    // Verify ZK proofs.
    if (zk_cldl_verify(pi_cldl, state->g_to_the_alpha, state->ctx_alpha, state->tumbler_cl_pk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (adaptor_ecdsa_preverify(state->sigma_t, tx, sizeof(tx), state->g_to_the_alpha, state->tumbler_ec_pk) != 1) {
      RLC_THROW(ERR_CAUGHT);
    }

    PROMISE_COMPLETED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    zk_proof_cldl_free(pi_cldl);
  }

  return result_status;
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
  ec_t g_to_the_alpha_times_beta;

  cl_ciphertext_null(ctx_alpha_times_beta);
  bn_null(q);
  ec_null(g_to_the_alpha_times_beta);

  RLC_TRY {
    cl_ciphertext_new(ctx_alpha_times_beta);
    bn_new(q);
    ec_new(g_to_the_alpha_times_beta);

    ec_curve_get_ord(q);

    // Randomize the promise challenge.
    GEN beta_prime = randomi(state->cl_params->bound);
    bn_read_str(state->beta, GENtostr(beta_prime), strlen(GENtostr(beta_prime)), 10);
    bn_mod(state->beta, state->beta, q);

    ec_mul(g_to_the_alpha_times_beta, state->g_to_the_alpha, state->beta);
    ec_norm(g_to_the_alpha_times_beta, g_to_the_alpha_times_beta);

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
    ec_write_bin(puzzle_share_msg->data, RLC_EC_SIZE_COMPRESSED, g_to_the_alpha_times_beta, 1);
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
    ec_free(g_to_the_alpha_times_beta);
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

  bn_t x, q, alpha, alpha_hat, alpha_inverse, beta_inverse;

  bn_null(x);
  bn_null(q);
  bn_null(alpha);
  bn_null(alpha_hat);
  bn_null(alpha_inverse);
  bn_null(beta_inverse);

  RLC_TRY {
    bn_new(x);
    bn_new(q);
    bn_new(alpha);
    bn_new(alpha_hat);
    bn_new(alpha_inverse);
    bn_new(beta_inverse);
    
    // Deserialize the data from the message.
    bn_read_bin(alpha_hat, data, RLC_BN_SIZE);

    ec_curve_get_ord(q);

    // Extract the secret alpha.
    bn_gcd_ext(x, beta_inverse, NULL, state->beta, q);
    if (bn_sign(beta_inverse) == RLC_NEG) {
      bn_add(beta_inverse, beta_inverse, q);
    }

    bn_mul(alpha, alpha_hat, beta_inverse);
    bn_mod(alpha, alpha, q);

    // Complete the "almost" signature.
    bn_gcd_ext(x, alpha_inverse, NULL, alpha, q);
    if (bn_sign(alpha_inverse) == RLC_NEG) {
      bn_add(alpha_inverse, alpha_inverse, q);
    }

    bn_mul(state->sigma_t->s, state->sigma_t->s, alpha_inverse);
    bn_mod(state->sigma_t->s, state->sigma_t->s, q);

    // Verify the completed signature.
    if (cp_ecdsa_ver(state->sigma_t->r, state->sigma_t->s, tx, sizeof(tx), 0, state->tumbler_ec_pk->pk) != 1) {
      RLC_THROW(ERR_CAUGHT);
    }
    PUZZLE_SOLVED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(x);
    bn_free(q);
    bn_free(alpha)
    bn_free(alpha_hat);
    bn_free(alpha_inverse);
    bn_free(beta_inverse);
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
                                      state->bob_ec_sk,
                                      state->bob_ec_pk,
                                      state->tumbler_ec_pk,
                                      state->tumbler_ps_pk,
                                      state->tumbler_cl_pk) != RLC_OK) {
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
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("\nPuzzle promise and share time: %.5f sec\n", total_time / CLOCK_PRECISION);

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