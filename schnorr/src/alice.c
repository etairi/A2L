#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "relic/relic.h"
#include "pari/pari.h"
#include "zmq.h"
#include "alice.h"
#include "types.h"
#include "util.h"

unsigned REGISTRATION_COMPLETED;
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
    case REGISTRATION_DONE:
      return registration_done_handler;
    
    case PUZZLE_SHARE:
      return puzzle_share_handler;

    case PAYMENT_DONE:
      return payment_done_handler;

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

int registration(alice_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }
  
  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;
  
  message_t registration_msg;
  message_null(registration_msg);

  bn_t q;
  bn_null(q);

  pedersen_com_zk_proof_t com_zk_proof;
  pedersen_com_zk_proof_null(com_zk_proof);

  RLC_TRY {
    bn_new(q);
    pedersen_com_zk_proof_new(com_zk_proof);

    ec_curve_get_ord(q);
    bn_rand_mod(state->tid, q);

    if (pedersen_commit(state->pcom, state->pdecom, state->tumbler_ps_pk->Y_1, state->tid) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (zk_pedersen_com_prove(com_zk_proof, state->tumbler_ps_pk->Y_1, state->pcom, state->pdecom) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "registration";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (2 * RLC_G1_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(registration_msg, msg_type_length, msg_data_length);
    
    // Serialize the message.
    g1_write_bin(registration_msg->data, RLC_G1_SIZE_COMPRESSED, state->pcom->c, 1);
    g1_write_bin(registration_msg->data + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED, com_zk_proof->c->c, 1);
    bn_write_bin(registration_msg->data + (2 * RLC_G1_SIZE_COMPRESSED), RLC_BN_SIZE, com_zk_proof->u);
    bn_write_bin(registration_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE, com_zk_proof->v);

    memcpy(registration_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, registration_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t registration;
    int rc = zmq_msg_init_size(&registration, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&registration), serialized_message, total_msg_length);
    rc = zmq_msg_send(&registration, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    pedersen_com_zk_proof_free(com_zk_proof);
    if (registration_msg != NULL) message_free(registration_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int registration_done_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  bn_t q, t;
  bn_null(q);
  bn_null(t);

  RLC_TRY {
    bn_new(q);
    bn_new(t);

    // Deserialize the data from the message.
    g1_read_bin(state->sigma_tid->sigma_1, data, RLC_G1_SIZE_COMPRESSED);
    g1_read_bin(state->sigma_tid->sigma_2, data + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED);

    if (ps_unblind(state->sigma_tid, state->pdecom) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (ps_verify(state->sigma_tid, state->tid, state->tumbler_ps_pk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    
    g1_get_ord(q);
    bn_rand_mod(t, q);

    g1_mul(state->sigma_tid->sigma_1, state->sigma_tid->sigma_1, t);
    g1_mul(state->sigma_tid->sigma_2, state->sigma_tid->sigma_2, t);
    REGISTRATION_COMPLETED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_new(q);
    bn_new(t);
  }

  return result_status;
}

int token_share(alice_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;

  message_t token_share_msg;
  message_null(token_share_msg);

  RLC_TRY {
    // Build and define the message.
    char *msg_type = "token_share";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE + (2 * RLC_G1_SIZE_COMPRESSED);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(token_share_msg, msg_type_length, msg_data_length);
    
    // Serialize the data for the message.
    bn_write_bin(token_share_msg->data, RLC_BN_SIZE, state->tid);
    g1_write_bin(token_share_msg->data + RLC_BN_SIZE, RLC_G1_SIZE_COMPRESSED, state->sigma_tid->sigma_1, 1);
    g1_write_bin(token_share_msg->data + RLC_BN_SIZE + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED, state->sigma_tid->sigma_2, 1);

    // Serialize the message.
    memcpy(token_share_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, token_share_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t token_share;
    int rc = zmq_msg_init_size(&token_share, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&token_share), serialized_message, total_msg_length);
    rc = zmq_msg_send(&token_share, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (token_share_msg != NULL) message_free(token_share_msg);
    if (serialized_message != NULL) free(serialized_message);
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

int payment_init(alice_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;

  message_t payment_init_msg;
  message_null(payment_init_msg);

  cl_ciphertext_t ctx_alpha_times_beta_times_tau;
  bn_t q;

  cl_ciphertext_null(ctx_alpha_times_beta_times_tau);
  bn_null(q);

  RLC_TRY {
    cl_ciphertext_new(ctx_alpha_times_beta_times_tau);
    bn_new(q);
    ec_curve_get_ord(q);

    // Homomorphically randomize the challenge ciphertext.
    uint64_t start_time, stop_time, total_time;

    start_time = ttimer();
    GEN tau_prime = randomi(state->cl_params->bound);
    bn_read_str(state->tau, GENtostr(tau_prime), strlen(GENtostr(tau_prime)), 10);
    bn_mod(state->tau, state->tau, q);
    ec_mul(state->g_to_the_alpha_times_beta_times_tau, state->g_to_the_alpha_times_beta, state->tau);

    const unsigned tau_str_len = bn_size_str(state->tau, 10);
    char tau_str[tau_str_len];
    bn_write_str(tau_str, tau_str_len, state->tau, 10);

    GEN plain_tau = strtoi(tau_str);
    ctx_alpha_times_beta_times_tau->c1 = nupow(state->ctx_alpha_times_beta->c1, plain_tau, NULL);
    ctx_alpha_times_beta_times_tau->c2 = nupow(state->ctx_alpha_times_beta->c2, plain_tau, NULL);

    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("Re-randomization time: %.5f sec\n", total_time / CLOCK_PRECISION);

    if (adaptor_schnorr_sign(state->sigma_hat_s,
                             tx,
                             sizeof(tx),
                             state->g_to_the_alpha_times_beta_times_tau,
                             state->alice_ec_sk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "payment_init";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (2 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_init_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    bn_write_bin(payment_init_msg->data, RLC_BN_SIZE, state->sigma_hat_s->e);
    bn_write_bin(payment_init_msg->data + RLC_BN_SIZE, RLC_BN_SIZE, state->sigma_hat_s->s);
    memcpy(payment_init_msg->data + (2 * RLC_BN_SIZE),
           GENtostr(ctx_alpha_times_beta_times_tau->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(payment_init_msg->data + (2 * RLC_BN_SIZE) + RLC_CL_CIPHERTEXT_SIZE,
           GENtostr(ctx_alpha_times_beta_times_tau->c2), RLC_CL_CIPHERTEXT_SIZE);

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
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    cl_ciphertext_free(ctx_alpha_times_beta_times_tau);
    bn_free(q);
    if (payment_init_msg != NULL) message_free(payment_init_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int payment_done_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  bn_t q, x, tau_inverse, gamma;
  ec_t g_to_the_gamma;

  bn_null(q);
  bn_null(x);
  bn_null(tau_inverse);
  bn_null(gamma);
  ec_null(g_to_the_gamma);

  RLC_TRY {
    bn_new(q);
    bn_new(x);
    bn_new(tau_inverse);
    bn_new(gamma);
    ec_new(g_to_the_gamma);

    ec_curve_get_ord(q);

    // Deserialize the data from the message.
    bn_read_bin(state->sigma_s->e, data, RLC_BN_SIZE);
    bn_read_bin(state->sigma_s->s, data + RLC_BN_SIZE, RLC_BN_SIZE);

    // Extract the secret value.
		bn_sub(gamma, state->sigma_s->s, state->sigma_hat_s->s);
		bn_mod(gamma, gamma, q);

    // Verify the extracted secret.
    ec_mul_gen(g_to_the_gamma, gamma);
    if (ec_cmp(state->g_to_the_alpha_times_beta_times_tau, g_to_the_gamma) != RLC_EQ) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Derandomize the extracted secret.
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
    bn_free(q);
    bn_free(x);
    bn_free(tau_inverse);
    ec_free(g_to_the_gamma);
  }

  return result_status;
}

int puzzle_solution_share(alice_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;

  message_t puzzle_solution_share_msg;
  message_null(puzzle_solution_share_msg);

  RLC_TRY {
    // Build and define the message.
    char *msg_type = "puzzle_solution_share";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(puzzle_solution_share_msg, msg_type_length, msg_data_length);
    
    // Serialize the data for the message.
    bn_write_bin(puzzle_solution_share_msg->data, RLC_BN_SIZE, state->alpha_hat);

    // Serialize the message.
    memcpy(puzzle_solution_share_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, puzzle_solution_share_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t puzzle_solution_share;
    int rc = zmq_msg_init_size(&puzzle_solution_share, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&puzzle_solution_share), serialized_message, total_msg_length);
    rc = zmq_msg_send(&puzzle_solution_share, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (puzzle_solution_share_msg != NULL) message_free(puzzle_solution_share_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int main(void)
{
  init();
  int result_status = RLC_OK;
  REGISTRATION_COMPLETED = 0;
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

  printf("Connecting to Tumbler...\n\n");
  void *socket = zmq_socket(context, ZMQ_REQ);
  if (!socket) {
    fprintf(stderr, "Error: could not create a socket.\n");
    exit(1);
  }

  int rc = zmq_connect(socket, TUMBLER_ENDPOINT);
  if (rc != 0) {
    fprintf(stderr, "Error: could not bind the socket.\n");
    exit(1);
  }

  RLC_TRY {
    alice_state_new(state);

    if (generate_cl_params(state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (read_keys_from_file_alice_bob(ALICE_KEY_FILE_PREFIX,
                                      state->alice_ec_sk,
                                      state->alice_ec_pk,
                                      state->tumbler_ec_pk,
                                      state->tumbler_ps_pk,
                                      state->tumbler_cl_pk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    start_time = ttimer();
    if (registration(state, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    while (!REGISTRATION_COMPLETED) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("\nRegistration time: %.5f sec\n", total_time / CLOCK_PRECISION);

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      exit(1);
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
      exit(1);
    }

    if (token_share(state, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("Registration time plus token share: %.5f sec\n", total_time / CLOCK_PRECISION);

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

    rc = zmq_bind(socket, ALICE_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not bind the socket.\n");
      exit(1);
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

    printf("Connecting to Tumbler...\n\n");
    socket = zmq_socket(context, ZMQ_REQ);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    rc = zmq_connect(socket, TUMBLER_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not connect to Tumbler.\n");
      exit(1);
    }

    start_time = ttimer();
    if (payment_init(state, socket) != RLC_OK) {
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
      exit(1);
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
      exit(1);
    }

    if (puzzle_solution_share(state, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("Puzzle solver and solution share time: %.5f sec\n", total_time / CLOCK_PRECISION);
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