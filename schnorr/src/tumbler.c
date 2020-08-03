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
    case REGISTRATION:
      return registration_handler;
    
    case PROMISE_INIT:
      return promise_init_handler;

    case PAYMENT_INIT:
      return payment_init_handler;

    default:
      fprintf(stderr, "Error: invalid message type.\n");
      exit(1);
  }
}

int handle_message(tumbler_state_t state, void *socket, zmq_msg_t message) {
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

int receive_message(tumbler_state_t state, void *socket) {
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

int registration_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  message_t registration_done_msg;
  uint8_t *serialized_message = NULL;

  pedersen_com_t com;
  pedersen_com_null(com);

  pedersen_com_zk_proof_t com_zk_proof;
  pedersen_com_zk_proof_null(com_zk_proof);

  ps_signature_t sigma_prime;
  ps_signature_null(sigma_prime);
  
  RLC_TRY {
    pedersen_com_new(com);
    pedersen_com_zk_proof_new(com_zk_proof);
    ps_signature_new(sigma_prime);

    // Deserialize the data from the message.
    g1_read_bin(com->c, data, RLC_G1_SIZE_COMPRESSED);
    g1_read_bin(com_zk_proof->c->c, data + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED);
    bn_read_bin(com_zk_proof->u, data + (2 * RLC_G1_SIZE_COMPRESSED), RLC_BN_SIZE);
    bn_read_bin(com_zk_proof->v, data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE);
    
    if (zk_pedersen_com_verify(com_zk_proof, state->tumbler_ps_pk->Y_1, com) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (ps_blind_sign(sigma_prime, com, state->tumbler_ps_sk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "registration_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = 2 * RLC_G1_SIZE_COMPRESSED;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(registration_done_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    g1_write_bin(registration_done_msg->data, RLC_G1_SIZE_COMPRESSED, sigma_prime->sigma_1, 1);
    g1_write_bin(registration_done_msg->data + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED, sigma_prime->sigma_2, 1);

    memcpy(registration_done_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, registration_done_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t registration_done;
    int rc = zmq_msg_init_size(&registration_done, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&registration_done), serialized_message, total_msg_length);
    rc = zmq_msg_send(&registration_done, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    pedersen_com_free(com);
    pedersen_com_zk_proof_free(com_zk_proof);
    ps_signature_free(sigma_prime);
    if (registration_done_msg != NULL) message_free(registration_done_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int promise_init_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  message_t promise_done_msg;
  uint8_t *serialized_message = NULL;

  bn_t q, tid;
  zk_proof_cldl_t pi_cldl;
  ps_signature_t sigma_tid;

  bn_null(q);
  bn_null(tid);
  zk_proof_cldl_null(pi_cldl);
  ps_signature_null(sigma_tid);
  
  RLC_TRY {
    bn_new(q);
    bn_new(tid);
    zk_proof_cldl_new(pi_cldl);
    ps_signature_new(sigma_tid);

    // Deserialize the data from the message.
    bn_read_bin(tid, data, RLC_BN_SIZE);
    g1_read_bin(sigma_tid->sigma_1, data + RLC_BN_SIZE, RLC_G1_SIZE_COMPRESSED);
    g1_read_bin(sigma_tid->sigma_2, data + RLC_BN_SIZE + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED);
    bn_read_bin(state->sigma_r->e, data + RLC_BN_SIZE + (2 * RLC_G1_SIZE_COMPRESSED), RLC_BN_SIZE);
    bn_read_bin(state->sigma_r->s, data + (2 * RLC_BN_SIZE) + (2 * RLC_G1_SIZE_COMPRESSED), RLC_BN_SIZE);

    if (ps_verify(sigma_tid, tid, state->tumbler_ps_pk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (cp_ecss_ver(state->sigma_r->e, state->sigma_r->s, tx, sizeof(tx), state->bob_ec_pk->pk) != 1) {
      RLC_THROW(ERR_CAUGHT);
    }

    ec_curve_get_ord(q);
    bn_rand_mod(state->alpha, q);
    ec_mul_gen(state->g_to_the_alpha, state->alpha);

    const unsigned alpha_str_len = bn_size_str(state->alpha, 10);
    char alpha_str[alpha_str_len];
    bn_write_str(alpha_str, alpha_str_len, state->alpha, 10);

    GEN plain_alpha = strtoi(alpha_str);
    if (cl_enc(state->ctx_alpha, plain_alpha, state->tumbler_cl_pk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (zk_cldl_prove(pi_cldl, plain_alpha, state->ctx_alpha, state->tumbler_cl_pk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (adaptor_schnorr_sign(state->sigma_tr, tx, sizeof(tx), state->g_to_the_alpha, state->tumbler_ec_sk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "promise_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE) 
    + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T2_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_done_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(promise_done_msg->data, RLC_EC_SIZE_COMPRESSED, state->g_to_the_alpha, 1);
    bn_write_bin(promise_done_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_BN_SIZE, state->sigma_tr->e);
    bn_write_bin(promise_done_msg->data + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE, RLC_BN_SIZE, state->sigma_tr->s);
    memcpy(promise_done_msg->data + RLC_EC_SIZE_COMPRESSED + (2 * RLC_BN_SIZE),
           GENtostr(state->ctx_alpha->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_done_msg->data + RLC_EC_SIZE_COMPRESSED + (2 * RLC_BN_SIZE) + RLC_CL_CIPHERTEXT_SIZE,
           GENtostr(state->ctx_alpha->c2), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_done_msg->data + RLC_EC_SIZE_COMPRESSED + (2 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE),
           GENtostr(pi_cldl->t1), RLC_CLDL_PROOF_T1_SIZE);
    ec_write_bin(promise_done_msg->data + RLC_EC_SIZE_COMPRESSED + (2 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE) 
              + RLC_CLDL_PROOF_T1_SIZE, RLC_EC_SIZE_COMPRESSED, pi_cldl->t2, 1);
    memcpy(promise_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE, GENtostr(pi_cldl->t3), RLC_CLDL_PROOF_T3_SIZE);
    memcpy(promise_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE, GENtostr(pi_cldl->u1), RLC_CLDL_PROOF_U1_SIZE);
    memcpy(promise_done_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE, GENtostr(pi_cldl->u2), RLC_CLDL_PROOF_U2_SIZE);

    memcpy(promise_done_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_done_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_done;
    int rc = zmq_msg_init_size(&promise_done, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_done), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_done, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    bn_free(tid);
    zk_proof_cldl_free(pi_cldl);
    ps_signature_free(sigma_tid);
    if (promise_done_msg != NULL) message_free(promise_done_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int payment_init_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  message_t payment_done_msg;

  bn_t q;
  cl_ciphertext_t ctx_alpha_times_beta_times_tau;

  bn_null(q);
  cl_ciphertext_null(ctx_alpha_times_beta_times_tau);
  message_null(payment_done_msg);

  RLC_TRY {
    bn_new(q);
    cl_ciphertext_new(ctx_alpha_times_beta_times_tau);

    // Deserialize the data from the message.
    bn_read_bin(state->sigma_s->e, data, RLC_BN_SIZE);
    bn_read_bin(state->sigma_s->s, data + RLC_BN_SIZE, RLC_BN_SIZE);

    char ct_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ct_str, data + (2 * RLC_BN_SIZE), RLC_CL_CIPHERTEXT_SIZE);
    ctx_alpha_times_beta_times_tau->c1 = gp_read_str(ct_str);
    memcpy(ct_str, data + (2 * RLC_BN_SIZE) + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx_alpha_times_beta_times_tau->c2 = gp_read_str(ct_str);

    // Decrypt the ciphertext.
    GEN gamma;
    if (cl_dec(&gamma, ctx_alpha_times_beta_times_tau, state->tumbler_cl_sk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    bn_read_str(state->gamma, GENtostr(gamma), strlen(GENtostr(gamma)), 10);

    ec_curve_get_ord(q);
    bn_add(state->sigma_s->s, state->sigma_s->s, state->gamma);
    bn_mod(state->sigma_s->s, state->sigma_s->s, q);

    if (cp_ecss_ver(state->sigma_s->e, state->sigma_s->s, tx, sizeof(tx), state->alice_ec_pk->pk) != 1) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (cp_ecss_sig(state->sigma_ts->e, state->sigma_ts->s, tx, sizeof(tx), state->tumbler_ec_sk->sk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "payment_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = 2 * RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_done_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    bn_write_bin(payment_done_msg->data, RLC_BN_SIZE, state->sigma_s->e);
    bn_write_bin(payment_done_msg->data + RLC_BN_SIZE, RLC_BN_SIZE, state->sigma_s->s);

    memcpy(payment_done_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_done_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_done;
    int rc = zmq_msg_init_size(&payment_done, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_done), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_done, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    cl_ciphertext_free(ctx_alpha_times_beta_times_tau);
    if (payment_done_msg != NULL) message_free(payment_done_msg);
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

  RLC_TRY {
    tumbler_state_new(state);

    if (generate_cl_params(state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    
    if (read_keys_from_file_tumbler(state->tumbler_ec_sk,
                                    state->tumbler_ec_pk,
                                    state->tumbler_ps_sk,
                                    state->tumbler_ps_pk,
                                    state->tumbler_cl_sk,
                                    state->tumbler_cl_pk,
                                    state->alice_ec_pk,
                                    state->bob_ec_pk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    while (1) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
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