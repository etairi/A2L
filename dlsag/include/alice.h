#ifndef TRILERO_DLSAG_INCLUDE_ALICE
#define TRILERO_DLSAG_INCLUDE_ALICE

#include <stddef.h>
#include <string.h>
#include "relic/relic.h"
#include "zmq.h"
#include "types.h"

#define TUMBLER_ENDPOINT  "tcp://localhost:8181"
#define ALICE_ENDPOINT    "tcp://*:8182"
#define BOB_ENDPOINT      "tcp://localhost:8183"

static uint8_t tx[2] = { 116, 120 }; // "tx"

typedef enum {
  SETUP_DONE,
  PROMISE_SENT,
  PUZZLE_SHARE,
  PUZZLE_SOLVE,
  PAYMENT_INIT_DONE,
  PAYMENT_SIGN_DONE,
  PAYMENT_COMPLETE
} msgcode_t;

typedef struct {
  char *key;
  msgcode_t code;
} symstruct_t;

static symstruct_t msg_lookuptable[] = {
  { "setup_done", SETUP_DONE },
  { "promise_sent", PROMISE_SENT },
  { "puzzle_share", PUZZLE_SHARE },
  { "payment_init_done", PAYMENT_INIT_DONE },
  { "payment_sign_done", PAYMENT_SIGN_DONE },
  { "payment_complete", PAYMENT_COMPLETE },
  { "puzzle_solve", PUZZLE_SOLVE }
};

#define TOTAL_MESSAGES (sizeof(msg_lookuptable) / sizeof(symstruct_t))

typedef struct {
  ring_t ring;
  keys_t keys;
  cl_public_key_t tumbler_cl_pk;
  ps_public_key_t tumbler_ps_pk;
  bn_t *vec_s;
  bn_t h0;
  bn_t s0;
  bn_t s0_A;
  commit_t com;
  ec_t A_prime;
  cl_ciphertext_t ctx_alpha_times_beta;
  ec_t J;
  ec_t J_A;
  ec_t J_A_tilde;
  ec_t R_A;
  bn_t tau;
  bn_t alpha_hat;
  bn_t tid;
  ps_signature_t sigma;
  pedersen_com_t pcom;
  pedersen_decom_t pdecom;
} alice_state_st;

typedef alice_state_st *alice_state_t;

#define alice_state_null(state) state = NULL;

#define alice_state_new(state)                              \
  do {                                                      \
    state = malloc(sizeof(alice_state_st));                 \
    if (state == NULL) {                                    \
      RLC_THROW(ERR_NO_MEMORY);                             \
    }                                                       \
    ring_new((state)->ring, RING_SIZE);                     \
    keys_new((state)->keys);                                \
    cl_public_key_new((state)->tumbler_cl_pk);              \
    ps_public_key_new((state)->tumbler_ps_pk);              \
    (state)->vec_s = malloc(sizeof(bn_t) * RING_SIZE);      \
    if ((state)->vec_s == NULL) {                           \
      RLC_THROW(ERR_NO_MEMORY);                             \
    }                                                       \
    for (size_t i = 0; i < RING_SIZE; i++) {                \
      bn_new((state)->vec_s[i]);                            \
    }                                                       \
    bn_new((state)->h0);                                    \
    bn_new((state)->s0);                                    \
    bn_new((state)->s0_A);                                  \
    commit_new((state)->com);                               \
    ec_new((state)->A_prime);                               \
    cl_ciphertext_new((state)->ctx_alpha_times_beta);       \
    ec_new((state)->J);                                     \
    ec_new((state)->J_A);                                   \
    ec_new((state)->J_A_tilde);                             \
    ec_new((state)->R_A);                                   \
    bn_new((state)->tau);                                   \
    bn_new((state)->alpha_hat);                             \
    bn_new((state)->tid);                                   \
    ps_signature_new((state)->sigma);                       \
    pedersen_com_new((state)->pcom);                        \
    pedersen_decom_new((state)->pdecom);                    \
  } while (0)

#define alice_state_free(state)                             \
  do {                                                      \
    ring_free((state)->ring, RING_SIZE);                    \
    keys_free((state)->keys);                               \
    cl_public_key_free((state)->tumbler_cl_pk);             \
    ps_public_key_free((state)->tumbler_ps_pk);             \
    for (size_t i = 0; i < RING_SIZE; i++) {                \
      bn_free((state)->vec_s[i]);                           \
    }                                                       \
    bn_free((state)->h0);                                   \
    bn_free((state)->s0);                                   \
    bn_free((state)->s0_A);                                 \
    commit_free((state)->com);                              \
    ec_free((state)->A_prime);                              \
    cl_ciphertext_free((state)->ctx_alpha_times_beta);      \
    ec_free((state)->J);                                    \
    ec_free((state)->J_A);                                  \
    ec_free((state)->J_A_tilde);                            \
    ec_free((state)->R_A);                                  \
    bn_free((state)->tau);                                  \
    bn_free((state)->alpha_hat);                            \
    ps_signature_free((state)->sigma);                      \
    pedersen_com_new((state)->pcom);                        \
    pedersen_decom_new((state)->pdecom);                    \
    free(state);                                            \
    state = NULL;                                           \
  } while (0)

typedef int (*msg_handler_t)(alice_state_t, void*, uint8_t*);

int get_message_type(char *key);
msg_handler_t get_message_handler(char *key);
int handle_message(alice_state_t state, void *socket, zmq_msg_t message);
int receive_message(alice_state_t state, void *socket);

int setup(alice_state_t state, void *socket);
int setup_done_handler(alice_state_t state, void *socket, uint8_t *data);
int token_share(alice_state_t state, void *socket);
int puzzle_share_handler(alice_state_t state, void *socket, uint8_t *data);
int payment_init(void *socket);
int payment_init_done_handler(alice_state_t state, void *socket, uint8_t *data);
int payment_sign_done_handler(alice_state_t state, void *socket, uint8_t *data);
int puzzle_solve_handler(alice_state_t state, void *socket, uint8_t *data);
int puzzle_solution_share(alice_state_t state, void *socket);

#endif // TRILERO_DLSAG_INCLUDE_ALICE