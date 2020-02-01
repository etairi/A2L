#ifndef TRILERO_DLSAG_INCLUDE_BOB
#define TRILERO_DLSAG_INCLUDE_BOB

#include <stddef.h>
#include <string.h>
#include "relic/relic.h"
#include "zmq.h"
#include "types.h"

#define TUMBLER_ENDPOINT  "tcp://localhost:8181"
#define ALICE_ENDPOINT    "tcp://localhost:8182"
#define BOB_ENDPOINT      "tcp://*:8183"

static uint8_t tx[2] = { 116, 120 }; // "tx"

typedef enum {
  PROMISE_INIT_DONE,
  PROMISE_SIGN_DONE,
  PROMISE_END_DONE,
  PUZZLE_SHARE_DONE,
  PUZZLE_SOLUTION_SHARE
} msgcode_t;

typedef struct {
  char *key;
  msgcode_t code;
} symstruct_t;

static symstruct_t msg_lookuptable[] = {
  { "promise_init_done", PROMISE_INIT_DONE },
  { "promise_sign_done", PROMISE_SIGN_DONE },
  { "promise_end_done", PROMISE_END_DONE },
  { "puzzle_share_done", PUZZLE_SHARE_DONE },
  { "puzzle_solution_share", PUZZLE_SOLUTION_SHARE }
};

#define TOTAL_MESSAGES (sizeof(msg_lookuptable) / sizeof(symstruct_t))

typedef struct {
  ring_t ring;
  keys_t keys;
  cl_params_t cl_params;
  cl_public_key_t tumbler_cl_pk;
  bn_t *vec_s;
  bn_t h0;
  bn_t s0;
  bn_t s0_B;
  commit_t com;
  cl_ciphertext_t ctx_alpha;
  ec_t A;
  ec_t A_star;
  ec_t J;
  ec_t J_B;
  ec_t J_B_tilde;
  ec_t R_B;
  bn_t beta;
} bob_state_st;

typedef bob_state_st *bob_state_t;

#define bob_state_null(state) state = NULL;

#define bob_state_new(state)                                \
  do {                                                      \
    state = malloc(sizeof(bob_state_st));                   \
    if (state == NULL) {                                    \
      THROW(ERR_NO_MEMORY);                                 \
    }                                                       \
    ring_new((state)->ring, RING_SIZE);                     \
    keys_new((state)->keys);                                \
    cl_params_new((state)->cl_params);                      \
    cl_public_key_new((state)->tumbler_cl_pk);              \
    (state)->vec_s = malloc(sizeof(bn_t) * RING_SIZE);      \
    if ((state)->vec_s == NULL) {                           \
      THROW(ERR_NO_MEMORY);                                 \
    }                                                       \
    for (size_t i = 0; i < RING_SIZE; i++) {                \
      bn_new((state)->vec_s[i]);                            \
    }                                                       \
    bn_new((state)->h0);                                    \
    bn_new((state)->s0);                                    \
    bn_new((state)->s0_B);                                  \
    commit_new((state)->com);                               \
    cl_ciphertext_new((state)->ctx_alpha);                  \
    ec_new((state)->A);                                     \
    ec_new((state)->A_star);                                \
    ec_new((state)->J);                                     \
    ec_new((state)->J_B);                                   \
    ec_new((state)->J_B_tilde);                             \
    ec_new((state)->R_B);                                   \
    bn_new((state)->beta);                                  \
  } while (0)

#define bob_state_free(state)                               \
  do {                                                      \
    ring_free((state)->ring, RING_SIZE);                    \
    keys_free((state)->keys);                               \
    cl_params_free((state)->cl_params);                     \
    cl_public_key_free((state)->tumbler_cl_pk);             \
    for (size_t i = 0; i < RING_SIZE; i++) {                \
      bn_free((state)->vec_s[i]);                           \
    }                                                       \
    free((state)->vec_s);                                   \
    bn_free((state)->h0);                                   \
    bn_free((state)->s0);                                   \
    bn_free((state)->s0_B);                                 \
    commit_free((state)->com);                              \
    cl_ciphertext_free((state)->ctx_alpha);                 \
    ec_free((state)->A);                                    \
    ec_free((state)->A_star);                               \
    ec_free((state)->J);                                    \
    ec_free((state)->J_B);                                  \
    ec_free((state)->J_B_tilde);                            \
    ec_free((state)->R_B);                                  \
    bn_free((state)->beta);                                 \
    free(state);                                            \
    state = NULL;                                           \
  } while (0)

typedef int (*msg_handler_t)(bob_state_t, void*, uint8_t*);

int get_message_type(char *key);
msg_handler_t get_message_handler(char *key);
int handle_message(bob_state_t state, void *socket, zmq_msg_t message);
int receive_message(bob_state_t state, void *socket);

int promise_init(void *socket);
int promise_init_done_handler(bob_state_t state, void *socket, uint8_t *data);
int promise_sign_done_handler(bob_state_t state, void *socket, uint8_t *data);
int promise_end_done_handler(bob_state_t state, void *socket, uint8_t *data);
int puzzle_share(bob_state_t state, void *socket);
int puzzle_share_done_handler(bob_state_t state, void *socket, uint8_t *data);
int puzzle_solution_share_handler(bob_state_t state, void *socet, uint8_t *data);

#endif // TRILERO_DLSAG_INCLUDE_BOB