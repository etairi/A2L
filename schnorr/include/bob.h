#ifndef TRILERO_SCHNORR_INCLUDE_BOB
#define TRILERO_SCHNORR_INCLUDE_BOB

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
  keys_t keys;
  cl_params_t cl_params;
  cl_public_key_t tumbler_cl_pk;
  commit_t com;
  ec_t g_to_the_alpha;
  cl_ciphertext_t ctx_alpha;
  bn_t k_1_prime;
  ec_t R_1_prime;
  bn_t s_prime;
  bn_t e_prime;
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
    keys_new((state)->keys);                                \
    cl_params_new((state)->cl_params);                      \
    cl_public_key_new((state)->tumbler_cl_pk);              \
    commit_new((state)->com);                               \
    ec_new((state)->g_to_the_alpha);                        \
    cl_ciphertext_new((state)->ctx_alpha);                  \
    bn_new((state)->k_1_prime);                             \
    ec_new((state)->R_1_prime);                             \
    bn_new((state)->s_prime);                               \
    bn_new((state)->e_prime);                               \
    bn_new((state)->beta);                                  \
  } while (0)

#define bob_state_free(state)                               \
  do {                                                      \
    keys_free((state)->keys);                               \
    cl_params_free((state)->cl_params);                     \
    cl_public_key_free((state)->tumbler_cl_pk);             \
    commit_free((state)->com);                              \
    ec_free((state)->g_to_the_alpha);                       \
    cl_ciphertext_free((state)->ctx_alpha);                 \
    bn_free((state)->k_1_prime);                            \
    ec_free((state)->R_1_prime);                            \
    bn_free((state)->s_prime);                              \
    bn_free((state)->e_prime);                              \
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

#endif // TRILERO_SCHNORR_INCLUDE_BOB