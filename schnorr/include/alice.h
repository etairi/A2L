#ifndef TRILERO_SCHNORR_INCLUDE_ALICE
#define TRILERO_SCHNORR_INCLUDE_ALICE

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
  { "promise_sent", PROMISE_SENT },
  { "puzzle_share", PUZZLE_SHARE },
  { "payment_init_done", PAYMENT_INIT_DONE },
  { "payment_sign_done", PAYMENT_SIGN_DONE },
  { "payment_complete", PAYMENT_COMPLETE },
  { "puzzle_solve", PUZZLE_SOLVE }
};

#define TOTAL_MESSAGES (sizeof(msg_lookuptable) / sizeof(symstruct_t))

typedef struct {
  keys_t keys;
  cl_public_key_t tumbler_cl_pk;
  commit_t com;
  ec_t g_to_the_alpha_times_beta;
  cl_ciphertext_t ctx_alpha_times_beta;
  bn_t k_1;
  ec_t R_1;
  bn_t s_hat;
  bn_t s;
  bn_t e;
  bn_t tau;
  bn_t alpha_hat;
} alice_state_st;

typedef alice_state_st *alice_state_t;

#define alice_state_null(state) state = NULL;

#define alice_state_new(state)                              \
  do {                                                      \
    state = malloc(sizeof(alice_state_st));                 \
    if (state == NULL) {                                    \
      THROW(ERR_NO_MEMORY);                                 \
    }                                                       \
    keys_new((state)->keys);                                \
    cl_public_key_new((state)->tumbler_cl_pk);              \
    commit_new((state)->com);                               \
    ec_new((state)->g_to_the_alpha_times_beta);             \
    cl_ciphertext_new((state)->ctx_alpha_times_beta);       \
    bn_new((state)->k_1);                                   \
    ec_new((state)->R_1);                                   \
    bn_new((state)->s_hat);                                 \
    bn_new((state)->s);                                     \
    bn_new((state)->e);                                     \
    bn_new((state)->tau);                                   \
    bn_new((state)->alpha_hat);                             \
  } while (0)

#define alice_state_free(state)                             \
  do {                                                      \
    keys_free((state)->keys);                               \
    cl_public_key_free((state)->tumbler_cl_pk);             \
    commit_free((state)->com);                              \
    ec_free((state)->g_to_the_alpha_times_beta);            \
    cl_ciphertext_free((state)->ctx_alpha_times_beta);      \
    bn_free((state)->k_1);                                  \
    ec_free((state)->R_1);                                  \
    bn_free((state)->s_hat);                                \
    bn_free((state)->s);                                    \
    bn_free((state)->e);                                    \
    bn_free((state)->tau);                                  \
    bn_free((state)->alpha_hat);                            \
    free(state);                                            \
    state = NULL;                                           \
  } while (0)

typedef int (*msg_handler_t)(alice_state_t, void*, uint8_t*);

int get_message_type(char *key);
msg_handler_t get_message_handler(char *key);
int handle_message(alice_state_t state, void *socket, zmq_msg_t message);
int receive_message(alice_state_t state, void *socket);

int puzzle_share_handler(alice_state_t state, void *socket, uint8_t *data);
int payment_init(void *socket);
int payment_init_done_handler(alice_state_t state, void *socket, uint8_t *data);
int payment_sign_done_handler(alice_state_t state, void *socket, uint8_t *data);
int puzzle_solve_handler(alice_state_t state, void *socket, uint8_t *data);

#endif // TRILERO_SCHNORR_INCLUDE_ALICE