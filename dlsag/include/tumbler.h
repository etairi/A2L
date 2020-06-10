#ifndef TRILERO_DLSAG_INCLUDE_TUMBLER
#define TRILERO_DLSAG_INCLUDE_TUMBLER

#include <stddef.h>
#include <string.h>
#include "relic/relic.h"
#include "zmq.h"
#include "types.h"

#define TUMBLER_ENDPOINT  "tcp://*:8181"

static uint8_t tx[2] = { 116, 120 }; // "tx"

typedef enum {
  PROMISE_INIT,
  PROMISE_SIGN,
  PROMISE_END,
  PAYMENT_INIT,
  PAYMENT_SIGN,
  PAYMENT_END,
} msgcode_t;

typedef struct {
  char *key;
  msgcode_t code;
} symstruct_t;

static symstruct_t msg_lookuptable[] = {
  { "promise_init", PROMISE_INIT },
  { "promise_sign", PROMISE_SIGN },
  { "promise_end", PROMISE_END },
  { "payment_init", PAYMENT_INIT },
  { "payment_sign", PAYMENT_SIGN },
  { "payment_end", PAYMENT_END }
};

#define TOTAL_MESSAGES (sizeof(msg_lookuptable) / sizeof(symstruct_t))

typedef struct {
  ring_t ring;
  keys_t keys_alice;
  keys_t keys_bob;
  ec_public_key_t ec_pk_tumbler_alice;
  ec_public_key_t ec_pk_tumbler_bob;
  cl_params_t cl_params;
  cl_public_key_t cl_pk_alice;
  cl_public_key_t cl_pk_bob;
  bn_t *vec_s;
  bn_t h0;
  bn_t s0;
  bn_t s0_T;
  bn_t alpha;
  cl_ciphertext_t ctx_alpha;
  ec_t A;
  ec_t A_star;
  ec_t J;
  ec_t J_T;
  ec_t J_T_tilde;
  ec_t R_T;
  zk_proof_t pi_T;
  bn_t gamma;
} tumbler_state_st;

typedef tumbler_state_st *tumbler_state_t;

#define tumbler_state_null(state) state = NULL;

#define tumbler_state_new(state)                          \
  do {                                                    \
    state = malloc(sizeof(tumbler_state_st));             \
    if (state == NULL) {                                  \
      RLC_THROW(ERR_NO_MEMORY);                               \
    }                                                     \
    ring_new((state)->ring, RING_SIZE);                   \
    keys_new((state)->keys_alice);                        \
    keys_new((state)->keys_bob);                          \
    ec_public_key_new((state)->ec_pk_tumbler_alice);      \
    ec_public_key_new((state)->ec_pk_tumbler_bob);        \
    cl_params_new((state)->cl_params);                    \
    cl_public_key_new((state)->cl_pk_alice);              \
    cl_public_key_new((state)->cl_pk_bob);                \
    (state)->vec_s = malloc(sizeof(bn_t) * RING_SIZE);    \
    if ((state)->vec_s == NULL) {                         \
      RLC_THROW(ERR_NO_MEMORY);                               \
    }                                                     \
    for (size_t i = 0; i < RING_SIZE; i++) {              \
      bn_new((state)->vec_s[i]);                          \
    }                                                     \
    bn_new((state)->h0);                                  \
    bn_new((state)->s0);                                  \
    bn_new((state)->s0_T);                                \
    bn_new((state)->alpha);                               \
    ec_new((state)->A);                                   \
    ec_new((state)->A_star);                              \
    ec_new((state)->g_to_the_alpha);                      \
    cl_ciphertext_new((state)->ctx_alpha);                \
    ec_new((state)->J);                                   \
    ec_new((state)->J_T);                                 \
    ec_new((state)->J_T_tilde);                           \
    ec_new((state)->R_T);                                 \
    zk_proof_new((state)->pi_T);                          \
    bn_new((state)->gamma);                               \
  } while (0)

#define tumbler_state_free(state)                         \
  do {                                                    \
    ring_free((state)->ring, RING_SIZE);                  \
    keys_free((state)->keys_alice);                       \
    keys_free((state)->keys_bob);                         \
    ec_public_key_free((state)->ec_pk_tumbler_alice);     \
    ec_public_key_free((state)->ec_pk_tumbler_bob);       \
    cl_params_free((state)->cl_params);                   \
    cl_public_key_free((state)->cl_pk_alice);             \
    cl_public_key_free((state)->cl_pk_bob);               \
    for (size_t i = 0; i < RING_SIZE; i++) {              \
      bn_free((state)->vec_s[i]);                         \
    }                                                     \
    free((state)->vec_s);                                 \
    bn_free((state)->h0);                                 \
    bn_free((state)->s0);                                 \
    bn_free((state)->s0_T);                               \
    bn_free((state)->alpha);                              \
    ec_free((state)->A);                                  \
    ec_free((state)->A_star);                             \
    ec_free((state)->g_to_the_alpha);                     \
    cl_ciphertext_free((state)->ctx_alpha);               \
    ec_free((state)->J);                                  \
    ec_free((state)->J_T);                                \
    ec_free((state)->J_T_tilde);                          \
    ec_free((state)->R_T);                                \
    zk_proof_free((state)->pi_T);                         \
    bn_free((state)->gamma);                              \
    free(state);                                          \
    state = NULL;                                         \
  } while (0)

typedef int (*msg_handler_t)(tumbler_state_t, void*, uint8_t*);

int get_message_type(char *key);
msg_handler_t get_message_handler(char *key);
int handle_message(tumbler_state_t state, void *socket, zmq_msg_t message);
int receive_message(tumbler_state_t state, void *socket);

int promise_init_handler(tumbler_state_t state, void *socket, uint8_t *data);
int promise_sign_handler(tumbler_state_t state, void *socket, uint8_t *data);
int promise_end_handler(tumbler_state_t state, void *socket, uint8_t *data);
int payment_init_handler(tumbler_state_t state, void *socket, uint8_t *data);
int payment_sign_handler(tumbler_state_t state, void *socket, uint8_t *data);
int payment_end_handler(tumbler_state_t state, void *socket, uint8_t *data);

#endif // TRILERO_DLSAG_INCLUDE_TUMBLER