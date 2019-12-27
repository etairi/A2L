#ifndef TRILERO_SCHNORR_INCLUDE_TUMBLER
#define TRILERO_SCHNORR_INCLUDE_TUMBLER

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
  keys_t keys;
  ec_public_key_t ec_pk_tumbler_alice;
  ec_public_key_t ec_pk_tumbler_bob;
  cl_params_t cl_params;
  cl_public_key_t cl_pk_alice;
  cl_public_key_t cl_pk_bob;
  bn_t alpha;
  ec_t g_to_the_alpha;
  cl_ciphertext_t ctx_alpha;
  bn_t k_2_prime;
  ec_t R_2_prime;
  ec_t R_1_prime;
  bn_t k_2;
  ec_t R_2;
  zk_proof_t pi_2_prime;
  zk_proof_t pi_2;
  bn_t e_prime;
  bn_t e;
  bn_t s;
  bn_t gamma;
} tumbler_state_st;

typedef tumbler_state_st *tumbler_state_t;

#define tumbler_state_null(state) state = NULL;

#define tumbler_state_new(state)                          \
  do {                                                    \
    state = malloc(sizeof(tumbler_state_st));             \
    if (state == NULL) {                                  \
      THROW(ERR_NO_MEMORY);                               \
    }                                                     \
    keys_new((state)->keys);                              \
    ec_public_key_new((state)->ec_pk_tumbler_alice);      \
    ec_public_key_new((state)->ec_pk_tumbler_bob);        \
    cl_params_new((state)->cl_params);                    \
    cl_public_key_new((state)->cl_pk_alice);              \
    cl_public_key_new((state)->cl_pk_bob);                \
    bn_new((state)->alpha);                               \
    ec_new((state)->g_to_the_alpha);                      \
    cl_ciphertext_new((state)->ctx_alpha);                \
    bn_new((state)->k_2_prime);                           \
    ec_new((state)->R_2_prime);                           \
    ec_new((state)->R_1_prime);                           \
    bn_new((state)->k_2);                                 \
    ec_new((state)->R_2);                                 \
    zk_proof_new((state)->pi_2_prime);                    \
    zk_proof_new((state)->pi_2);                          \
    bn_new((state)->e_prime);                             \
    bn_new((state)->e);                                   \
    bn_new((state)->s);                                   \
    bn_new((state)->gamma);                               \
  } while (0)

#define tumbler_state_free(state)                         \
  do {                                                    \
    keys_free((state)->keys);                             \
    ec_public_key_free((state)->ec_pk_tumbler_alice);     \
    ec_public_key_free((state)->ec_pk_tumbler_bob);       \
    cl_params_free((state)->cl_params);                   \
    cl_public_key_free((state)->cl_pk_alice);             \
    cl_public_key_free((state)->cl_pk_bob);               \
    bn_free((state)->alpha);                              \
    ec_free((state)->g_to_the_alpha);                     \
    cl_ciphertext_free((state)->ctx_alpha);               \
    bn_free((state)->k_2_prime);                          \
    ec_free((state)->R_2_prime);                          \
    ec_free((state)->R_1_prime);                          \
    bn_free((state)->k_2);                                \
    ec_free((state)->R_2);                                \
    zk_proof_free((state)->pi_2_prime);                   \
    zk_proof_free((state)->pi_2);                         \
    bn_free((state)->e_prime);                            \
    bn_free((state)->e);                                  \
    bn_free((state)->s);                                  \
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

#endif // TRILERO_SCHNORR_INCLUDE_TUMBLER