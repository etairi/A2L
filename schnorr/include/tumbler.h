#ifndef A2L_SCHNORR_INCLUDE_TUMBLER
#define A2L_SCHNORR_INCLUDE_TUMBLER

#include <stddef.h>
#include <string.h>
#include "relic/relic.h"
#include "zmq.h"
#include "types.h"

#define TUMBLER_ENDPOINT  "tcp://*:8181"

typedef enum {
  REGISTRATION,
  PROMISE_INIT,
  PAYMENT_INIT,
} msgcode_t;

typedef struct {
  char *key;
  msgcode_t code;
} symstruct_t;

static symstruct_t msg_lookuptable[] = {
  { "registration", REGISTRATION },
  { "promise_init", PROMISE_INIT },
  { "payment_init", PAYMENT_INIT },
};

#define TOTAL_MESSAGES (sizeof(msg_lookuptable) / sizeof(symstruct_t))

typedef struct {
  ec_secret_key_t tumbler_ec_sk;
  ec_public_key_t tumbler_ec_pk;
  ec_public_key_t alice_ec_pk;
  ec_public_key_t bob_ec_pk;
  ps_secret_key_t tumbler_ps_sk;
  ps_public_key_t tumbler_ps_pk;
  cl_secret_key_t tumbler_cl_sk;
  cl_public_key_t tumbler_cl_pk;
  cl_params_t cl_params;
  bn_t gamma;
  bn_t alpha;
  ec_t g_to_the_alpha;
  cl_ciphertext_t ctx_alpha;
  schnorr_signature_t sigma_r;
  schnorr_signature_t sigma_tr;
  schnorr_signature_t sigma_s;
  schnorr_signature_t sigma_ts;
} tumbler_state_st;

typedef tumbler_state_st *tumbler_state_t;

#define tumbler_state_null(state) state = NULL;

#define tumbler_state_new(state)                          \
  do {                                                    \
    state = malloc(sizeof(tumbler_state_st));             \
    if (state == NULL) {                                  \
      RLC_THROW(ERR_NO_MEMORY);                           \
    }                                                     \
    ec_secret_key_new((state)->tumbler_ec_sk);            \
    ec_public_key_new((state)->tumbler_ec_pk);            \
    ec_public_key_new((state)->alice_ec_pk);              \
    ec_public_key_new((state)->bob_ec_pk);                \
    ps_secret_key_new((state)->tumbler_ps_sk);            \
    ps_public_key_new((state)->tumbler_ps_pk);            \
    cl_secret_key_new((state)->tumbler_cl_sk);            \
    cl_public_key_new((state)->tumbler_cl_pk);            \
    cl_params_new((state)->cl_params);                    \
    bn_new((state)->gamma);                               \
    bn_new((state)->alpha);                               \
    ec_new((state)->g_to_the_alpha);                      \
    cl_ciphertext_new((state)->ctx_alpha);                \
    schnorr_signature_new((state)->sigma_r);              \
    schnorr_signature_new((state)->sigma_tr);             \
    schnorr_signature_new((state)->sigma_s);              \
    schnorr_signature_new((state)->sigma_ts);             \
  } while (0)

#define tumbler_state_free(state)                         \
  do {                                                    \
    ec_secret_key_free((state)->tumbler_ec_sk);           \
    ec_public_key_free((state)->tumbler_ec_pk);           \
    ec_public_key_free((state)->alice_ec_pk);             \
    ec_public_key_free((state)->bob_ec_pk);               \
    ps_secret_key_free((state)->tumbler_ps_sk);           \
    ps_public_key_free((state)->tumbler_ps_pk);           \
    cl_secret_key_free((state)->tumbler_cl_sk);           \
    cl_public_key_free((state)->tumbler_cl_pk);           \
    cl_params_free((state)->cl_params);                   \
    bn_free((state)->gamma);                              \
    bn_free((state)->alpha);                              \
    ec_free((state)->g_to_the_alpha);                     \
    cl_ciphertext_free((state)->ctx_alpha);               \
    schnorr_signature_free((state)->sigma_r);             \
    schnorr_signature_free((state)->sigma_tr);            \
    schnorr_signature_free((state)->sigma_s);             \
    schnorr_signature_free((state)->sigma_ts);            \
    free(state);                                          \
    state = NULL;                                         \
  } while (0)

typedef int (*msg_handler_t)(tumbler_state_t, void*, uint8_t*);

int get_message_type(char *key);
msg_handler_t get_message_handler(char *key);
int handle_message(tumbler_state_t state, void *socket, zmq_msg_t message);
int receive_message(tumbler_state_t state, void *socket);

int registration_handler(tumbler_state_t state, void *socket, uint8_t *data);
int promise_init_handler(tumbler_state_t state, void *socket, uint8_t *data);
int payment_init_handler(tumbler_state_t state, void *socket, uint8_t *data);

#endif // A2L_SCHNORR_INCLUDE_TUMBLER