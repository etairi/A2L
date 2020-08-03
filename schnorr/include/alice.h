#ifndef A2L_SCHNORR_INCLUDE_ALICE
#define A2L_SCHNORR_INCLUDE_ALICE

#include <stddef.h>
#include <string.h>
#include "relic/relic.h"
#include "zmq.h"
#include "types.h"

#define TUMBLER_ENDPOINT  "tcp://localhost:8181"
#define ALICE_ENDPOINT    "tcp://*:8182"
#define BOB_ENDPOINT      "tcp://localhost:8183"

typedef enum {
  REGISTRATION_DONE,
  PUZZLE_SHARE,
  PAYMENT_DONE,
} msgcode_t;

typedef struct {
  char *key;
  msgcode_t code;
} symstruct_t;

static symstruct_t msg_lookuptable[] = {
  { "registration_done", REGISTRATION_DONE },
  { "puzzle_share", PUZZLE_SHARE },
  { "payment_done", PAYMENT_DONE }
};

#define TOTAL_MESSAGES (sizeof(msg_lookuptable) / sizeof(symstruct_t))

typedef struct {
  ec_secret_key_t alice_ec_sk;
  ec_public_key_t alice_ec_pk;
  ec_public_key_t tumbler_ec_pk;
  ps_public_key_t tumbler_ps_pk;
  cl_public_key_t tumbler_cl_pk;
  cl_params_t cl_params;
  commit_t com;
  ec_t g_to_the_alpha_times_beta;
  ec_t g_to_the_alpha_times_beta_times_tau;
  cl_ciphertext_t ctx_alpha_times_beta;
  schnorr_signature_t sigma_hat_s;
  schnorr_signature_t sigma_s;
  bn_t tau;
  bn_t alpha_hat;
  bn_t tid;
  ps_signature_t sigma_tid;
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
    ec_secret_key_new((state)->alice_ec_sk);                \
    ec_public_key_new((state)->alice_ec_pk);                \
    ec_public_key_new((state)->tumbler_ec_pk);              \
    ps_public_key_new((state)->tumbler_ps_pk);              \
    cl_public_key_new((state)->tumbler_cl_pk);              \
    cl_params_new((state)->cl_params);                      \
    commit_new((state)->com);                               \
    ec_new((state)->g_to_the_alpha_times_beta);             \
    ec_new((state)->g_to_the_alpha_times_beta_times_tau);   \
    cl_ciphertext_new((state)->ctx_alpha_times_beta);       \
    schnorr_signature_new((state)->sigma_hat_s);            \
    schnorr_signature_new((state)->sigma_s);                \
    bn_new((state)->tau);                                   \
    bn_new((state)->alpha_hat);                             \
    bn_new((state)->tid);                                   \
    ps_signature_new((state)->sigma_tid);                   \
    pedersen_com_new((state)->pcom);                        \
    pedersen_decom_new((state)->pdecom);                    \
  } while (0)

#define alice_state_free(state)                             \
  do {                                                      \
    ec_secret_key_free((state)->alice_ec_sk);               \
    ec_public_key_free((state)->alice_ec_pk);               \
    ec_public_key_free((state)->tumbler_ec_pk);             \
    ps_public_key_free((state)->tumbler_ps_pk);             \
    cl_public_key_free((state)->tumbler_cl_pk);             \
    cl_params_free((state)->cl_params);                     \
    commit_free((state)->com);                              \
    ec_free((state)->g_to_the_alpha_times_beta);            \
    ec_free((state)->g_to_the_alpha_times_beta_times_tau);  \
    cl_ciphertext_free((state)->ctx_alpha_times_beta);      \
    schnorr_signature_free((state)->sigma_hat_s);           \
    schnorr_signature_free((state)->sigma_s);               \
    bn_free((state)->tau);                                  \
    bn_free((state)->alpha_hat);                            \
    bn_free((state)->tid);                                  \
    ps_signature_free((state)->sigma_tid);                  \
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

int registration(alice_state_t state, void *socket);
int registration_done_handler(alice_state_t state, void *socket, uint8_t *data);
int token_share(alice_state_t state, void *socket);
int puzzle_share_handler(alice_state_t state, void *socket, uint8_t *data);
int payment_init(alice_state_t state, void *socket);
int payment_done_handler(alice_state_t state, void *socket, uint8_t *data);
int puzzle_solution_share(alice_state_t state, void *socket);

#endif // A2L_SCHNORR_INCLUDE_ALICE