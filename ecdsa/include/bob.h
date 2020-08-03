#ifndef A2L_ECDSA_INCLUDE_BOB
#define A2L_ECDSA_INCLUDE_BOB

#include <stddef.h>
#include <string.h>
#include "relic/relic.h"
#include "zmq.h"
#include "types.h"

#define TUMBLER_ENDPOINT  "tcp://localhost:8181"
#define ALICE_ENDPOINT    "tcp://localhost:8182"
#define BOB_ENDPOINT      "tcp://*:8183"

typedef enum {
  TOKEN_SHARE,
  PROMISE_DONE,
  PUZZLE_SHARE_DONE,
  PUZZLE_SOLUTION_SHARE
} msgcode_t;

typedef struct {
  char *key;
  msgcode_t code;
} symstruct_t;

static symstruct_t msg_lookuptable[] = {
  { "token_share", TOKEN_SHARE },
  { "promise_done", PROMISE_DONE },
  { "puzzle_share_done", PUZZLE_SHARE_DONE },
  { "puzzle_solution_share", PUZZLE_SOLUTION_SHARE }
};

#define TOTAL_MESSAGES (sizeof(msg_lookuptable) / sizeof(symstruct_t))

typedef struct {
  ec_secret_key_t bob_ec_sk;
  ec_public_key_t bob_ec_pk;
  ec_public_key_t tumbler_ec_pk;
  ps_public_key_t tumbler_ps_pk;
  cl_public_key_t tumbler_cl_pk;
  cl_params_t cl_params;
  commit_t com;
  ec_t g_to_the_alpha;
  cl_ciphertext_t ctx_alpha;
  ecdsa_signature_t sigma_r;
  ecdsa_signature_t sigma_t;
  bn_t beta;
  bn_t tid;
  ps_signature_t sigma_tid;
} bob_state_st;

typedef bob_state_st *bob_state_t;

#define bob_state_null(state) state = NULL;

#define bob_state_new(state)                                \
  do {                                                      \
    state = malloc(sizeof(bob_state_st));                   \
    if (state == NULL) {                                    \
      RLC_THROW(ERR_NO_MEMORY);                             \
    }                                                       \
    ec_secret_key_new((state)->bob_ec_sk);                  \
    ec_public_key_new((state)->bob_ec_pk);                  \
    ec_public_key_new((state)->tumbler_ec_pk);              \
    ps_public_key_new((state)->tumbler_ps_pk);              \
    cl_public_key_new((state)->tumbler_cl_pk);              \
    cl_params_new((state)->cl_params);                      \
    commit_new((state)->com);                               \
    ec_new((state)->g_to_the_alpha);                        \
    cl_ciphertext_new((state)->ctx_alpha);                  \
    ecdsa_signature_new((state)->sigma_r);                  \
    ecdsa_signature_new((state)->sigma_t);                  \
    bn_new((state)->beta);                                  \
    bn_new((state)->tid);                                   \
    ps_signature_new((state)->sigma_tid);                   \
  } while (0)

#define bob_state_free(state)                               \
  do {                                                      \
    ec_secret_key_free((state)->bob_ec_sk);                 \
    ec_public_key_free((state)->bob_ec_pk);                 \
    ec_public_key_free((state)->tumbler_ec_pk);             \
    ps_public_key_free((state)->tumbler_ps_pk);             \
    cl_public_key_free((state)->tumbler_cl_pk);             \
    cl_params_free((state)->cl_params);                     \
    commit_free((state)->com);                              \
    ec_free((state)->g_to_the_alpha);                       \
    cl_ciphertext_free((state)->ctx_alpha);                 \
    ecdsa_signature_free((state)->sigma_r);                 \
    ecdsa_signature_free((state)->sigma_t);                 \
    bn_free((state)->beta);                                 \
    bn_free((state)->tid);                                  \
    ps_signature_free((state)->sigma_tid);                  \
    free(state);                                            \
    state = NULL;                                           \
  } while (0)

typedef int (*msg_handler_t)(bob_state_t, void*, uint8_t*);

int get_message_type(char *key);
msg_handler_t get_message_handler(char *key);
int handle_message(bob_state_t state, void *socket, zmq_msg_t message);
int receive_message(bob_state_t state, void *socket);

int token_share_handler(bob_state_t state, void *socet, uint8_t *data);
int promise_init(bob_state_t state, void *socket);
int promise_done_handler(bob_state_t state, void *socket, uint8_t *data);
int puzzle_share(bob_state_t state, void *socket);
int puzzle_share_done_handler(bob_state_t state, void *socket, uint8_t *data);
int puzzle_solution_share_handler(bob_state_t state, void *socet, uint8_t *data);

#endif // A2L_ECDSA_INCLUDE_BOB