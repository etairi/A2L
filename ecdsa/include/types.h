#ifndef TRILERO_ECDSA_INCLUDE_TYPES
#define TRILERO_ECDSA_INCLUDE_TYPES

#include "relic/relic.h"
#include "pari/pari.h"

typedef struct {
  char *type;
  uint8_t *data;
} message_st;

typedef message_st *message_t;

#define message_null(message) message = NULL;

#define message_new(message, type_length, data_length)                  \
  do {                                                                  \
    message = malloc(sizeof(message_st));                               \
    if (message == NULL) {                                              \
      THROW(ERR_NO_MEMORY);                                             \
    }                                                                   \
    (message)->type = malloc(sizeof(char) * type_length);               \
    if ((message)->type == NULL) {                                      \
      THROW(ERR_NO_MEMORY);                                             \
    }                                                                   \
    (message)->data = malloc(sizeof(uint8_t) * data_length);            \
    if ((message)->data == NULL) {                                      \
      THROW(ERR_NO_MEMORY);                                             \
    }                                                                   \
  } while (0)

#define message_free(message)                                           \
  do {                                                                  \
    free((message)->type);                                              \
    free((message)->data);                                              \
    free(message);                                                      \
    message = NULL;                                                     \
  } while (0)

typedef struct {
  ec_t a;
  ec_t b;
  bn_t z;
} zk_proof_st;

typedef zk_proof_st *zk_proof_t;

#define zk_proof_null(proof) proof = NULL;

#define zk_proof_new(proof)                   \
  do {                                        \
    proof = malloc(sizeof(zk_proof_st));      \
    if (proof == NULL) {                      \
      THROW(ERR_NO_MEMORY);                   \
    }                                         \
    ec_new((proof)->a);                       \
    ec_new((proof)->b);                       \
    bn_new((proof)->z);                       \
  } while (0)

#define zk_proof_free(proof)                  \
  do {                                        \
    ec_free((proof)->a);                      \
    ec_free((proof)->b);                      \
    bn_free((proof)->z);                      \
    free(proof);                              \
    proof = NULL;                             \
  } while (0)

typedef struct {
  GEN t1;
  ec_t t2;
  GEN t3;
  GEN u1;
  GEN u2;
} zk_proof_cldl_st;

typedef zk_proof_cldl_st *zk_proof_cldl_t;

#define zk_proof_cldl_null(proof) proof = NULL;

#define zk_proof_cldl_new(proof)              \
  do {                                        \
    proof = malloc(sizeof(zk_proof_cldl_st)); \
    if (proof == NULL) {                      \
      THROW(ERR_NO_MEMORY);                   \
    }                                         \
    ec_new((proof)->t2);                      \
  } while (0)

#define zk_proof_cldl_free(proof)             \
  do {                                        \
    ec_free((proof)->t2);                     \
    free(proof);                              \
    proof = NULL;                             \
  } while (0)

typedef struct {
  bn_t c;
  ec_t r;
} commit_st;

typedef commit_st *commit_t;

#define commit_null(commit) commit = NULL;

#define commit_new(commit)                    \
  do {                                        \
    commit = malloc(sizeof(commit_st));       \
    if (commit == NULL) {                     \
      THROW(ERR_NO_MEMORY);                   \
    }                                         \
    bn_new((commit)->c);                      \
    ec_new((commit)->r);                      \
  } while (0)

#define commit_free(commit)                   \
  do {                                        \
    bn_free((commit)->c);                     \
    ec_free((commit)->r);                     \
    free(commit);                             \
    commit = NULL;                            \
  } while (0)

typedef struct {
  GEN Delta_K;  // fundamental discriminant
  GEN E;        // the secp256k1 elliptic curve
  GEN q;        // the order of the elliptic curve
  GEN G;        // the generator of the elliptic curve group
  GEN g_q;      // the generator of G^q
  GEN bound;    // the bound for exponentiation
} cl_params_st;

typedef cl_params_st *cl_params_t;

#define cl_params_null(params) params = NULL;

#define cl_params_new(params)                         \
  do {                                                \
    params = malloc(sizeof(cl_params_st));            \
    if (params == NULL) {                             \
      THROW(ERR_NO_MEMORY);                           \
    }                                                 \
  } while (0)

#define cl_params_free(params)                        \
  do {                                                \
    free(params);                                     \
    params = NULL;                                    \
  } while (0)

typedef struct {
  GEN c1;
  GEN c2;
  GEN r;
} cl_ciphertext_st;

typedef cl_ciphertext_st *cl_ciphertext_t;

#define cl_ciphertext_null(ciphertext) ciphertext = NULL;

#define cl_ciphertext_new(ciphertext)                 \
  do {                                                \
    ciphertext = malloc(sizeof(cl_ciphertext_st));    \
    if (ciphertext == NULL) {                         \
      THROW(ERR_NO_MEMORY);                           \
    }                                                 \
  } while (0)

#define cl_ciphertext_free(ciphertext)                \
  do {                                                \
    free(ciphertext);                                 \
    ciphertext = NULL;                                \
  } while (0)

typedef struct {
  GEN sk;
} cl_secret_key_st;

typedef cl_secret_key_st *cl_secret_key_t;

#define cl_secret_key_null(secret_key) secret_key = NULL;

#define cl_secret_key_new(secret_key)                 \
  do {                                                \
    secret_key = malloc(sizeof(cl_secret_key_st));    \
    if (secret_key == NULL) {                         \
      THROW(ERR_NO_MEMORY);                           \
    }                                                 \
  } while (0)

#define cl_secret_key_free(secret_key)                \
  do {                                                \
    free(secret_key);                                 \
    secret_key = NULL;                                \
  } while (0)


typedef struct {
  GEN pk;
} cl_public_key_st;

typedef cl_public_key_st *cl_public_key_t;

#define cl_public_key_null(public_key) public_key = NULL;

#define cl_public_key_new(public_key)                 \
  do {                                                \
    public_key = malloc(sizeof(cl_public_key_st));    \
    if (public_key == NULL) {                         \
      THROW(ERR_NO_MEMORY);                           \
    }                                                 \
  } while (0)

#define cl_public_key_free(public_key)                \
  do {                                                \
    free(public_key);                                 \
    public_key = NULL;                                \
  } while (0)

typedef struct {
  bn_t sk;
} ec_secret_key_st;

typedef ec_secret_key_st *ec_secret_key_t;

#define ec_secret_key_null(secret_key) secret_key = NULL;

#define ec_secret_key_new(secret_key)                 \
  do {                                                \
    secret_key = malloc(sizeof(ec_secret_key_st));    \
    if (secret_key == NULL) {                         \
      THROW(ERR_NO_MEMORY);                           \
    }                                                 \
    bn_new((secret_key)->sk);                         \
  } while (0)

#define ec_secret_key_free(secret_key)                \
  do {                                                \
    bn_free((secret_key)->sk);                        \
    free(secret_key);                                 \
    secret_key = NULL;                                \
  } while (0)

typedef struct {
  ec_t pk;
} ec_public_key_st;

typedef ec_public_key_st *ec_public_key_t;

#define ec_public_key_null(public_key) public_key = NULL;

#define ec_public_key_new(public_key)                 \
  do {                                                \
    public_key = malloc(sizeof(ec_public_key_st));    \
    if (public_key == NULL) {                         \
      THROW(ERR_NO_MEMORY);                           \
    }                                                 \
    ec_new((public_key)->pk);                         \
  } while (0)

#define ec_public_key_free(public_key)                \
  do {                                                \
    ec_free((public_key)->pk);                        \
    free(public_key);                                 \
    public_key = NULL;                                \
  } while (0)

typedef struct {
  cl_public_key_t cl_pk;
  cl_secret_key_t cl_sk;
  ec_public_key_t ec_pk;
  ec_secret_key_t ec_sk;
} keys_st;

typedef keys_st *keys_t;

#define keys_null(keys) keys = NULL;

#define keys_new(keys)                              \
  do {                                              \
    keys = malloc(sizeof(keys_st));                 \
    if (keys == NULL) {                             \
      THROW(ERR_NO_MEMORY);                         \
    }                                               \
    cl_public_key_new((keys)->cl_pk);               \
    cl_secret_key_new((keys)->cl_sk);               \
    ec_public_key_new((keys)->ec_pk);               \
    ec_secret_key_new((keys)->ec_sk);               \
  } while (0)

#define keys_free(keys)                             \
  do {                                              \
    cl_public_key_free((keys)->cl_pk);              \
    cl_secret_key_free((keys)->cl_sk);              \
    ec_public_key_free((keys)->ec_pk);              \
    ec_secret_key_free((keys)->ec_sk);              \
    free(keys);                                     \
    keys = NULL;                                    \
  } while (0)

#endif // TRILERO_ECDSA_INCLUDE_TYPES