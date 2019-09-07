#ifndef TRILERO_SCHNORR_INCLUDE_TYPES
#define TRILERO_SCHNORR_INCLUDE_TYPES

#include "relic/relic.h"

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

#define zk_proof_null(zk_proof) zk_proof = NULL;

#define zk_proof_new(zk_proof)                \
  do {                                        \
    zk_proof = malloc(sizeof(zk_proof_st));   \
    if (zk_proof == NULL) {                   \
      THROW(ERR_NO_MEMORY);                   \
    }                                         \
    ec_new((zk_proof)->a);                    \
    ec_new((zk_proof)->b);                    \
    bn_new((zk_proof)->z);                    \
  } while (0)

#define zk_proof_free(zk_proof)               \
  do {                                        \
    ec_free((zk_proof)->a);                   \
    ec_free((zk_proof)->b);                   \
    bn_free((zk_proof)->z);                   \
    free(zk_proof);                           \
    zk_proof = NULL;                          \
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
  bn_t sk;
} paillier_secret_key_st;

typedef paillier_secret_key_st *paillier_secret_key_t;

#define paillier_secret_key_null(secret_key) secret_key = NULL;

#define paillier_secret_key_new(secret_key)                     \
  do {                                                          \
    secret_key = malloc(sizeof(paillier_secret_key_st));        \
    if (secret_key == NULL) {                                   \
      THROW(ERR_NO_MEMORY);                                     \
    }                                                           \
    bn_new((secret_key)->sk);                                   \
  } while (0)

#define paillier_secret_key_free(secret_key)                    \
  do {                                                          \
    bn_free((secret_key)->sk);                                  \
    free(secret_key);                                           \
    secret_key = NULL;                                          \
  } while (0)

typedef struct {
  bn_t pk;
} paillier_public_key_st;

typedef paillier_public_key_st *paillier_public_key_t;

#define paillier_public_key_null(public_key) public_key = NULL;

#define paillier_public_key_new(public_key)                     \
  do {                                                          \
    public_key = malloc(sizeof(paillier_public_key_st));        \
    if (public_key == NULL) {                                   \
      THROW(ERR_NO_MEMORY);                                     \
    }                                                           \
    bn_new((public_key)->pk);                                   \
  } while (0)

#define paillier_public_key_free(public_key)                    \
  do {                                                          \
    bn_free((public_key)->pk);                                  \
    free(public_key);                                           \
    public_key = NULL;                                          \
  } while (0)

typedef struct {
  paillier_public_key_t paillier_pk;
  paillier_secret_key_t paillier_sk;
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
    paillier_public_key_new((keys)->paillier_pk);   \
    paillier_secret_key_new((keys)->paillier_sk);   \
    ec_public_key_new((keys)->ec_pk);               \
    ec_secret_key_new((keys)->ec_sk);               \
  } while (0)

#define keys_free(keys)                             \
  do {                                              \
    paillier_public_key_free((keys)->paillier_pk);  \
    paillier_secret_key_free((keys)->paillier_sk);  \
    ec_public_key_free((keys)->ec_pk);              \
    ec_secret_key_free((keys)->ec_sk);              \
    free(keys);                                     \
    keys = NULL;                                    \
  } while (0)

#endif // TRILERO_SCHNORR_INCLUDE_TYPES