#include <openssl/bio.h>

#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:@STRENGTH"
#define MAXCHAINDEPTH 99

typedef struct {
    char *CAfile;
    char *CApath;
    char *clientcert;
    char *clientkey;
} certinfo_t;

int _getcsr(X509_REQ **req, EVP_PKEY **pkeyp, int bits, const char *dn);

BIO *_connect_ssl(const char *host, int port, certinfo_t *certinfo);

int _myproxy_init(BIO *sbio, const char *user, const char *pass, int lifetime);

int _myproxy_getcerts(BIO *sbio, X509_REQ *req, STACK_OF(X509) **chain);

int _write_proxy(const char *filename, EVP_PKEY *pkey, STACK_OF(X509) *chain);

void _free_chain_key(X509_REQ **req, EVP_PKEY **pkey, STACK_OF(X509) **chain);

void _free_bio(BIO **sbio);
