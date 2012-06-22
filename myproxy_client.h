#ifndef _MYPRROXY_CLIENT_H
#define _MYPRROXY_CLIENT_H

#include <openssl/bio.h>

/************************************************************************/
/* TYPEDEFS AND DEFINES                                                 */
/************************************************************************/

/* SSL_CTX options: verification depth and cipher list */
#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:@STRENGTH"
#define MAXCHAINDEPTH 99

/**
 * Struct used for setting the openssl certificate input files and directories
 */
typedef struct {
    char *capath;	    /* OpenSSL CApath */
    char *cafile;	    /* OpenSSL CAfile */
    char *clientcert;	    /* client-side cert (e.g. hostcert) */
    char *clientkey;	    /* client-side key */
} certinfo_t;

/**
 * MyProxy server endpoint: host and port
 */
typedef struct {
    char *host;
    int port;
} endpoint_t;

/**
 * User input and output credentials.
 */
typedef struct {
    char *proxyfile;	    /* output proxyfile */
    const char *username;   /* MyProxy username (DN) */
    char *password;	    /* MyProxy password */
    EVP_PKEY *privkey;	    /* private key */
    STACK_OF(X509) *chain;  /* full proxy chain */
} cred_t;

/**
 * Error codes for MyProxy interaction problems
 */
typedef enum	{
    PAM_MYPROXY_SUCCESS		    = 0,
    PAM_MYPROXY_OUT_OF_MEM	    = 1,
    PAM_MYPROXY_INVAL		    = 2,
    PAM_MYPROXY_BUF_TOO_SMALL	    = 3,
    PAM_MYPROXY_BIO_WRITE_ERR	    = 4,
    PAM_MYPROXY_BIO_READ_ERR	    = 5,
    PAM_MYPROXY_INVALID_USERNAME    = 6,
    PAM_MYPROXY_INVALID_PASSWORD    = 7,
    PAM_MYPROXY_CERT_EXPIRED	    = 8,
    PAM_MYPROXY_RESPONSE_ERR	    = 9,
    PAM_MYPROXY_CSR_ERR		    = 10,
    PAM_MYPROXY_HOST_UNSET	    = 11,
    PAM_MYPROXY_CTX_ERR		    = 12,
    PAM_MYPROXY_SSL_ERR		    = 13,
    PAM_MYPROXY_CONNECT_ERR	    = 14,
} myproxy_err_t;

/************************************************************************/
/* FUNCTION PROTOTYPES                                                  */
/************************************************************************/

/**
 * Opens a TCP+SSL connection to endpoint using information from cert
 * \param sbio upon success the opened SSL connection
 * \param endpoint (MyProxy) server endpoint
 * \param certinfo cafile, capath, client credentials.
 * \return PAM_MYPROXY_SUCCESS or error
 */
myproxy_err_t _myproxy_connect_ssl(BIO **sbio, endpoint_t *endpoint, certinfo_t *cert);

/**
 * Closes TCP and SSL connection
 * \param sbio connection
 */
void _myproxy_close_ssl(BIO **sbio);

/**
 * Does all interaction with the MyProxy server, via the open connection in
 * sbio. (1) Sends first a COMMAND=0 with username/password. (2) Creates a
 * keypair + CSR. (3) Sends request (with pubkey) and reads the response.
 * \param sbio connection to MyProxy server (see _myproxy_connect_ssl)
 * \param cred contain username and password, upon success also contains private
 * key and chain
 * \param bits keysize of private/public keypair
 * \param lifetime proxy lifetime
 * \param errstr when the MyProxy response is 1, is usually contains a
 * descriptive errorstring. This contains its first line.
 * \return PAM_MYPROXY_SUCCESS or error
 */
myproxy_err_t _myproxy(BIO *sbio, cred_t *cred, int bits, int lifetime,
		       char **errstr);

/**
 * Writes proxy in chain and private key as pemfile to file.
 * \param filename proxy filename template: %d is substitute for getuid(),
 * XXXXXX for a random string (see mkstemp() )
 * \param cred contains proxy chain and private key. Upon success it also
 * contains the actual proxyfilename
 * \return 0 on success, -1 on error
 */
int _myproxy_write_proxy(const char *filename, cred_t *cred);

/**
 * Cleans and free-s password inside credential structure. Password is
 * explicitly overwritten
 * \param cred credential structure
 */
void _myproxy_free_password(cred_t *cred);

/**
 * Cleans credential data, except for proxy filename. Password is explicitly
 * overwritten
 * \param cred credential structure
 */
void _myproxy_free_cred(cred_t *cred);

#endif
