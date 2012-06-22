#ifndef _PAM_MYPROXY_H
#define _PAM_MYPROXY_H

typedef struct {
    char *conffile;	    /* Name of config file */

    char *CApath;	    /* OpenSSL CApath */
    char *CAfile;	    /* OpenSSL CAfile */
    char *clientcert;	    /* client-side cert */
    char *clientkey;	    /* client-side key */

    char *fileformat;	    /* Format string for proxy file */

    char *myproxy_host;	    /* MyProxy hostname */
    int myproxy_port;	    /* MyProxy portnumber */

    int lifetime;	    /* proxy lifetime */
    int bits;		    /* key bits */
} myproxy_opts_t;

typedef struct {
    char *username;
    char *password;
    EVP_PKEY *privkey;
    STACK_OF(X509) *chain;
} cred_t;

#endif
