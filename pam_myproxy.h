#ifndef _PAM_MYPROXY_H
#define _PAM_MYPROXY_H

#include "myproxy_client.h"

/* Names used as 'module_data_name' to set data in pam_sm_authenticate */
#define DATA_PROXY_FILENAME	"X509_USER_PROXY"
#define DATA_PROXY_CHAIN	"PROXYCHAIN"
#define DATA_PROXY_KEY		"PROXYKEY"

/* Name of environment variable for the user */
#define PROXY_ENV_VAR	"X509_USER_PROXY"

/* MyProxy defaults */
#define DEF_PORT	7512			/* MyProxy server port */
#define DEF_LIFETIME    43200L			/* proxy lifetime */
#define DEF_KEYSIZE	2048			/* bits for key-pair */
#define DEF_FORMAT	"/tmp/x509up_XXXXXX"	/* formatstring for file */
#define DEF_WRITE	1			/* proxyfile or in mem */

/* Structure containing all the options for pam module */
typedef struct {
    char *conffile;	    /* Name of config file */

    certinfo_t certinfo;    /* CApath etc. */
    endpoint_t endpoint;    /* MyProxy server */

    char *proxyname;	    /* Format string for proxy file */
    int writeproxy;	    /* Whether to store in pam or in file */
    long lifetime;	    /* proxy lifetime */
    int keysize;	    /* key bits */
} pam_myproxy_opts_t;

/**
 * free()s all memory contained in opts structure
 * \param opts struct containing the configuration options
 */
void _pam_myproxy_config_free(pam_myproxy_opts_t *opts);

/**
 * Parses the config file in opts.conffile, and leaves the output in the
 * different opts fields
 * \param opts struct containing the configuration options
 * \return -1 I/O error
 *	   -2 permission error (of config file)
 *	   -3 memory error
 *	   0 success
 */
int _pam_myproxy_parse_config(pam_myproxy_opts_t *opts);

/**
 * Parses the commandline options (incl config if present), and leaves the
 * output in the different opts fields
 * \param argc pam argc
 * \param argv pam argv
 * \param opts struct containing the configuration options
 * \return -1 I/O error (from config file)
 *	   -2 permission error (of config file)
 *	   -3 memory error
 *	   >0 index+1 of wrong commandline option
 *	   0 success
 */
int _pam_myproxy_parse_cmdline(int argc, const char *argv[], 
			       pam_myproxy_opts_t *opts);
#endif
