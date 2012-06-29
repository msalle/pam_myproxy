#include <stdio.h>
#include <unistd.h> /* For getpass */
#include <string.h> /* For strdup */

#include <openssl/bio.h>

#include "pam_myproxy.h"
#include "myproxy_client.h"

/**
 * Parses the given error code and prints a suitable error message
 * \return 0 on success, 1 on general error, 2 on authentication error
 */
int parse_error_code(int rc, char *errstr,
		     cred_t *cred, pam_myproxy_opts_t *opts)    {
    /* Default return code: general error */
    int prc=1;

    switch(rc)	{
	case PAM_MYPROXY_SUCCESS:
	    prc=0;
	    break;
	case PAM_MYPROXY_INVALID_USERNAME:
	    fprintf(stderr,"Invalid username %s\n", cred->username);
	    prc=2;
	    break;
	case PAM_MYPROXY_INVALID_PASSWORD:
	    fprintf(stderr,"Invalid password\n");
	    prc=2;
	    break;
	case PAM_MYPROXY_CERT_EXPIRED:
	    fprintf(stderr,"Certificate expired\n");
	    prc=2;
	    break;
	case PAM_MYPROXY_OUT_OF_MEM:
	    fprintf(stderr,"Out of memory while retrieving proxy\n");
	    break;
	case PAM_MYPROXY_INVAL:
	    fprintf(stderr,"Invalid input value configured\n");
	    break;
	case PAM_MYPROXY_BUF_TOO_SMALL:
	    fprintf(stderr,
		    "Buffer too small when forming myproxy request\n");
	    break;
	case PAM_MYPROXY_BIO_WRITE_ERR:
	    fprintf(stderr,"Error writing to bio\n");
	    break;
	case PAM_MYPROXY_BIO_READ_ERR:
	    fprintf(stderr,"Error reading from bio\n");
	    break;
	case PAM_MYPROXY_RESPONSE_ERR:
	    fprintf(stderr,
		    "Unexpected answer from myproxy server: %s\n",
		    errstr ? errstr : "");
	    break;
	case PAM_MYPROXY_CSR_ERR:
	    fprintf(stderr,
		    "Error creating Certificate Signing Request\n");
	    break;
	case PAM_MYPROXY_HOST_UNSET:
	    fprintf(stderr,"Myproxy server is unset\n");
	    break;
	case PAM_MYPROXY_CTX_ERR:
	    fprintf(stderr,"Error setting up SSL CTX\n");
	    break;
	case PAM_MYPROXY_SSL_ERR:
	    fprintf(stderr,"Error setting up SSL (pre-connect)\n");
	    break;
	case PAM_MYPROXY_CONNECT_ERR:
	    fprintf(stderr,
		    "Error connecting to myproxy server %s:%d\n",
		    opts->endpoint.host,opts->endpoint.port);
	    break;
	default:
	    fprintf(stderr,"Unknown error in pam myproxy\n");
	    break;
    }
    
    /* Free the errstr */
    if (errstr)	{
	free(errstr);
	errstr=NULL;
    }

    return prc;
}


/**
 * Example myproxy client using the functions from myproxy_client
 */
int main(int argc, char *argv[])    {
    cred_t cred={NULL,NULL,NULL,NULL,NULL};
    pam_myproxy_opts_t opts;
    int rc=0,prc;
    BIO *bio=NULL;
    char *errstr=NULL;

    if (argc<2)	{
	fprintf(stderr,"Usage: %s <dn> [conffile]\n",argv[0]);
	return 1;
    }

    /* Initialize opts */
    _pam_myproxy_config_init(&opts);

    /* Set conffile */
    opts.conffile=(argv[2] ? strdup(argv[2]) : strdup(PAM_MYPROXY_CONF));
    if (opts.conffile==NULL)	{
	fprintf(stderr,"Out of memory\n");
	return 1;
    }

    /* Parse config file */
    switch (_pam_myproxy_parse_config(&opts)) {
	case 0:
	    break;
	case -1:
	    fprintf(stderr,"Cannot read config file\n");
	    return 1;
	case -2:
	    fprintf(stderr,"Permissions on config file are wrong\n");
	    return 1;
	case -3:
	    fprintf(stderr,"Out of memory while parsing config file\n");
	    return 1;
	default:
	    fprintf(stderr,"Unknown error while parsing config file\n");
	    return 1;
    }
   
    /* Set user credentials */
    cred.username=argv[1];
    cred.password=getpass("Enter myproxy password: ");
    cred.privkey=NULL;
    cred.chain=NULL;

    prc=1; /* default exit code 1 */
    /* Setup connection */
    rc=_myproxy_connect_ssl(&bio, &opts.endpoint, &opts.certinfo);
    if ( rc==PAM_MYPROXY_SUCCESS )  {
	/* Try to obtain credentials */
	rc=_myproxy(bio, &cred, opts.keysize, opts.lifetime, &errstr);

	/* Close connection */
	_myproxy_close_ssl(&bio);
    }

    /* Cleanup password */
    _myproxy_free_password(&cred);

    /* Parse error code */
    prc=parse_error_code(rc, errstr, &cred,&opts);

    /* Write proxy when so far successful */
    if ( rc==PAM_MYPROXY_SUCCESS )  {
	if (_myproxy_write_proxy(opts.proxyfmt,&cred))	{
	    fprintf(stderr,"Failed to write %s\n",
		    cred.proxyfile ? cred.proxyfile : "(null)");
	    prc=1;
	} else {
	    printf("Proxy left in %s\n",cred.proxyfile);
	    prc=0;
	}
    }

    /* Cleanup opts */
    _pam_myproxy_config_free(&opts);

    /* Free credentials */
    _myproxy_free_cred(&cred);

    return prc;
}


