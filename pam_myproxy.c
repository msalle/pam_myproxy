#include <security/pam_modules.h>

#include <security/pam_ext.h>	/* For pam_syslog */
#include <syslog.h>

#include <stdio.h>  /* NULL */
#include <string.h> /* strdup() */

#include <sys/types.h>	/* stat() */
#include <sys/stat.h>	/* stat() */
#include <unistd.h>	/* stat() and unlink() */ 

#include <openssl/x509v3.h>    /* EVP_PKEY_free() X509_free etc. */

#include <errno.h>

#include "pam_myproxy.h"

/* This PAM module provides 'auth', 'account' and 'session'
 * pam_sm_authenticate() or pam_sm_acct_mgmt() authenticates at a myproxy
 * server, downloads a proxy and stores it either in mem or as pemfile on disk.
 * pam_sm_setcred() either sets the user environment variable to the specified
 * file or removes the pemfile from disk (only when applicable)
 * pam_sm_open_session() acts as pam_sm_setcred() when establishing,
 * pam_sm_close_session() acts as pam_sm_setcred() when deleting.
 */

/************************************************************************/
/* DEFINES                                                              */
/************************************************************************/

/* authentication part: need pam_sm_authenticate and pam_sm_setcred */
#define PAM_SM_AUTH

/* account part: need pam_sm_account */
#define PAM_SM_ACCOUNT

/* session part: need pam_sm_open_session and pam_sm_close_session */
#define PAM_SM_SESSION


/** Prompt when obtaining password */
#define PAM_MYPROXY_PW_PROMPT	"MyProxy password: "

/** Prompt when obtaining DN */
#define PAM_MYPROXY_USER_PROMPT	"Enter DN: "

/************************************************************************/
/* PRIVATE FUNCTIONS                                                    */
/************************************************************************/

/**
 * Cleanup function for string data, needed by pam_set_data
 * \param pamh pam handle
 * \param data string data
 * \param error_status see pam_set_data
 */
static void _pam_string_cleanup(pam_handle_t *pamh, void *data,
				   int error_status)	{
    if (data)
	free(data);
}

/**
 * Cleanup function for EVP_PKEY data, needed by pam_set_data
 * \param pamh pam handle
 * \param data string data
 * \param error_status see pam_set_data
 */
static void _pam_privkey_cleanup(pam_handle_t *pamh, void *data,
				   int error_status)	{
    if (data)
	EVP_PKEY_free((EVP_PKEY*)data);
}

/**
 * Cleanup function for STACK_OF(X509) data, needed by pam_set_data
 * \param pamh pam handle
 * \param data string data
 * \param error_status see pam_set_data
 */
static void _pam_chain_cleanup(pam_handle_t *pamh, void *data,
			   int error_status)	{
    if (data)
	sk_X509_pop_free((STACK_OF(X509) *)data, X509_free);
}

/**
 * Input credential function.
 *
 * Obtains MyProxy password from the user via the application provided conv
 * function
 * \param pamh pam handle
 * \param flags pam_sm_authenticate flags
 * \param password will contain the password or NULL on failure
 * \return MYPAM_SUCCESS upon succes, or suitable mypam_err_t error.
 */
static mypam_err_t _get_password(pam_handle_t *pamh, int flags, char **password)    {
    char *pass=NULL;
    int rc=PAM_SUCCESS;
    const struct pam_conv *conv;
    struct pam_message msg[1];
    const struct pam_message *pmsg[1];
    struct pam_response *resp=NULL;

    pmsg[0]=&msg[0];
    msg[0].msg_style=PAM_PROMPT_ECHO_OFF;
    msg[0].msg=PAM_MYPROXY_PW_PROMPT;
    
    /* Get conv structure */
    rc = pam_get_item(pamh,PAM_CONV,(const void**)&conv);
    /* Run conv when we have a conv struct */
    if (rc==PAM_SUCCESS && conv) {
	rc=conv->conv(1, pmsg, &resp, conv->appdata_ptr);
	/* Mem error */
	if (rc==PAM_BUF_ERR)	{
	    pam_syslog(pamh, LOG_ERR, "Converse function failed %d: %s",
		       rc, pam_strerror(pamh, rc));
	    return MYPAM_ERROR;
	}
	/* Other error */
	if (rc!=PAM_SUCCESS) {
	    pam_syslog(pamh, LOG_ERR, "Converse function failed %d: %s",
		       rc, pam_strerror(pamh, rc));
	    return MYPAM_AUTH_ERR;
	}
    } else {
	/* PAM_CONV unset or conv==NULL */
	pam_syslog(pamh, LOG_ERR, "Failed to get pam_conv");
	return MYPAM_ERROR;
    }

    /* If response is obtained */
    if (resp==NULL)
	return MYPAM_AUTH_ERR;

    /* Response, but empty */
    if (resp[0].resp == NULL) {
	pam_syslog(pamh, LOG_DEBUG,
	    "pam_sm_authenticate: NULL authtok given");
	if (flags & PAM_DISALLOW_NULL_AUTHTOK) {
	    free(resp);
	    return MYPAM_AUTH_ERR;
	}
	/* If pass == NULL make it empty string */
	if ( (pass=strdup(""))==NULL) /* Out-of-mem */
	    return MYPAM_ERROR;
    } else {
	pass=resp[0].resp;/* remember this! */
	resp[0].resp = NULL;
    }

    /* Can free the resp (but not the actual content) */
    free(resp);
    
    /* this *MUST* be free()'d by this module */
    *password = pass;

    return MYPAM_SUCCESS;
}

/**
 * Stores proxy on disk in a file with name cred->filename, which is constructed
 * from opts->proxyfmt; the name is stored in pam data with name
 * DATA_PROXY_FILENAME.
 * \param pamh pam handle
 * \param cred credentials, including the name of the proxy file, contents will
 * be cleared unless successfully stored in memory
 * \return MYPAM_SUCCESS upon success or a suitable mypam_err_t error.
 */
static mypam_err_t _store_proxyfile(pam_handle_t *pamh, const char *filename,
			    cred_t *cred) {
    int rc;
    char *proxy_buf=NULL;

    /* Use filebased: write to file, store filename as a pam data element
     * for other modules and put in environment. Then free chain and private
     * key */
    /* Write proxy */
    if ( (rc=_myproxy_write_proxy(filename, cred))!=0)   {
	if (cred->proxyfile)
	    pam_syslog(pamh, LOG_WARNING,
		   "Failed to write proxy %s\n",
		   cred->proxyfile);
	else
	    pam_syslog(pamh, LOG_WARNING,
		   "Failed to write proxy\n");
	return MYPAM_ERROR;
    }

    /* Normally, proxyfile shouldn't be empty, check in any case */
    if (cred->proxyfile==NULL)
	return MYPAM_ERROR;

    /* Duplicate buffer */
    if ( (proxy_buf=strdup(cred->proxyfile))==NULL ) {
	pam_syslog(pamh,LOG_ERR,"Out of memory\n");
	return MYPAM_ERROR;
    }

    /* Store in pam data */
    if ( (rc=pam_set_data(pamh, PAM_PROXY_FILENAME, proxy_buf,
			  _pam_string_cleanup))!=PAM_SUCCESS)    {
	pam_syslog(pamh,LOG_ERR,"Cannot store proxyname as pam data: %s\n",
	    pam_strerror(pamh,rc));
	free(proxy_buf);
	return MYPAM_ERROR;
    }

    return MYPAM_SUCCESS;
}

/**
 * Stores proxy in memory as ENV_PKEY and STACK_OF(X509) in pam data with names
 * DATA_PROXY_KEY and DATA_PROXY_CHAIN.
 * \param pamh pam handle
 * \param cred credentials, including the name of the proxy file, contents will
 * be cleared unless successfully stored in memory
 * \return MYPAM_SUCCESS upon success or a suitable mypam_err_t error.
 */
static mypam_err_t _store_proxykeychain(pam_handle_t *pamh, cred_t *cred) {
    int rc;

    /* Memory based: store in pam items "myproxychain" and "myproxykey",
     * store chain first */
    if ( (rc=pam_set_data(pamh, PAM_PROXY_CHAIN,
			  (void*)cred->chain,
			  _pam_chain_cleanup))!=PAM_SUCCESS)    {
	/* Chain failed */
	pam_syslog(pamh, LOG_ERR,
	    "Failed to pam_set_data proxy chain: %s\n",
	    pam_strerror(pamh,rc));
	return MYPAM_ERROR;
    } else if ( (rc=pam_set_data(pamh, PAM_PROXY_KEY,
			  (void*)cred->privkey,
			  _pam_privkey_cleanup))!=PAM_SUCCESS)    {
	/* Key failed */
	pam_syslog(pamh, LOG_ERR,
	    "Failed to pam_set_data private key: %s\n",
	    pam_strerror(pamh,rc));
	return MYPAM_ERROR;
    }

    return MYPAM_SUCCESS;
}

/**
 * Output-credential from pam-data function.
 *
 * Retrieves credential data (proxyfile) from the pam data
 * \param pamh pam handle
 * \param cred credential structure
 * \return MYPAM_SUCCESS upon success or a suitable mypam_err_t error.
 */
static mypam_err_t _retrieve_proxyfile(pam_handle_t *pamh, cred_t *cred)    {
    int rc;
    const char *proxy_buf;
    
    /* proxy */
    /* Obtain from data */
    if ( (rc=pam_get_data(pamh,PAM_PROXY_FILENAME,(const void **)&proxy_buf))
		    !=PAM_SUCCESS) {
	    pam_syslog(pamh,LOG_ERR,"Cannot obtain proxy data: %s\n",
		    pam_strerror(pamh,rc));
	    return MYPAM_DATA_MISSING;
    }

    /* proxy_buf can be set but empty: no error, but don't strdup! */
    if (proxy_buf==NULL)    {
	cred->proxyfile=NULL;
	return MYPAM_SUCCESS;
    }

    /* Put in credentials */
    if ( (cred->proxyfile=strdup(proxy_buf))==NULL )	{
	pam_syslog(pamh,LOG_ERR,"Out of memory\n");
	return MYPAM_DATA_MISSING;
    }

    return MYPAM_SUCCESS;
}

/**
 * Output-credential pam-data to environment function.
 *
 * Stores the proxy filename pam data into the internal pam environment for
 * recovery by the _restore_pam_data function.
 * \param pamh pam handle
 * \return MYPAM_SUCCESS upon success or a suitable mypam_err_t error.
 */
static mypam_err_t _store_pam_data(pam_handle_t *pamh)	{
    const char *proxy_buf;
    char *buffer=NULL;
    int rc,len;

    /* proxy */
    rc=pam_get_data(pamh, PAM_PROXY_FILENAME, (const void **)&proxy_buf);
    if (rc==PAM_SUCCESS)    { /* data found */
	len=1+snprintf(buffer,0,"%s=%s",PAM_PROXY_FILENAME,proxy_buf);
	if ( (buffer=malloc(len))==NULL )
	    return MYPAM_ERROR;
	snprintf(buffer,len,"%s=%s",PAM_PROXY_FILENAME,proxy_buf);
	rc=pam_putenv(pamh,buffer);
	free(buffer);
	if (rc!=PAM_SUCCESS)
	    return MYPAM_ERROR;
    } else if (rc==PAM_NO_MODULE_DATA)	{ /* clear env variable */
	if (pam_putenv(pamh,PAM_PROXY_FILENAME)!=PAM_SUCCESS)
	    return MYPAM_ERROR;
    } else /* Error */
	return MYPAM_ERROR;
    
    return MYPAM_SUCCESS;
}

/**
 * Output-credential pam-data from environment function.
 *
 * Restores proxy filename, uid and gid from the internal environment, and
 * stores it in the pam data. \See _store_pam_data
 * \param pamh pam handle
 * \return MYPAM_SUCCESS upon success or a suitable mypam_err_t error.
 */
static mypam_err_t _restore_pam_data(pam_handle_t *pamh)	{
    const char *envval=NULL;
    char *proxy_buf=NULL;
    int rc;

    /* proxy */
    if ( (envval=pam_getenv(pamh, PAM_PROXY_FILENAME)) != NULL )    {
	/* Copy for data */
	if ( (proxy_buf=strdup(envval))==NULL)	{
	    pam_syslog(pamh,LOG_ERR,"Out of memory\n");
	    return MYPAM_ERROR;
	}
	/* Store in data */
	if ( (rc=pam_set_data(pamh,PAM_PROXY_FILENAME,
			  proxy_buf,_pam_string_cleanup))!=PAM_SUCCESS )    {
	    pam_syslog(pamh,LOG_ERR,"Cannot put %s in pam data: %s\n",
		proxy_buf,pam_strerror(pamh,rc));
	    free(proxy_buf);
	    return MYPAM_ERROR;
	}
	/* Remove from env */
	if ( (rc=pam_putenv(pamh,PAM_PROXY_FILENAME))!=PAM_SUCCESS )  {
	    pam_syslog(pamh,LOG_ERR,"Cannot remove %s from pam env: %s\n",
		PAM_PROXY_FILENAME,pam_strerror(pamh,rc));
	    return MYPAM_ERROR;
	}
    }

    return MYPAM_SUCCESS;
}

/**
 * Proxy removal
 *
 * Remove proxy, update pam data and environment
 * \param pamh  pam handle
 * \param cred credentials incl. target uid and gid and proxy filename
 * \return MYPAM_SUCCESS on success or a suitable mypam_err_t error
 */
static mypam_err_t _remove_proxy(pam_handle_t *pamh, cred_t *cred)  {
    int rc,myerrno;
    mypam_err_t prc;
    const char *proxy_env;
    struct stat buf;
  
    /* Remove file only if a name has been set */
    if (cred->proxyfile==NULL)
	return MYPAM_SUCCESS;
   
    /* Try to stat it */
    if (stat(cred->proxyfile,&buf)==-1) { /* stat failed */
	myerrno=errno;
	if (myerrno==ENOENT)
	    /* file does not exist: ok, but remove pam data as it no longer
	     * valid */
	    prc=MYPAM_SUCCESS;
	else	{ /* unknown error */
	    pam_syslog(pamh,LOG_ERR,"Cannot stat proxy %s: %s\n",
		cred->proxyfile,strerror(myerrno));
	    prc=MYPAM_ERROR;
	}
    } else if (unlink(cred->proxyfile)==0)   {
	pam_syslog(pamh,LOG_DEBUG,"Removed proxy %s\n",cred->proxyfile);
	prc=MYPAM_SUCCESS;
    } else  { /* unlink() failed */
	myerrno=errno;
	pam_syslog(pamh,LOG_ERR,"Cannot remove proxy %s: %s\n",
		cred->proxyfile,strerror(myerrno));
	prc=MYPAM_ERROR;
    }

    /* Now unset the data entry, warn if fails, don't set the prc */
    if ( (rc=pam_set_data(pamh, PAM_PROXY_FILENAME, NULL,
		    _pam_string_cleanup)) != PAM_SUCCESS){
	pam_syslog(pamh,LOG_WARNING,"Cannot unset proxy data: %s\n",
		pam_strerror(pamh, rc));
    }

    /* Check if the PROXY_ENV_VAR points to the same file, if so unset it
     * too. Warn if it fails, don't set the prc */
    if ( (proxy_env=pam_getenv(pamh, PROXY_ENV_VAR))!=NULL &&
	 strcmp(proxy_env,cred->proxyfile)==0 &&
	 (rc=pam_putenv(pamh, PROXY_ENV_VAR)) != PAM_SUCCESS )
	pam_syslog(pamh,LOG_WARNING,"Cannot unset variable %s: %s\n",
		   PROXY_ENV_VAR,pam_strerror(pamh,rc));

    return prc;
}

/**
 * cmdline option parsing log function
 *
 * Parses return value from _pam_myproxy_parse_cmdline() and logs corresponding
 * error message
 * \param pamh pam handle
 * \param rc return code from _pam_myproxy_parse_cmdline
 * \param argv pam_sm_authenticate argv
 * \param opts configure options
 */
static void _parse_opts_cmdline_returncode(pam_handle_t *pamh,
					   int rc, const char *argv[],
					   pam_myproxy_opts_t *opts)	{
    switch(rc)  {
	case -1:
	    pam_syslog(pamh, LOG_ERR,
		"I/O Error while parsing config file (%s)\n",opts->conffile);
	    break;
	case -2:
	    pam_syslog(pamh, LOG_ERR,
		"Permission of config file are wrong (%s)\n",opts->conffile);
	    break;
	case -3:
	    pam_syslog(pamh, LOG_ERR,
		"Out of memory while parsing options\n");
	    break;
	default:
	    pam_syslog(pamh, LOG_ERR,
		"Syntax error around option %s\n",argv[rc-1]);
	    break;
    }
}

/**
 * MyProxy interaction parsing function
 *
 * Parses return value from _myproxy() and logs corresponding error message. A
 * corresponding pam_sm_authenticate return value is returned.
 * \param pamh pam handle
 * \param rc return code from _pam_myproxy_parse_cmdline
 * \param errstr error string from MyProxy response, will be freed 
 * \param cred credentials
 * \param opts configure options
 * \return MYPAM_SUCCESS upon succes, or suitable mypam_err_t error.
 */
static mypam_err_t _parse_myproxy_returncode(pam_handle_t *pamh,
				     myproxy_err_t rc, char *errstr,
				     cred_t *cred, pam_myproxy_opts_t *opts) {
    /* Default pam return code: MYPAM_ERROR */
    int prc=MYPAM_ERROR;

    switch(rc)	{
	case PAM_MYPROXY_SUCCESS:
	    prc=MYPAM_SUCCESS;
	    break;
	case PAM_MYPROXY_INVALID_USERNAME:
	    pam_syslog(pamh, LOG_INFO,"Invalid username %s\n", cred->username);
	    prc=MYPAM_USER_UNKNOWN;
	    break;
	case PAM_MYPROXY_INVALID_PASSWORD:
	    pam_syslog(pamh, LOG_INFO,"Invalid password\n");
	    prc=MYPAM_AUTH_ERR;
	    break;
	case PAM_MYPROXY_CERT_EXPIRED:
	    pam_syslog(pamh, LOG_INFO,"Certificate expired\n");
	    prc=MYPAM_AUTH_ERR;
	    break;
	case PAM_MYPROXY_OUT_OF_MEM:
	    pam_syslog(pamh, LOG_ERR,"Out of memory while retrieving proxy\n");
	    break;
	case PAM_MYPROXY_INVAL:
	    pam_syslog(pamh, LOG_ERR,"Invalid input value configured\n");
	    break;
	case PAM_MYPROXY_BUF_TOO_SMALL:
	    pam_syslog(pamh, LOG_ERR,
		    "Buffer too small when forming myproxy request\n");
	    break;
	case PAM_MYPROXY_BIO_WRITE_ERR:
	    pam_syslog(pamh, LOG_ERR,"Error writing to bio\n");
	    break;
	case PAM_MYPROXY_BIO_READ_ERR:
	    pam_syslog(pamh, LOG_ERR,"Error reading from bio\n");
	    break;
	case PAM_MYPROXY_RESPONSE_ERR:
	    pam_syslog(pamh, LOG_ERR,
		    "Unexpected answer from myproxy server: %s\n",
		    errstr ? errstr : "");
	    break;
	case PAM_MYPROXY_CSR_ERR:
	    pam_syslog(pamh, LOG_ERR,
		    "Error creating Certificate Signing Request\n");
	    break;
	case PAM_MYPROXY_HOST_UNSET:
	    pam_syslog(pamh, LOG_ERR,"Myproxy server is unset\n");
	    break;
	case PAM_MYPROXY_CTX_ERR:
	    pam_syslog(pamh, LOG_ERR,"Error setting up SSL CTX\n");
	    break;
	case PAM_MYPROXY_SSL_ERR:
	    pam_syslog(pamh, LOG_ERR,"Error setting up SSL (pre-connect)\n");
	    break;
	case PAM_MYPROXY_CONNECT_ERR:
	    pam_syslog(pamh, LOG_ERR,
		    "Error connecting to myproxy server %s:%d\n",
		    opts->endpoint.host,opts->endpoint.port);
	    break;
	default:
	    pam_syslog(pamh, LOG_ERR,"Unknown error in pam myproxy\n");
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
 * authentication/authorization function
 *
 * Implements authentication/authorization for obtaining a MyProxy delegation
 * via username/password. It stores the credentials either in a proxy file of
 * which the name will be stored in the pam data or stores it only in memory in
 * a chain/key in pam data. Used by either pam_sm_authenticate or
 * pam_sm_acct_mgmt
 * \param see pam_sm_authenticate or pam_sm_acct_mgmt
 * \return MYPAM_SUCCESS on success or a suitable mypam_err_t error.
 */
static mypam_err_t _pam_auth(pam_handle_t *pamh, int flags,
			     int argc, const char **argv) {
    /* initialize cred structure */
    cred_t cred={NULL,NULL,NULL,NULL,NULL};
    pam_myproxy_opts_t opts;
    int rc;
    myproxy_err_t mrc;
    mypam_err_t prc;
    BIO *bio=NULL;
    char *errstr=NULL;

    /* Initialize opts */
    _pam_myproxy_config_init(&opts);

    /* Get commandline (and perhaps config file) options */
    if ( (rc=_pam_myproxy_parse_cmdline(argc,argv,&opts)) != 0)	{
	_parse_opts_cmdline_returncode(pamh,rc,argv,&opts);
	_pam_myproxy_config_free(&opts);
	return MYPAM_ERROR;
    }
    
    /* Get username */
    if (pam_get_user(pamh, &(cred.username), PAM_MYPROXY_USER_PROMPT)
	    != PAM_SUCCESS)  {
	pam_syslog(pamh, LOG_WARNING,
	    "user is unset, cannot continue.\n");
	_pam_myproxy_config_free(&opts);
	return MYPAM_DATA_MISSING;
    }

    /* Get myproxy password: do not put this in PAM_AUTHTOK, it will not be of
     * use for others */
    if ( (prc=_get_password(pamh, flags, &(cred.password))) != MYPAM_SUCCESS)  {
	_pam_myproxy_config_free(&opts);
	return prc;
    }

    /* Setup SSL connection to myproxy server */
    mrc=_myproxy_connect_ssl(&bio, &opts.endpoint, &opts.certinfo);
    if ( mrc==PAM_MYPROXY_SUCCESS )  {
	/* Try to obtain credentials */
	mrc=_myproxy(bio, &cred, opts.keysize, opts.lifetime,&errstr);

	/* Close connection */
	_myproxy_close_ssl(&bio);
    }
    
    /* Parse return code (this also free-s clears the errstr) */
    if ( (prc=_parse_myproxy_returncode(pamh, mrc, errstr, &cred, &opts))
	    != MYPAM_SUCCESS)
	goto _auth_cleanup;

    /* Write proxy when needed: when writing, will free chain and private key */
    if (opts.writeproxy)    {
	/* Store proxy in file and in pam data */
	if ( (prc=_store_proxyfile(pamh,opts.proxyfmt,&cred)) != MYPAM_SUCCESS )
	    goto _auth_cleanup;
	
	/* Optionally store pam data in internal env */
	if (opts.useenv)
	    prc=_store_pam_data(pamh);
    } else {
	/* Store proxy key and chain in pam data */
	prc=_store_proxykeychain(pamh, &cred);
    }

_auth_cleanup:
    /* We're done with the credentials as we have it on disk now */
    if (opts.writeproxy || prc!=PAM_SUCCESS)
	_myproxy_free_cred(&cred);
    else
	/* Cleanup only password */
	_myproxy_free_password(&cred);

    /* Cleanup opts */
    _pam_myproxy_config_free(&opts);

    return prc;
}

/**
 * Credential setting function
 *
 * Implements 
 * Used by either pam_sm_setcred or pam_sm_open_session
 * \param see pam_sm_setcred or pam_sm_open_session
 * \return MYPAM_SUCCESS on success or a suitable mypam_err_t error.
 */
static mypam_err_t _pam_establish_cred(pam_handle_t *pamh,
			       int argc, const char **argv) {
    pam_myproxy_opts_t opts;
    cred_t cred={NULL,NULL,NULL,NULL,NULL};
    int len,rc;
    char *buffer=NULL;
    mypam_err_t prc;

    /* Initialize opts */
    _pam_myproxy_config_init(&opts);

    /* Get commandline (and perhaps config file) options */
    if ( (rc=_pam_myproxy_parse_cmdline(argc,argv,&opts)) !=0 ) {
	_parse_opts_cmdline_returncode(pamh,rc,argv,&opts);
	prc=MYPAM_ERROR;
	goto _setcred_cleanup;
    }

    
    /* If we don't write the proxy, we don't need to do anything */
    if (!opts.writeproxy)   {
	prc=MYPAM_SUCCESS;
	goto _setcred_cleanup;
    }
    
    /* Is is present in the environment to be retrieved? */
    if (opts.useenv)	{
	if ( (prc=_restore_pam_data(pamh))!=MYPAM_SUCCESS)
	    goto _setcred_cleanup;
    }

    /* Get pam data */
    if ( (prc=_retrieve_proxyfile(pamh, &cred))!=MYPAM_SUCCESS)
	goto _setcred_cleanup;

    /* proxy is now present as data, now set it in the pam environment for the
     * user */
    len=2+strlen(PROXY_ENV_VAR)+strlen(cred.proxyfile);
    if ( (buffer=(char *)malloc(len))==NULL )	{
	pam_syslog(pamh,LOG_ERR,"Out of memory\n");
	prc=MYPAM_ERROR;
	goto _setcred_cleanup;
    }
    snprintf(buffer,len,"%s=%s",PROXY_ENV_VAR,cred.proxyfile);
    if ( (rc=pam_putenv(pamh, buffer))!=PAM_SUCCESS )   {
	pam_syslog(pamh,LOG_ERR,"Cannot set data for proxy %s: %s\n",
		cred.proxyfile,pam_strerror(pamh,rc));
	prc=MYPAM_ERROR;
	goto _setcred_cleanup;
    }

    prc=MYPAM_SUCCESS;

_setcred_cleanup:
    /* free temporary env buffer */
    free(buffer);

    /* free credential struct */
    _myproxy_free_cred(&cred);

    /* free config options stuct */
    _pam_myproxy_config_free(&opts);

    return prc;
}

/**
 * Credential removing function
 *
 * Implements 
 * Used by either pam_sm_setcred or pam_sm_close_session
 * \param see pam_sm_setcred or pam_sm_close_session
 * \return MYPAM_SUCCESS on success or a suitable mypam_err_t error.
 */
static mypam_err_t _pam_delete_cred(pam_handle_t *pamh,
			       int argc, const char **argv) {
    pam_myproxy_opts_t opts;
    cred_t cred={NULL,NULL,NULL,NULL,NULL};
    int rc;
    mypam_err_t prc;

    /* Initialize opts */
    _pam_myproxy_config_init(&opts);

    /* Get commandline (and perhaps config file) options */
    if ( (rc=_pam_myproxy_parse_cmdline(argc,argv,&opts)) !=0 ) {
	_parse_opts_cmdline_returncode(pamh,rc,argv,&opts);
	prc=MYPAM_ERROR;
	goto _delete_cred_cleanup;
    }
   
    /* If we don't write the proxy, we don't need to do anything */
    if (!opts.writeproxy)   {
	prc=MYPAM_SUCCESS;
	goto _delete_cred_cleanup;
    }
   
    /* Get pam data */
    if ( (prc=_retrieve_proxyfile(pamh,&cred))!=MYPAM_SUCCESS)
	goto _delete_cred_cleanup;

    /* data entry found (although could be empty) try to remove it. In any case
     * remove the data entry as it will no longer be valid */
    prc=_remove_proxy(pamh, &cred);

_delete_cred_cleanup:
    /* free credential struct */
    _myproxy_free_cred(&cred);

    /* Cleanup opts, we're done with them */
    _pam_myproxy_config_free(&opts);

    return prc;
}


/************************************************************************/
/* PUBLIC FUNCTIONS                                                     */
/************************************************************************/

/**
 * pam_sm_authenticate() function implementing the pam_authenticate function for
 * obtaining a MyProxy delegation via username/password (see _pam_auth()). It
 * stores the credentials either in a proxy file, or stores them only in memory
 * in a chain/key in pam data.
 * \param see pam_sm_authenticate
 * \return see pam_sm_authenticate
 */
PAM_EXTERN int 
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    mypam_err_t rc;

    rc=_pam_auth(pamh, flags, argc, argv);

    switch (rc) {
        case MYPAM_SUCCESS:
            return PAM_SUCCESS;
        case MYPAM_DATA_MISSING:
            return PAM_CRED_INSUFFICIENT;
        case MYPAM_USER_UNKNOWN:
            return PAM_USER_UNKNOWN;
        case MYPAM_AUTH_ERR:
            return PAM_AUTH_ERR;
        case MYPAM_ERROR:
        default:
            return PAM_AUTHINFO_UNAVAIL;
    }
    
    /* MYPAM_CRED_EXPIRED cannot be logically mapped */
}

/**
 * pam_sm_acct_mgmt() function implementing the pam_acct_mgmt function for
 * obtaining a MyProxy delegation via username/password (see _pam_auth()). It
 * stores the credentials either in a proxy file, or stores them only in memory
 * in a chain/key in pam data.
 * \param see pam_sm_authenticate
 * \return see pam_sm_authenticate
 */
PAM_EXTERN int 
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    mypam_err_t rc;

    rc=_pam_auth(pamh, flags, argc, argv);

    switch (rc) {
        case MYPAM_SUCCESS:
            return PAM_SUCCESS;
        case MYPAM_USER_UNKNOWN:
            return PAM_USER_UNKNOWN;
        case MYPAM_CRED_EXPIRED:
            return PAM_NEW_AUTHTOK_REQD;
        case MYPAM_AUTH_ERR:
            return PAM_AUTH_ERR;
        case MYPAM_ERROR:
        case MYPAM_DATA_MISSING:
        default:
            /* Linux pam_acct_mgmt does not have a general failure */
            return PAM_AUTH_ERR;
    }
}

/**
 * pam_sm_setcred() function implementing the pam_setcred function for obtaining
 * a MyProxy delegation via username/password. When using proxy file
 * (writeproxy=1), it either sets the target user env variable PROXY_ENV_VAR
 * (when flags indicates setting the credential) or it removes the file and
 * unsets the pam data DATA_PROXY_FILENAME and target user env variable
 * PROXY_ENV_VAR (when flags indicates deleting the credential). In the case of
 * setting, it retrieves the value from the internal pam env variable
 * PAM_MYPROXY_ENVVAR, which is unset afterwards.
 * \param see pam_sm_setcred
 * \return see pam_sm_setcred
 */
PAM_EXTERN int 
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    mypam_err_t rc;

    /* First handle credential removal */
    if ( flags & PAM_DELETE_CRED )
	rc=_pam_delete_cred(pamh, argc, argv);
    else
	rc=_pam_establish_cred(pamh, argc, argv);

    switch(rc)	{
	case MYPAM_SUCCESS:
	    return PAM_SUCCESS;
	case MYPAM_DATA_MISSING:
	    return PAM_CRED_UNAVAIL;
	case MYPAM_USER_UNKNOWN: /* Currently not used */
	    return PAM_USER_UNKNOWN;
	case MYPAM_CRED_EXPIRED: /* Currently not used */
	    return PAM_CRED_EXPIRED;
	case MYPAM_AUTH_ERR: /* Currently not used */ 
	case MYPAM_ERROR:
	default:
	    return PAM_CRED_ERR;
    }

}

/**
 * pam_sm_open_session() function implementing the pam_open_session function for
 * obtaining a MyProxy delegation via username/password (see
 * _pam_establish_cred()). When using files, it sets the proxy filename into the
 * user pam environment.
 * \param see pam_sm_open_session
 * \return see pam_sm_open_session
 */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    mypam_err_t rc;

    rc=_pam_establish_cred(pamh, argc, argv);

    switch(rc)  {
        case MYPAM_SUCCESS:
            return PAM_SUCCESS;
        case MYPAM_DATA_MISSING:
        case MYPAM_USER_UNKNOWN: /* Currently not used */
        case MYPAM_CRED_EXPIRED: /* Currently not used */
        case MYPAM_AUTH_ERR: /* Currently not used */ 
        case MYPAM_ERROR:
        default:
            return PAM_SESSION_ERR;
    }
}

/**
 * pam_sm_close_session() function implementing the pam_close_session function
 * for obtaining a MyProxy delegation via username/password (see
 * _pam_delete_cred()). When using files, it removes the proxy file and its
 * references in the pam data and pam environment.
 * \param see pam_sm_close_session
 * \return see pam_sm_close_session
 */
PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    mypam_err_t rc;

    rc=_pam_delete_cred(pamh, argc, argv);

    switch(rc)  {
        case MYPAM_SUCCESS:
            return PAM_SUCCESS;
        case MYPAM_DATA_MISSING:
        case MYPAM_USER_UNKNOWN: /* Currently not used */
        case MYPAM_CRED_EXPIRED: /* Currently not used */
        case MYPAM_AUTH_ERR: /* Currently not used */ 
        case MYPAM_ERROR:
        default:
            return PAM_SESSION_ERR;
    }
}
