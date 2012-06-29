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

/* This PAM module provides only 'auth':
 * pam_sm_authenticate() authenticates at a myproxy server, downloads a proxy
 * and stores it either in mem or as pemfile on disk.
 * pam_sm_setcred() either sets the user environment variable to the specified
 * file or removes the pemfile from disk (only when applicable)
 */

/************************************************************************/
/* DEFINES                                                              */
/************************************************************************/

/**
 * authentication part: need pam_sm_authenticate and pam_sm_setcred
 */
#define PAM_SM_AUTH

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
 * Obtains MyProxy password from the user via the application provided conv
 * function
 * \param pamh pam handle
 * \param flags pam_sm_authenticate flags
 * \param password will contain the password or NULL on failure
 * \return error corresponding to pam_sm_authenticate return values
 */
static int _get_password(pam_handle_t *pamh, int flags, char **password)    {
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
	    return PAM_AUTHINFO_UNAVAIL;
	}
	/* Other error */
	if (rc!=PAM_SUCCESS) {
	    pam_syslog(pamh, LOG_ERR, "Converse function failed %d: %s",
		       rc, pam_strerror(pamh, rc));
	    return PAM_AUTH_ERR;
	}
    } else {
	/* PAM_CONV unset or conv==NULL */
	pam_syslog(pamh, LOG_ERR, "Failed to get pam_conv");
	return PAM_AUTHINFO_UNAVAIL;
    }

    /* If response is obtained */
    if (resp==NULL)
	return PAM_AUTH_ERR;

    /* Response, but empty */
    if (resp[0].resp == NULL) {
	pam_syslog(pamh, LOG_DEBUG,
	    "pam_sm_authenticate: NULL authtok given");
	if (flags & PAM_DISALLOW_NULL_AUTHTOK) {
	    free(resp);
	    return PAM_AUTH_ERR;
	}
	/* If pass == NULL make it empty string */
	if ( (pass=strdup(""))==NULL) /* Out-of-mem */
	    return PAM_AUTHINFO_UNAVAIL;
    } else {
	pass=resp[0].resp;/* remember this! */
	resp[0].resp = NULL;
    }

    /* Can free the resp (but not the actual content) */
    free(resp);
    
    /* this *MUST* be free()'d by this module */
    *password = pass;

    return PAM_SUCCESS;
}

/**
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
 * Parses return value from _myproxy() and logs corresponding error message. A
 * corresponding pam_sm_authenticate return value is returned.
 * \param pamh pam handle
 * \param rc return code from _pam_myproxy_parse_cmdline
 * \param errstr error string from MyProxy response, will be freed 
 * \param cred credentials
 * \param opts configure options
 * \return pam_sm_authenticate return value corresponding to _myproxy error
 */
static int _parse_myproxy_returncode(pam_handle_t *pamh,
				     int rc, char *errstr,
				     cred_t *cred, pam_myproxy_opts_t *opts) {
    /* Default pam return code: PAM_AUTHINFO_UNAVAIL */
    int prc=PAM_AUTHINFO_UNAVAIL;

    switch(rc)	{
	case PAM_MYPROXY_SUCCESS:
	    prc=PAM_SUCCESS;
	    break;
	case PAM_MYPROXY_INVALID_USERNAME:
	    pam_syslog(pamh, LOG_INFO,"Invalid username %s\n", cred->username);
	    prc=PAM_USER_UNKNOWN;
	    break;
	case PAM_MYPROXY_INVALID_PASSWORD:
	    pam_syslog(pamh, LOG_INFO,"Invalid password\n");
	    prc=PAM_AUTH_ERR;
	    break;
	case PAM_MYPROXY_CERT_EXPIRED:
	    pam_syslog(pamh, LOG_INFO,"Certificate expired\n");
	    prc=PAM_AUTH_ERR;
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
 * Stores proxy either in memory and or on disk, depending on opts.writeproxy. 
 * In the former case it is stored as ENV_PKEY and STACK_OF(X509) in pam data
 * with names DATA_PROXY_KEY and DATA_PROXY_CHAIN, in the latter case it is
 * stored in a file with name cred->filename, which is constructed from
 * opts->proxyfmt; the name is stored in pam data with name
 * DATA_PROXY_FILENAME.
 * \param pamh pam handle
 * \param opts configuration options
 * \param cred credentials, including the name of the proxy file, contents will
 * be cleared unless successfully stored in memory
 * \return pam_sm_authenticate compatible return value
 */
static int _store_proxy(pam_handle_t *pamh, pam_myproxy_opts_t *opts,
			cred_t *cred) {
    int rc,len;
    char *proxy_buf=NULL;
    char *buffer=NULL;

    /* Write when writeproxy is non-zero */
    if (opts->writeproxy)   {
	/* Use filebased: write to file, store filename as a pam data element
	 * for other modules and put in environment. Then free chain and private
	 * key */
	/* Write proxy */
	if ( (rc=_myproxy_write_proxy(opts->proxyfmt, cred))!=0)   {
	    if (cred->proxyfile)
		pam_syslog(pamh, LOG_WARNING,
		       "Failed to write proxy %s\n",
		       cred->proxyfile);
	    else
		pam_syslog(pamh, LOG_WARNING,
		       "Failed to write proxy\n");
	    return PAM_AUTHINFO_UNAVAIL;
	}
	/* Duplicate buffer */
	if ( (proxy_buf=strdup(cred->proxyfile))==NULL ) {
	    pam_syslog(pamh,LOG_ERR,"Out of memory\n");
	    return PAM_AUTHINFO_UNAVAIL;
	}
	/* Store in pam data */
	if ( (rc=pam_set_data(pamh, PAM_PROXY_FILENAME, proxy_buf,
			      _pam_string_cleanup))!=PAM_SUCCESS)    {
	    pam_syslog(pamh,LOG_ERR,"Cannot store proxyname as pam data: %s\n",
		pam_strerror(pamh,rc));
	    free(proxy_buf);
	    return PAM_AUTHINFO_UNAVAIL;
	}
	
	/* Store proxy internal env */
	if (opts->useenv)	{
	    /* proxy */
	    len=1+snprintf(buffer,0,"%s=%s",PAM_PROXY_FILENAME,cred->proxyfile);
	    if ( (buffer=malloc(len))==NULL )
		return PAM_AUTHINFO_UNAVAIL;
	    snprintf(buffer,len,"%s=%s",PAM_PROXY_FILENAME,cred->proxyfile);
	    rc=pam_putenv(pamh,buffer);
	    free(buffer);
	    if (rc!=PAM_SUCCESS)
		return PAM_AUTHINFO_UNAVAIL;
	}
    } else {
	/* Memory based: store in pam items "myproxychain" and "myproxykey",
	 * store chain first */
	if ( (rc=pam_set_data(pamh, PAM_PROXY_CHAIN,
			      (void*)cred->chain,
			      _pam_chain_cleanup))!=PAM_SUCCESS)    {
	    /* Chain failed */
	    pam_syslog(pamh, LOG_ERR,
		"Failed to pam_set_data proxy chain: %s\n",
		pam_strerror(pamh,rc));
	    return PAM_AUTHINFO_UNAVAIL;
	} else if ( (rc=pam_set_data(pamh, PAM_PROXY_KEY,
			      (void*)cred->privkey,
			      _pam_privkey_cleanup))!=PAM_SUCCESS)    {
	    /* Key failed */
	    pam_syslog(pamh, LOG_ERR,
		"Failed to pam_set_data private key: %s\n",
		pam_strerror(pamh,rc));
	    return PAM_AUTHINFO_UNAVAIL;
	}
    }

    return rc;
}

/************************************************************************/
/* PUBLIC FUNCTIONS                                                     */
/************************************************************************/

/**
 * pam_sm_authenticate() function implementing the pam_authenticate function for
 * obtaining a MyProxy delegation via username/password. It stores the
 * credentials either in a proxy file, setting the name in PAM_MYPROXY_ENVVAR
 * env variable and DATA_PROXY_FILENAME pam data, or stores it only in memory in
 * a chain/key in pam data DATA_PROXY_CHAIN/DATA_PROXY_KEY. The env variable is
 * needed to retrieve it in pam_sm_setcred. Other pam modules may obtain the
 * proxy filename or in-memory data via the DATA_PROXY_FILENAME or
 * DATA_PROXY_CHAIN and DATA_PROXY_KEY.
 * \param see pam_sm_authenticate
 * \return see pam_sm_authenticate
 */
PAM_EXTERN int 
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    /* initialize cred structure */
    cred_t cred={NULL,NULL,NULL,NULL,NULL};
    pam_myproxy_opts_t opts;
    int rc,prc;
    BIO *bio=NULL;
    char *errstr=NULL;

    /* Initialize opts */
    _pam_myproxy_config_init(&opts);

    /* Get commandline (and perhaps config file) options */
    if ( (rc=_pam_myproxy_parse_cmdline(argc,argv,&opts)) != 0)	{
	_parse_opts_cmdline_returncode(pamh,rc,argv,&opts);
	_pam_myproxy_config_free(&opts);
	return PAM_AUTHINFO_UNAVAIL;
    }
    
    /* Get username */
    if (pam_get_user(pamh, &(cred.username), PAM_MYPROXY_USER_PROMPT)
	    != PAM_SUCCESS)  {
	pam_syslog(pamh, LOG_WARNING,
	    "user is unset, cannot continue.\n");
	_pam_myproxy_config_free(&opts);
	return PAM_CRED_INSUFFICIENT;
    }

    /* Get myproxy password: do not put this in PAM_AUTHTOK, it will not be of
     * use for others */
    if ( (rc=_get_password(pamh, flags, &(cred.password))) != PAM_SUCCESS)  {
	_pam_myproxy_config_free(&opts);
	return rc;
    }

    /* Setup SSL connection to myproxy server */
    rc=_myproxy_connect_ssl(&bio, &opts.endpoint, &opts.certinfo);
    if ( rc==PAM_MYPROXY_SUCCESS )  {
	/* Try to obtain credentials */
	rc=_myproxy(bio, &cred, opts.keysize, opts.lifetime,&errstr);

	/* Close connection */
	_myproxy_close_ssl(&bio);
    }
    
    /* Cleanup password */
    _myproxy_free_password(&cred);

    /* Parse return code (this also free-s clears the errstr) */
    prc=_parse_myproxy_returncode(pamh, rc, errstr, &cred, &opts);

    /* Write proxy when needed: when writing, will free chain and private key */
    if (prc==PAM_SUCCESS)
	prc=_store_proxy(pamh,&opts, &cred);

    /* We're done with the credentials as we have it on disk now */
    if (opts.writeproxy || prc!=PAM_SUCCESS)
	_myproxy_free_cred(&cred);

    /* Cleanup opts */
    _pam_myproxy_config_free(&opts);

    return prc;
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
    pam_myproxy_opts_t opts;
    int len,prc,rc,myerrno;
    char *buffer,*proxy_buf;
    const char *proxy,*proxy_env;
    struct stat buf;

    /* Initialize opts */
    _pam_myproxy_config_init(&opts);

    /* Get commandline (and perhaps config file) options */
    if ( (rc=_pam_myproxy_parse_cmdline(argc,argv,&opts)) !=0 ) {
	_parse_opts_cmdline_returncode(pamh,rc,argv,&opts);
	_pam_myproxy_config_free(&opts);
	return PAM_CRED_ERR;
    }
    
    /* If we don't write the proxy, we don't need to do anything */
    if (!opts.writeproxy)   {
	_pam_myproxy_config_free(&opts);
	return PAM_SUCCESS;
    }
    
    /* Cleanup opts, we're done with them */
    _pam_myproxy_config_free(&opts);

    /* First handle credential removal */
    if ( flags & PAM_DELETE_CRED )  {
	/* First check we have a name */
	rc=pam_get_data(pamh,PAM_PROXY_FILENAME,(const void **)&proxy);
	if (rc==PAM_NO_MODULE_DATA) { /* Nothing to do */
	    pam_syslog(pamh,LOG_DEBUG,"No proxy data found\n");
	    return PAM_SUCCESS;
	}
	/* Any non-success at this stage is an error */
	if (rc!=PAM_SUCCESS)	{
	    pam_syslog(pamh,LOG_ERR,"Error retrieving pam data\n");
	    return PAM_CRED_ERR;
	}

	/* data entry found, try to remove it. In any case remove the data
	 * entry as it will no longer be valid */

	/* Try to stat it */
	if (stat(proxy,&buf)==-1) { /* stat failed */
	    myerrno=errno;
	    if (myerrno==ENOENT)
		/* file does not exist: ok, but remove pam data as it no longer
		 * valid */
		prc=PAM_SUCCESS;
	    else	{ /* unknown error */
		pam_syslog(pamh,LOG_ERR,"Cannot stat proxy %s: %s\n",
		    proxy,strerror(myerrno));
		prc=PAM_CRED_ERR;
	    }
	} else if (unlink(proxy)==0)   {
	    pam_syslog(pamh,LOG_DEBUG,"Removed proxy %s\n",proxy);
	    prc=PAM_SUCCESS;
	} else  { /* unlink() failed */
	    myerrno=errno;
	    pam_syslog(pamh,LOG_ERR,"Cannot remove proxy %s: %s\n",
		    proxy,strerror(myerrno));
	    prc=PAM_CRED_ERR;
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
	     strcmp(proxy_env,proxy)==0 &&
	     (rc=pam_putenv(pamh, PROXY_ENV_VAR)) != PAM_SUCCESS )
	    pam_syslog(pamh,LOG_WARNING,"Cannot unset variable %s: %s\n",
		       PROXY_ENV_VAR,pam_strerror(pamh,rc));

	return prc;
    }

    /* Remainder is credential setting */
    /* Is is present in the environment to be retrieved? */
    if (opts.useenv && (proxy=pam_getenv(pamh, PAM_PROXY_FILENAME))!=NULL) {
	/* Copy for data and credentials */
	if ( (proxy_buf=strdup(proxy))==NULL )	{
	    pam_syslog(pamh,LOG_ERR,"Out of memory\n");
	    return PAM_CRED_ERR;
	}
	/* Store in data */
	if ( (rc=pam_set_data(pamh,PAM_PROXY_FILENAME,
			  proxy_buf,_pam_string_cleanup))!=PAM_SUCCESS )    {
	    pam_syslog(pamh,LOG_ERR,"Cannot put %s in pam data: %s\n",
		proxy_buf,pam_strerror(pamh,rc));
	    free(proxy_buf);
	    return PAM_CRED_ERR;
	}
	/* Remove from env */
	if ( (rc=pam_putenv(pamh,PAM_PROXY_FILENAME))!=PAM_SUCCESS )  {
	    pam_syslog(pamh,LOG_ERR,"Cannot remove %s from pam env: %s\n",
		PAM_PROXY_FILENAME,pam_strerror(pamh,rc));
	    return PAM_CRED_ERR;
	}
    } else if ( (rc=pam_get_data(pamh,PAM_PROXY_FILENAME,
		    (const void **)&proxy)) !=PAM_SUCCESS) {
	pam_syslog(pamh,LOG_ERR,"Cannot obtain proxy data: %s\n",
		pam_strerror(pamh,rc));
	return PAM_CRED_ERR;
    }

    /* proxy is now present as data, now set it in the pam environment for the
     * user */
    len=2+strlen(PROXY_ENV_VAR)+strlen(proxy);
    if ( (buffer=(char *)malloc(len))==NULL )	{
	pam_syslog(pamh,LOG_ERR,"Out of memory\n");
	return PAM_CRED_ERR;
    } else {
	snprintf(buffer,len,"%s=%s",PROXY_ENV_VAR,proxy);
	if ( (rc=pam_putenv(pamh, buffer))!=PAM_SUCCESS )   {
	    pam_syslog(pamh,LOG_ERR,"Cannot set data for proxy %s: %s\n",
		    proxy,pam_strerror(pamh,rc));
	    free(buffer);
	    return PAM_CRED_ERR;
	}
    }
   
    return PAM_SUCCESS;
}

