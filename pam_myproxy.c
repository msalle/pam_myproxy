#include <security/pam_modules.h>
#include <security/pam_ext.h> 
#include <syslog.h>

/* Only authenticate and session for now */

/* For pam_sm_authenticate */
#define PAM_SM_AUTH

#define PAM_SM_SESSION

static int _get_password(pam_handle_t *pamh, char **password)	{
    const struct pam_conv *conv;
    struct pam_message msg[1];
    const struct pam_message *pmsg[1];
    struct pam_response *resp=NULL;

    pmsg[0]=&msg[0];
    msg[0].msg_style=PAM_PROMPT_ECHO_OFF;
    msg[0].msg="MyProxy password: ";
    
    /* Get conv structure */
    retval = pam_get_item(pamh,PAM_CONV,&conv);
    /* Run conv when we have a conv struct */
    if (rc==PAM_SUCCESS && conv) {
	rc=conv->conv(1, pmsg, &resp, conv->appdata_ptr);
	if (rc!=PAM_SUCCESS) {
	    pam_syslog(pamh, LOG_ERR, "Converse function failed %d: %s",
		       rc, pam_strerror(pamh, retval));
	    return rc;
	}
    } else { /* either not got PAM_SUCCESS or conv was null */
	pam_syslog(pamh, LOG_ERR, "Failed to get pam_conv");
	if (rc == PAM_SUCCESS)
	    rc = PAM_BAD_ITEM;
	return rc;
    }

    /* If response is obtained */
    if (resp) {
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
    } else
	return PAM_CONV_ERR;

    free(resp);
    
    /* this *MUST* be free()'d by this module */
    *password = pass;

    return PAM_SUCCESS;
}


}

PAM_EXTERN int 
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    cred_t cred;
    pam_myproxy_opts_t opts;
    int rc=0;
    BIO *bio=NULL;

    /* Get commandline (and perhaps config file) options */
    rc=_pam_myproxy_parse_cmdline(argc,argv,&opts);

    if (rc!=0)	{
	switch(rc)  {
	    case -1:
		pam_syslog(LOG_ERR,
		    "I/O Error while parsing config file (%s)\n",opts.conffile);
		break;
	    case -2:
		pam_syslog(LOG_ERR,
		    "Permission of config file are wrong (%s)\n",opts.conffile);
		break;
	    case -3:
		pam_syslog(LOG_ERR,
		    "Out of memory while parsing options\n");
		break;
	    default:
		pam_syslog(LOG_ERR,
		    "Syntax error around for option %s\n",argv[rc-1]);
		break;
	}
	_pam_myproxy_config_free(&opts);
	return PAM_AUTHINFO_UNAVAIL;
    }

    /* Get myproxy password */
    if ( (rc=_get_password(pamh, &(cred.passwd))) != PAM_SUCCESS)
	return rc;

    /* Get username */
    if (pam_get_user(pamh, &(cred.user), "Enter DN: ")!=PAM_SUCCESS)  {
	pam_syslog(LOG_WARN,
	    "user is unset, cannot continue.\n");
	_pam_myproxy_config_free(&opts);
	return PAM_CRED_INSUFFICIENT;
    }


}
