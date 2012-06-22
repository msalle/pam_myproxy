#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "pam_myproxy.h"

/**
 * Reads the config file into buffer
 * \param buffer will be malloced and contain the contents of the config file
 * \return 0 on success, -1 I/O failure, -2 permission failure, -3 memory
 * failure
 */
static int _read_conf_file(char **buffer, const char *conffile)   {
    char *buf;
    int rc=0,fd=0;
    struct stat fstatbuf;

    /* initialize buffer */
    buf=NULL;

    /* open file */
    if ( (fd=open(conffile, O_RDONLY))==-1 ||
	 fstat(fd, &fstatbuf) )
	return -1;  /* I/O error */

    /* basic checks. TODO: safeopen */
    if (!S_ISREG(fstatbuf.st_mode) ||	/* regular file? */
	fstatbuf.st_uid!=0 ||		/* root-owned? */
	(fstatbuf.st_mode & S_IWGRP) || /* unwriteable group? */
	(fstatbuf.st_mode & S_IWOTH))	{ /* unwriteable others? */
	rc=-2;
	goto conf_failed;
    }

    /* malloc buffer */
    if ( (buf=(char*)malloc(fstatbuf.st_size))==NULL )	{
	rc=-3;
	goto conf_failed;
    }

    /* read config */
    if ( read(fd, buf, fstatbuf.st_size)<=0 )	{
	rc=-1;
	goto conf_failed;
    }
    rc=0;
    close(fd);
    *buffer=buf;
    return rc;

conf_failed:
    if (buf)	free(buf);
    if (fd>0)	close(fd);

    return rc;
}

/**
 * Parses buf for option, which will be returned. Caller needs to free.
 * \param buf contains config file
 * \param option option name
 * \return value of option
 */
static char *_conf_value(const char *buf, const char *option)   {
    char *value=NULL;
    int optlen,pos=0,pos2,pos3,len;

    if (buf==NULL || option==NULL) return NULL;
    optlen=strlen(option);
    do {
	/* Find next non-whitespace */
	while (buf[pos]==' ' || buf[pos]=='\t' || buf[pos]=='\n')
	    pos++;

	if (buf[pos]=='\0')
	    return NULL;

	if (strncmp(&(buf[pos]),option,optlen)==0 &&
	    (buf[pos+optlen]==' ' || buf[pos+optlen]=='\t' ||
	     buf[pos+optlen]=='='))
	{   /* Found option */
	    /* Find start of value */
	    pos2=pos+optlen;
	    while ( buf[pos2]==' ' || buf[pos2]=='\t')
		pos2++;
	    if (buf[pos2]=='=') {
		do {
		    pos2++;
		} while (buf[pos2]==' ' || buf[pos2]=='\t');
	    }
	    /* Find end of value */
	    pos3=pos2;
	    while (buf[pos3]!='\n' && buf[pos3]!='\0' && buf[pos3]!='#')
		pos3++;
	    /* one back and remove trailing whitespace */
	    do {
		pos3--;
	    } while (buf[pos3]==' ' || buf[pos3]=='\t');
	    if ((len=pos3-pos2+1)>0)  {
		if ( (value=(char*)calloc(1,len+1))==NULL )
		    return NULL;
		strncpy(value,&(buf[pos2]),len);
		break;
	    }
	    pos=pos3;
	}
	/* Skip till next line or end of buffer */
	while (buf[pos]!='\n' && buf[pos]!='\0')
	    pos++;
    } while (value==NULL && buf[pos]!='\0');

    return value;
}

/**
 * Looks for option in buf, when successfully found, returns it value, otherwise
 * default
 * \param buf contains configuration
 * \param option option to look for
 * \param defval value to return when option cannot be found
 * \return value found or defval
 */
static char *_conf_val_str(const char *buf, const char *option,
			   const char *defval) {
    char *value;

    if ( (value=_conf_value(buf, option)) == NULL )
	value=strdup(defval);

    return value;
}

/**
 * Looks for option in buf, when successfully found, returns it value converted
 * to long, otherwise default
 * \param buf contains configuration
 * \param option option to look for
 * \param defval value to return when option cannot be found or converted to
 * long
 * \return value found or defval
 */
static long _conf_val_long(const char *buf, const char *option,
				   const long defval) {
    char *strval;
    long value=defval;

    if ( (strval=_conf_value(buf, option)) == NULL )
	value=defval;
    else    {
	if ( (sscanf(strval,"%ld",&value)!=1 ) )
	    value=defval;
	free(strval);
    }

    return value;
}

/**
 * Looks for option in buf, when successfully found, returns it value converted
 * to int, otherwise default
 * \param buf contains configuration
 * \param option option to look for
 * \param defval value to return when option cannot be found or converted to
 * int
 * \return value found or defval
 */
static int _conf_val_int(const char *buf, const char *option,
				   const int defval) {
    char *strval;
    int value=defval;

    if ( (strval=_conf_value(buf, option)) == NULL )
	value=defval;
    else    {
	if ( (sscanf(strval,"%d",&value)!=1 ) )
	    value=defval;
	free(strval);
    }

    return value;
}

/**
 * Free()s memory in config options
 * \param opts contains the lcmapsd options 
 */
void _pam_myproxy_config_free(pam_myproxy_opts_t *opts) {
    free(opts->certinfo.CApath);	opts->certinfo.CApath=NULL;
    free(opts->certinfo.CAfile);	opts->certinfo.CAfile=NULL;
    free(opts->certinfo.clientcert);	opts->certinfo.clientcert=NULL;
    free(opts->certinfo.clientkey);	opts->certinfo.clientkey=NULL;

    free(opts->endpoint.host);		opts->endpoint.host=NULL;

    free(opts->proxyname);		opts->proxyname=NULL;
}

/**
 * Parses the config file and stores the values in opts
 * \param opts contains the lcmapsd options
 * \return 0 success, -1 on I/O error, -2 on permission error, -3 on memory
 * error
 */
int _pam_myproxy_parse_config(pam_myproxy_opts_t *opts) {
    char *buf=NULL;
    int rc;

    if ( (rc=_read_conf_file(&buf, opts->conffile)) )
	goto finalize;

//    opts->certinfo.CApath=_conf_val_str(buf,"CApath","/etc/grid-security/certificates");
    opts->certinfo.CApath=_conf_val_str(buf,"CApath",NULL);
    opts->certinfo.CAfile=_conf_val_str(buf,"CAfile",NULL);
    opts->certinfo.clientcert=_conf_val_str(buf,"hostcert",NULL);
    opts->certinfo.clientkey=_conf_val_str(buf,"hostkey",NULL);

    opts->endpoint.host=_conf_val_str(buf,"MyProxyHost",NULL);
    opts->endpoint.port=_conf_val_int(buf,"MyProxyPort",7512);

    opts->proxyname=_conf_val_str(buf,"proxyformat","/tmp/x509up_u%d_XXXXXX");

    opts->lifetime=_conf_val_long(buf,"proxylifetime",43200);
    opts->bits=_conf_val_int(buf,"keysize",2048);

finalize:
    free(buf);
    return rc;
}
