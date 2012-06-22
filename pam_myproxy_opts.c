#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "pam_myproxy.h"

/************************************************************************
 * Private functions
 ************************************************************************/

/**
 * Replaces dst with src iff src!=NULL, free-ing dst first.
 * \param dst destination
 * \param src source
 * \return dst (either old or new)
 */
static char *_subst_val(char **dst, char *src) {
    /* new value? */
    if (src!=NULL)  {
	if (*dst) free(*dst);
	*dst=src;
    }
    return *dst;
}

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

    /* malloc buffer: filesize plus trailing \0 */
    if ( (buf=(char*)malloc(1+fstatbuf.st_size))==NULL )	{
	rc=-3;
	goto conf_failed;
    }

    /* Read config is filesize >0 */
    if (fstatbuf.st_size>0) {
	if ( read(fd, buf, fstatbuf.st_size)<=0 )	{
	    rc=-1;
	    goto conf_failed;
	}
    }
    /* Add trailing \0 */
    buf[fstatbuf.st_size]='\0';
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
 * \param buf contains config file contents
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
 * Looks for option in buf, when successfully found, returns it value as string,
 * otherwise return default value
 * \param buf contains configuration
 * \param option option to look for
 * \param defval value to return when option cannot be found
 * \return value found as string or defval, NULL on memory error
 */
static char *_conf_val_str(const char *buf, const char *option,
			   const char *defval) {
    char *value;

    if ( (value=_conf_value(buf, option)) == NULL )
	value=defval ? strdup(defval) : NULL;

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
 * Initializes the options structure
 * \param opts configuration options structure 
 */
static void _init_opts_struct(pam_myproxy_opts_t *opts)	{
    opts->conffile=NULL;

    opts->certinfo.cafile=opts->certinfo.capath=
	opts->certinfo.clientcert=opts->certinfo.clientkey=NULL;

    opts->endpoint.host=NULL;
    opts->endpoint.port=DEF_PORT;

    opts->proxyname=strdup(DEF_FORMAT);
    opts->writeproxy=DEF_WRITE;
    opts->lifetime=DEF_LIFETIME;
    opts->keysize=DEF_KEYSIZE;
}

/************************************************************************
 * Public functions
 ************************************************************************/

/**
 * free()s all memory contained in opts structure
 * \param opts struct containing the configuration options
 */
void _pam_myproxy_config_free(pam_myproxy_opts_t *opts) {
    free(opts->conffile);		opts->conffile=NULL;

    free(opts->certinfo.capath);	opts->certinfo.capath=NULL;
    free(opts->certinfo.cafile);	opts->certinfo.cafile=NULL;
    free(opts->certinfo.clientcert);	opts->certinfo.clientcert=NULL;
    free(opts->certinfo.clientkey);	opts->certinfo.clientkey=NULL;

    free(opts->endpoint.host);		opts->endpoint.host=NULL;

    free(opts->proxyname);		opts->proxyname=NULL;
}

/**
 * Parses the config file in opts.conffile, and leaves the output in the
 * different opts fields
 * \param opts struct containing the configuration options
 * \return -1 I/O error
 *	   -2 permission error (of config file)
 *	   -3 memory error
 *	   0 success
 */
int _pam_myproxy_parse_config(pam_myproxy_opts_t *opts) {
    char *buf=NULL;
    int rc;

    if ( (rc=_read_conf_file(&buf, opts->conffile)) )
	goto finalize;

/*    opts->certinfo.CApath=_conf_val_str(buf,"CApath","/etc/grid-security/certificates");*/
    opts->certinfo.capath=_conf_val_str(buf,"capath",NULL);
    opts->certinfo.cafile=_conf_val_str(buf,"cafile",NULL);
    opts->certinfo.clientcert=_conf_val_str(buf,"hostcert",NULL);
    opts->certinfo.clientkey=_conf_val_str(buf,"hostkey",NULL);

    opts->endpoint.host=_conf_val_str(buf,"myproxyhost",NULL);
    opts->endpoint.port=_conf_val_int(buf,"myproxyport",DEF_PORT);

    opts->proxyname=_conf_val_str(buf,"proxyfmt",DEF_FORMAT);
    opts->writeproxy=_conf_val_int(buf,"writeproxy",DEF_WRITE);

    opts->lifetime=_conf_val_long(buf,"lifetime",DEF_LIFETIME);
    opts->keysize=_conf_val_int(buf,"keysize",DEF_KEYSIZE);

finalize:
    free(buf);
    return rc;
}

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
				pam_myproxy_opts_t *opts) {
    int i,intval,longval,rc;
    char *pos,*opt,*val;

    /* Initialize opts */
    _init_opts_struct(opts);

    /* Note: pam opts start at 0, not at 1 */
    for (i=0; i<argc; i++)  {
	if ( (opt=strdup(argv[i])) == NULL )
	    return -3;
	/* Get value and remove from opt */
	if ( (pos=strchr(opt,'='))==NULL )  {
	    free(opt);
	    return i+1;
	}
	pos[0]='\0';
	/* strdup, since we need to free opt separately */
	if ( (val=strdup(&pos[1]))==NULL)   {
	    free(opt);
	    return -3;
	}

	/* Look for right option */
	if (strcmp(opt,"config")==0)    {
	    _subst_val(&(opts->conffile),val);
	    if ( (rc=_pam_myproxy_parse_config(opts))!=0)   {
		free(opt);
		return rc;
	    }
	} else if (strcmp(opt,"capath")==0)
	    _subst_val(&(opts->certinfo.capath),val);
	else if (strcmp(opt,"cafile")==0)
	    _subst_val(&(opts->certinfo.cafile),val);
	else if (strcmp(opt,"hostcert")==0)
	    _subst_val(&(opts->certinfo.clientcert),val);
	else if (strcmp(opt,"hostkey")==0)
	    _subst_val(&(opts->certinfo.clientkey),val);
	else if (strcmp(opt,"myproxyhost")==0)
	    _subst_val(&(opts->endpoint.host),val);
	else if (strcmp(opt,"myproxyport")==0) {
	    if (sscanf(val,"%d",&intval)!=1)	{
		free(val); free(opt);
		return i+1;
	    }
	    opts->endpoint.port=intval;
	    free(val);
	} else if (strcmp(opt,"proxyfmt")==0)
	    _subst_val(&(opts->proxyname),val);
	else if (strcmp(opt,"writeproxy")==0)	{
	    if (sscanf(val,"%d",&intval)!=1)	{
		free(val); free(opt);
		return i+1;
	    }
	    opts->writeproxy=intval;
	    free(val);
	}
	else if (strcmp(opt,"lifetime")==0) {
	    if (sscanf(val,"%d",&longval)!=1)	{
		free(val); free(opt);
		return i+1;
	    }
	    opts->lifetime=longval;
	    free(val);
	} else if (strcmp(opt,"keysize")==0) {
	    if (sscanf(val,"%d",&intval)!=1)	{
		free(val); free(opt);
		return i+1;
	    }
	    opts->keysize=intval;
	    free(val);
	} else {
	    free(val); free(opt);
	    return i+1;
	}
	free(opt);
    }

    return 0;
}
