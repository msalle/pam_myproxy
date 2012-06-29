#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "myproxy_client.h"

/************************************************************************/
/* PRIVATE FUNCTIONS                                                    */
/************************************************************************/

/************************************************************************
 * Certificate Signing Request code
 ***********************************************************************/
/*
 * Based on mkreq.c from OpenSSL source code
 * Creates a keypair and certificate signing request (only needed to transport
 * the public key)
 * \param req resulting CSR
 * \param pkeyp private key
 * \param bits keysize
 * \param dn user's Distinguished Name
 * \return error or PAM_MYPROXY_SUCCESS
 */
static myproxy_err_t _getcsr(X509_REQ **req, EVP_PKEY **pkeyp,
		   int bits, const unsigned char *dn) {
        X509_REQ *x;
        EVP_PKEY *pk;
        RSA *rsa;
        X509_NAME *name=NULL;
	const unsigned char *country=(unsigned char*)"UK";
        
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

        if ((pk=EVP_PKEY_new()) == NULL)
                goto err;

        if ((x=X509_REQ_new()) == NULL)
                goto err;

        rsa=RSA_generate_key(bits,RSA_F4,NULL,NULL);
        if (!EVP_PKEY_assign_RSA(pk,rsa))
                goto err;

        rsa=NULL;

        X509_REQ_set_pubkey(x,pk);

        name=X509_REQ_get_subject_name(x);

        /* This function creates and adds the entry, working out the
         * correct string type and performing checks on its length.
         * Normally we'd check the return value for errors...
         */
        X509_NAME_add_entry_by_txt(name,"C",
                                MBSTRING_ASC, country, -1, -1, 0);
        X509_NAME_add_entry_by_txt(name,"CN",
                                MBSTRING_ASC, dn, -1, -1, 0);

        if (!X509_REQ_sign(x,pk,EVP_sha1()))
                goto err;

        *req=x;
        *pkeyp=pk;

        return PAM_MYPROXY_SUCCESS;

err:
	return PAM_MYPROXY_CSR_ERR;
}

/************************************************************************
 * SSL socket and handshake setup code
 ***********************************************************************/

/**
 * Sets up the SSL_CTX for given certinfo structure.
 * \param cert contains the cafile, capath etc. information
 * \return SSL_CTX or NULL on error, should be freed
 */
static SSL_CTX *_setup_client_ctx(certinfo_t *cert) {
    const char *cafile, *capath;
    SSL_CTX * ctx = NULL;

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx)
        return NULL;

    /* Determine CAfile and CApath settings to use: use default certdir when
     * neither is given */
    if (cert->cafile==NULL && cert->capath==NULL)   {
	cafile=NULL;
	capath=X509_get_default_cert_dir();
    } else {
	cafile=cert->cafile;
	capath=cert->capath;
    }
    if (SSL_CTX_load_verify_locations(ctx, cafile, capath) != 1)
	goto ctx_failed;

    /* Set clientcert and key (only when both are given) */
    if (cert->clientcert && cert->clientkey && 
	(SSL_CTX_use_certificate_chain_file(ctx, cert->clientcert) != 1 ||
	 SSL_CTX_use_PrivateKey_file(ctx,cert->clientkey,SSL_FILETYPE_PEM)!=1))
	goto ctx_failed;

    /* Use default verifier */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    /* Set max Chain depth */
    SSL_CTX_set_verify_depth(ctx, MAXCHAINDEPTH);
    SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
/*    SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);*/
    if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
        goto ctx_failed;

    return ctx;

ctx_failed:
    SSL_CTX_free (ctx);
    return NULL;
}

/**
 * Post SSL handshake connection check to verify the peer certificate matches
 * given host, see post_connection_check() in lcmaps-plugins-scas-client
 * (saml2-xacml2/io_handler/ssl/ssl-common.c)
 * \param host hostname
 * \param ssl SSL handshake information
 * \return X509_V_OK on success or X509_V_ERR_APPLICATION_VERIFICATION on error
 */
static long _post_connection_check(SSL *ssl, const char *host) {
    X509      *      peer_cert = NULL;
    X509_NAME *      subj;
    char             datad[256];
    int              extcount;
    int              ok = 0;
    int              found_DNS_entry = 0;

    if (!host)
        goto err_occured;

    if (!(peer_cert = SSL_get_peer_certificate(ssl)) || !host)
        goto err_occured;

  #if OPENSSL_VERSION_NUMBER >= 0x00908000L
    peer_cert->ex_flags |= EXFLAG_PROXY;
  #endif /* OPENSSL_VERSION_NUMBER >= 0x00908000L */

    /* Compare the subjectAltName DNS value with the host value */
    if ((extcount = X509_get_ext_count(peer_cert)) > 0) {
        int i;

        for (i = 0; i < extcount; i++) {
            X509_EXTENSION    *ext;
            int NID_from_ext = NID_undef; /* Initialize with undefined NID (Numerical ID of a type of ASN1 object) */

            ext = X509_get_ext(peer_cert, i);
            NID_from_ext = OBJ_obj2nid(X509_EXTENSION_get_object(ext));

            if (NID_from_ext == NID_subject_alt_name) {
                int                  j;
                const unsigned char  *data;
                STACK_OF(CONF_VALUE) *val;
                CONF_VALUE           *nval;
                const X509V3_EXT_METHOD    *meth;
                void                 *ext_str = NULL;

                if (!(meth = X509V3_EXT_get(ext)))
                    break;
                data = ext->value->data;

#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
                if (meth->it)
                    ext_str = ASN1_item_d2i(NULL, &data, ext->value->length, ASN1_ITEM_ptr(meth->it));
                else
                    ext_str = meth->d2i(NULL, &data, ext->value->length);
#else
                ext_str = meth->d2i(NULL, &data, ext->value->length);
#endif
                val = meth->i2v(meth, ext_str, NULL);
                for (j = 0;  j < sk_CONF_VALUE_num(val);  j++)
                {
                    nval = sk_CONF_VALUE_value(val, j);
                    if (!strcmp(nval->name, "DNS") && !strcasecmp(nval->value, host))
                    {
                        ok = 1;
                        break;
                    }
                    if (!strcmp(nval->name, "DNS"))
                        found_DNS_entry = 1;
                }

                sk_CONF_VALUE_pop_free( val, X509V3_conf_free );
                if (meth->it)
                    ASN1_item_free((ASN1_VALUE*)ext_str, meth->it);
                else
                    meth->ext_free(ext_str);
                ext_str = NULL;

            }
            if (ok)
                break;
        }
    }


    if (found_DNS_entry && !ok)
        goto err_occured;

    /* If the subjectAltName DNS value doesn't match the host value,
     * resort back to the X509v1 solution which is to compare the host value
     * with the final CN value in the cert's subject
     */
    if (!ok && (subj = X509_get_subject_name(peer_cert)) &&
        X509_NAME_get_text_by_NID(subj, NID_commonName, datad, 256) > 0)
    {
        if (strcasecmp(datad, host) != 0)
            goto err_occured;
        else
            ok = 1;
    }


    /* Clean up */
    if (peer_cert)
    {
        X509_free(peer_cert);
        peer_cert = NULL;
    }

    if (ok)
        return X509_V_OK;
    else
        return X509_V_ERR_APPLICATION_VERIFICATION;

err_occured:
    if (peer_cert) {
        X509_free(peer_cert);
        peer_cert = NULL;
    }
    return X509_V_ERR_APPLICATION_VERIFICATION;
}

/************************************************************************
 * Proxy filename related code
 ***********************************************************************/

/**
 * Creates a proper filename from given template, %d is substituted for
 * getuid(), trailing XXXXXX is substituted for a random string, via mkstemp()
 * \param out output (opened) filename
 * \param in input filename template
 * \return open filedescriptor or -1 on error
 */
static int _get_path(char **out, const char *in)  {
    int len;
    uid_t uid;
    int fd;
    char *buffer=NULL;

    if (!in)
	return -1;

    if (strstr(in,"%d")!=NULL)	{
	uid=getuid();
	len=snprintf(buffer,0,in,uid);
	if ( (buffer=malloc(len+1))==NULL)
	    return -1;
	snprintf(buffer,len+1,in,uid);
    } else {
	len=strlen(in);
	if ( (buffer=strdup(in))==NULL)
	    return -1;
    }

    if (strcmp(&(buffer[len-6]),"XXXXXX")!=0)    {
	free(buffer); buffer=NULL;
	return -1;
    }

    fd=mkstemp(buffer);
    *out=buffer;

    return fd;
}

/************************************************************************
 * MyProxy handshake code, initial and final
 ***********************************************************************/

/**
 * Sends the initial request (COMMAND=0) to the MyProxy server and parsers the
 * respond.
 * \param sbio open SSL connection
 * \param user MyProxy username (DN)
 * \param pass MyProxy password for given username
 * \param lifetime requested proxy lifetime
 * \param errstr contains first error line in case RESPONSE=1 instead of
 * RESPONSE=0
 * \return PAM_MYPROXY_SUCCESS on success or suitable error code
 */
static myproxy_err_t _myproxy_init(BIO *sbio,
			const char *user, const char *pass,
			unsigned int lifetime,
			char **errstr) {
    const char *fmt="VERSION=MYPROXYv2\nCOMMAND=0\n"
		    "USERNAME=%s\nPASSPHRASE=%s\nLIFETIME=%d\n";
    char *request=NULL, *response=NULL, *pos;
    int i,buflen,len,rc=PAM_MYPROXY_SUCCESS;

    *errstr=NULL;
  
    /* MyProxy allows at most 1 billion seconds */
    if (lifetime>1000000000L)	{
	rc=PAM_MYPROXY_INVAL;
	goto _initcleanup;
    }

    /* 60 buf, 1 \0, 9 for LIFETIME (max 1 billion) = 70 */
    buflen=70+strlen(user)+strlen(pass);
    if ( (request=(char*)malloc(buflen))==NULL )    {
	rc=PAM_MYPROXY_OUT_OF_MEM;
	goto _initcleanup;
    }

    if ( (len=snprintf(request, buflen, fmt, user, pass, lifetime))>buflen) {
	rc=PAM_MYPROXY_BUF_TOO_SMALL;
	goto _initcleanup;
    }

    /* Write "0" to server and flush */
    if (BIO_write(sbio,"0",1)<=0 || BIO_flush(sbio) <= 0)	{
	rc=PAM_MYPROXY_BIO_WRITE_ERR;
        goto _initcleanup;
    }

    /* Write request */
    if (BIO_write(sbio,request,len)<=0 || BIO_flush(sbio) <= 0) {
	rc=PAM_MYPROXY_BIO_WRITE_ERR;
	goto _initcleanup;
    }
    /* Read response */
    response=malloc(1024);
    if ( (len=BIO_read(sbio, response, 1024)) <=0 || BIO_flush(sbio) <= 0) {
	rc=PAM_MYPROXY_BIO_READ_ERR;
	goto _initcleanup;
    }

    /* Parse response */
    if (strstr(response,"RESPONSE=0")!=NULL)	{
	rc=PAM_MYPROXY_SUCCESS;
	goto _initcleanup;
    }

    /* There is something wrong */
    if (strstr(response,"RESPONSE=1")!=NULL)	{
	/* Store first error line if present */
	if ( (pos=strstr(response,"ERROR="))!=NULL )	{
	    *errstr=strdup(&pos[6]);
	    /* Remove everything from first newline and onwards */
	    if ( (pos=strchr(*errstr,'\n'))!=NULL )
		pos[0]='\0';
	}

	if (strstr(response,"No credentials exist for username")!=NULL ||
	    strstr(response,"Invalid username")!=NULL)	{
	    rc=PAM_MYPROXY_INVALID_USERNAME;
	    goto _initcleanup;
	}
	if (strstr(response,"invalid pass")!=NULL)	{
	    rc=PAM_MYPROXY_INVALID_PASSWORD;
	    goto _initcleanup;
	}
	if (strstr(response,"certificate has expired")!=NULL)	{
	    rc=PAM_MYPROXY_CERT_EXPIRED;
	    goto _initcleanup;
	}
    }

    rc=PAM_MYPROXY_RESPONSE_ERR;
    goto _initcleanup;

_initcleanup:
    if (request)    {
	/* Zero-out request as it contains password */
	i=0; while (request[i]!='\0') request[i++]='\0';
	free(request);
    }
    free(response);

    return rc;
}

/**
 * Does the followup MyProxy interaction: sending a certificate signing request
 * and reading the response. MyProxy sends first the proxy certificate followed
 * by the rest of the chain, followed by a final response message.
 * \param sbio open SSL connection to MyProxy server
 * \param req certificate signing request
 * \param chain received proxy chain
 * \return PAM_MYPROXY_SUCCESS or error code
 */
static myproxy_err_t _myproxy_getcerts(BIO *sbio,
				       X509_REQ *req, STACK_OF(X509) **chain) {
    char *response=NULL;
    X509 *tmp_cert = NULL;
    int rc=PAM_MYPROXY_SUCCESS,len,i;
    unsigned char numcerts;

    /* Write request on bio */
    if ( (len=i2d_X509_REQ_bio(sbio,req)<=0) || BIO_flush(sbio) <= 0)  {
	/* TODO: maybe different error */
	rc=PAM_MYPROXY_BIO_WRITE_ERR;
	goto error;
    }

    /* Read number of certs */
    if ( (len=BIO_read(sbio, &numcerts, sizeof(numcerts)))<=0 ||
	 BIO_flush(sbio) <= 0) {
	/* TODO: maybe different error */
	rc=PAM_MYPROXY_BIO_READ_ERR;
        goto error;
    }

    /* Initialize a new chain */
    if ( (*chain = sk_X509_new_null())==NULL )  {
	rc=PAM_MYPROXY_OUT_OF_MEM;
	goto error;
    }
    /* Read it from the bio */
    for (i=0; i<numcerts; i++)	{
        if ( (tmp_cert=d2i_X509_bio(sbio, NULL))==NULL ||
	     BIO_flush(sbio)<=0) {
	    /* TODO: maybe different error */
	    rc=PAM_MYPROXY_BIO_READ_ERR;
            goto error;
        }
	sk_X509_push(*chain, tmp_cert);
	tmp_cert=NULL;
    }
    /* Read final response to check everything is ok */
    if ( (response=malloc(1024))==NULL )    {
	rc=PAM_MYPROXY_OUT_OF_MEM;
	goto error;
    }

    if ( (len=BIO_read(sbio, response, 1024))<=0 ||
	 strstr(response,"RESPONSE=0")==NULL) {
	/* TODO: maybe different error */
	rc=PAM_MYPROXY_BIO_READ_ERR;
	goto error;
    }

    free(response);
    return rc;

error:
    if (*chain)	{
	for (i=0; i<sk_X509_num(*chain); i++)
	    sk_X509_pop_free(*chain, X509_free);
	sk_X509_free(*chain);
	*chain=NULL;
    }

    free(response);
    return rc;
}

/************************************************************************/
/* PUBLIC FUNCTIONS                                                     */
/************************************************************************/

/**
 * Opens a TCP+SSL connection to endpoint using information from cert
 * \param sbio upon success the opened SSL connection
 * \param endpoint (MyProxy) server endpoint
 * \param certinfo cafile, capath, client credentials.
 * \return PAM_MYPROXY_SUCCESS or error
 */
myproxy_err_t _myproxy_connect_ssl(BIO **sbio, endpoint_t *endpoint,
				   certinfo_t *certinfo) {
    BIO *bio=NULL;
    SSL *ssl=NULL;
    SSL_CTX *ctx=NULL;
    int rc=PAM_MYPROXY_SUCCESS;

    if (endpoint->host==NULL)
	return PAM_MYPROXY_HOST_UNSET;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    if ( (ctx=_setup_client_ctx(certinfo))==NULL )
	return PAM_MYPROXY_CTX_ERR;

    if (!(bio = BIO_new_ssl_connect(ctx))) {
	rc=PAM_MYPROXY_SSL_ERR;
	goto connect_fail;
    }

    BIO_get_ssl(bio, &ssl);
    if(!ssl)	{
	rc=PAM_MYPROXY_SSL_ERR;
	goto connect_fail;
    }

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    if (BIO_set_conn_int_port(bio, &(endpoint->port))<=0 ||
	BIO_set_conn_hostname(bio, endpoint->host)<=0 ||
	BIO_do_connect(bio)<=0 ||
	BIO_do_handshake(bio)<=0)  {
	rc=PAM_MYPROXY_CONNECT_ERR;
	goto connect_fail;
    }

    if (_post_connection_check(ssl, endpoint->host)!=X509_V_OK) {
	rc=PAM_MYPROXY_CONNECT_ERR;
	goto connect_fail;
    }

    *sbio=bio;
    return PAM_MYPROXY_SUCCESS; 

connect_fail:
    if (bio)	{
	BIO_ssl_shutdown(bio);
	BIO_free_all(bio);
    }
    if (ctx)
	SSL_CTX_free(ctx);

    *sbio=NULL;
    return rc;
}

/**
 * Closes TCP and SSL connection
 * \param sbio connection
 */
void _myproxy_close_ssl(BIO **sbio)  {
    SSL *ssl;
    SSL_CTX *ctx;

    if (*sbio)	{
	/* Try getting the ctx to clean up */
	if (BIO_get_ssl(*sbio, &ssl)>0)	{
	    ctx=SSL_get_SSL_CTX(ssl);
	    SSL_CTX_free (ctx);
	}
	BIO_ssl_shutdown(*sbio);
	BIO_free_all(*sbio);
	*sbio=NULL;
    }
}

/**
 * Writes proxy in chain and private key as pemfile to file.
 * \param filename proxy filename template: %d is substitute for getuid(),
 * XXXXXX for a random string (see mkstemp() )
 * \param cred contains proxy chain and private key. Upon success it also
 * contains the actual proxyfilename
 * \return 0 on success, -1 on error
 */
int _myproxy_write_proxy(const char *filename, cred_t *cred) {
    int fd;
    mode_t omask;
    X509 *cert;
    int depth,i,rc=0;
    FILE *fp=NULL;

    omask=umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if ( (fd=_get_path(&(cred->proxyfile),filename))==-1 ||
	 (fp=fdopen(fd,"w"))==NULL)
	return -1;

    if (PEM_write_PrivateKey(fp, cred->privkey, NULL, NULL, 0, 0, NULL)==0)  {
/*    if (PEM_write_PKCS8PrivateKey(fp, pkey, NULL, NULL, 0, 0, NULL)==0)*/
	rc=-1;
	goto write_fail;
    }

    depth=sk_X509_num(cred->chain);
    for (i=0; i<depth; i++)	{
	if ( (cert=sk_X509_value(cred->chain,i))==NULL ||
	     PEM_write_X509(fp,cert)==0)    {
	    rc=-1;
	    goto write_fail;
	}
    }

write_fail:
    umask(omask);
    /* Close file if it exists */
    if (fp!=NULL)
	fclose(fp);
    else if (fd!=-1)
	close(fd);
    /* Upon error try to remove the file */
    if (rc!=0 && fd!=-1)
	unlink(cred->proxyfile);

    return rc;
}

/************************************************************************
 * SSL cleanup code
 ***********************************************************************/

/**
 * Cleans and free-s password inside credential structure. Password is
 * explicitly overwritten
 * \param cred credential structure
 */
void _myproxy_free_password(cred_t *cred)  {
    int i;

    if (cred->password)	{
	i=0;
	while (cred->password[i])
	    cred->password[i++]='\0';
	free(cred->password);
	cred->password=NULL;
    }
}

/**
 * Cleans credential data. Password is explicitly overwritten
 * \param cred credential structure
 */
void _myproxy_free_cred(cred_t *cred)  {
    /* Cleanup proxyfile */
    free(cred->proxyfile); cred->proxyfile=NULL;

    /* Cleanup password if not yet done */
    _myproxy_free_password(cred);

    /* Cleanup private key */
    EVP_PKEY_free(cred->privkey); cred->privkey=NULL;

    /* Cleanup chain */
    if (cred->chain)	{
	sk_X509_pop_free(cred->chain, X509_free);
	cred->chain=NULL;
    }
}


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
		      char **errstr) {
    X509_REQ *req=NULL;
    int rc=PAM_MYPROXY_SUCCESS;

    if ( (rc=_myproxy_init(sbio,cred->username,cred->password,lifetime,errstr))
	    != PAM_MYPROXY_SUCCESS ||
	 (rc=_getcsr(&req, &(cred->privkey), bits,
		(const unsigned char*)cred->username)) != PAM_MYPROXY_SUCCESS ||
	 (rc=_myproxy_getcerts(sbio, req, &(cred->chain)))
		!= PAM_MYPROXY_SUCCESS )
	goto _myproxycleanup;

_myproxycleanup:
    if (req)
	X509_REQ_free(req);

    return rc;
}

