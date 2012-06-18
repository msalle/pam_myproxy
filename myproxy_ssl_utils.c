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

#include "myproxy_ssl_utils.h"


/************************************************************************
 * Certificate Signing Request code
 ***********************************************************************/
/*
 * Based on mkreq.c from OpenSSL source code
 */
int _getcsr(X509_REQ **req, EVP_PKEY **pkeyp, int bits, const char *dn) {
        X509_REQ *x;
        EVP_PKEY *pk;
        RSA *rsa;
        X509_NAME *name=NULL;
        
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
                                MBSTRING_ASC, "UK", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name,"CN",
                                MBSTRING_ASC, dn, -1, -1, 0);

        if (!X509_REQ_sign(x,pk,EVP_sha1()))
                goto err;

        *req=x;
        *pkeyp=pk;

        return 0;

err:
	return 1;
}


/************************************************************************
 * SSL socket and handshake setup code
 ***********************************************************************/
static SSL_CTX *_setup_client_ctx(certinfo_t *certinfo) {
    const char *cafile, *capath;
    SSL_CTX * ctx = NULL;

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx)
        return NULL;

    /* Determine CAfile and CApath settings to use: use default certdir when
     * neither is given */
    if (certinfo->CAfile==NULL && certinfo->CApath==NULL)   {
	cafile=NULL;
	capath=X509_get_default_cert_dir();
    } else {
	cafile=certinfo->CAfile;
	capath=certinfo->CApath;
    }
    if (SSL_CTX_load_verify_locations(ctx, cafile, capath) != 1)
	goto ctx_failed;

    /* Set clientcert and key (only when both are given) */
    if (certinfo->clientcert && certinfo->clientkey && 
	(SSL_CTX_use_certificate_chain_file(ctx, certinfo->clientcert) != 1 ||
	 SSL_CTX_use_PrivateKey_file(ctx,certinfo->clientkey,SSL_FILETYPE_PEM)!=1))
	goto ctx_failed;

    /* Use default verifier */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    /* Set max Chain depth */
    SSL_CTX_set_verify_depth(ctx, MAXCHAINDEPTH);
    SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
//    SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
    if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
        goto ctx_failed;

    return ctx;

ctx_failed:
    SSL_CTX_free (ctx);
    return NULL;
}

static long _post_connection_check(SSL *ssl, const char *host)
{
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

BIO *_connect_ssl(const char *host, int port, certinfo_t *certinfo)	{
    BIO *sbio=NULL;
    SSL *ssl=NULL;
    SSL_CTX *ctx=NULL;

    SSL_library_init();
    SSL_load_error_strings();
//    OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_algorithms();

    if ( (ctx=_setup_client_ctx(certinfo))==NULL )
	return NULL;

    if (!(sbio = BIO_new_ssl_connect(ctx)))
	goto connect_fail;

    BIO_get_ssl(sbio, &ssl);
    if(!ssl)
	goto connect_fail;

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    if (BIO_set_conn_int_port(sbio, &port)<=0 ||
	BIO_set_conn_hostname(sbio, host)<=0 ||
	BIO_do_connect(sbio)<=0 ||
	BIO_do_handshake(sbio)<=0)
	goto connect_fail;

    if (_post_connection_check(ssl, host)!=X509_V_OK)
	goto connect_fail;

    return sbio;

connect_fail:
    if (sbio)	{
	BIO_ssl_shutdown(sbio);
	BIO_free_all(sbio);
    }
    if (ctx)
	SSL_CTX_free(ctx);

    return NULL;
}

/************************************************************************
 * Proxy writing code
 ***********************************************************************/
int _write_proxy(const char *filename, EVP_PKEY *pkey, STACK_OF(X509) *chain) {
    FILE *fp=NULL;
    mode_t omask;
    X509 *cert;
    int depth,i,rc=0;

    omask=umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if ( (fp=fopen(filename, "w"))==NULL )
	return -1;

    if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, 0, NULL)==0)  {
//    if (PEM_write_PKCS8PrivateKey(fp, pkey, NULL, NULL, 0, 0, NULL)==0)
	rc=-1;
	goto write_fail;
    }

    depth=sk_X509_num(chain);
    for (i=0; i<depth; i++)	{
	if ( (cert=sk_X509_value(chain,i))==NULL ||
	     PEM_write_X509(fp,cert)==0)    {
	    rc=-1;
	    goto write_fail;
	}
    }

write_fail:
    umask(omask);
    fclose(fp);

    return rc;
}

/************************************************************************
 * SSL cleanup code
 ***********************************************************************/
void _free_chain_key(X509_REQ **req, EVP_PKEY **pkey, STACK_OF(X509) **chain)  {
    int i,depth;

    X509_REQ_free(*req); *req=NULL;
    EVP_PKEY_free(*pkey); *pkey=NULL;
    if (*chain)	{
	sk_X509_pop_free(*chain, X509_free);
	*chain=NULL;
    }
}

void _free_bio(BIO **sbio)  {
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


/************************************************************************
 * MyPROXY handshake code, initial and final
 ***********************************************************************/
int _myproxy_init(BIO *sbio, const char *user, const char *pass, int lifetime) {
    char *request=NULL, *response=NULL;
    int buflen,len,rc=0;

    /* 60 buf, 1 \0, 10 for LIFETIME */
    buflen=61+strlen(user)+strlen(pass)+10;
    request=(char*)malloc(buflen);
    if ( (len=snprintf(request,buflen,
	"VERSION=MYPROXYv2\nCOMMAND=0\nUSERNAME=%s\nPASSPHRASE=%s\nLIFETIME=%d\n",
	user,pass,lifetime))>buflen)    {
	rc=1;
	goto initerror;
    }

    /* Write "0" to server and flush */
    if (BIO_write(sbio,"0",1)<=0 || BIO_flush(sbio) <= 0)	{
	rc=2;
        goto initerror;
    }

    /* Write request */
    if (BIO_write(sbio,request,len)<=0 || BIO_flush(sbio) <= 0) {
	rc=3;
	goto initerror;
    }
    /* Read response */
    response=malloc(1024);
    if ( (len=BIO_read(sbio, response, 1024)) <=0 ||
	 BIO_flush(sbio) <= 0 ||
	 strstr(response,"RESPONSE=0")==NULL) {
	rc=5;
	goto initerror;
    }

initerror:
    free(request);
    free(response);

    return rc;
}

int _myproxy_getcerts(BIO *sbio, X509_REQ *req, STACK_OF(X509) **chain) {
    char *response=NULL;
    X509 *tmp_cert = NULL;
    X509 *cert = NULL;
    int rc=0,len,i;
    unsigned char numcerts;

    /* Write request on bio */
    if ( (len=i2d_X509_REQ_bio(sbio,req)<=0) || BIO_flush(sbio) <= 0)  {
	rc=-1;
	goto error;
    }

    /* Read number of certs */
    if ( (len=BIO_read(sbio, &numcerts, sizeof(numcerts)))<=0 ||
	 BIO_flush(sbio) <= 0) {
	rc=-2;
        goto error;
    }

    /* Initialize a new chain */
    if ( (*chain = sk_X509_new_null())==NULL )  {
	rc=-3;
	goto error;
    }
    /* Read it from the bio */
    for (i=0; i<numcerts; i++)	{
        if ( (tmp_cert=d2i_X509_bio(sbio, NULL))==NULL ||
	     BIO_flush(sbio)<=0) {
	    rc=-4;
            goto error;
        }
	sk_X509_push(*chain, tmp_cert);
	tmp_cert=NULL;
    }
    /* Read final response to check everything is ok */
    response=malloc(1024);
    len=BIO_read(sbio, response, 1024);
    if (strstr(response,"RESPONSE=0")==NULL) {
	rc=-5;
	goto error;
    }

    free(response);
    return numcerts;

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


