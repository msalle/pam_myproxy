#include <stdio.h>

#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/x509v3.h>

#include "myproxy_ssl_utils.h"

#define SERVER		"px.grid.sara.nl"
#define PORT		7512
/*#define SERVER		"localhost"
#define PORT		4433*/
/*#define SERVER		"www.nikhef.nl"
#define PORT		443*/

int main(int argc, char *argv[])    {
    char *user=NULL;
    char *pass="";
    int life=43200;

    X509_REQ *req;
    EVP_PKEY *pk;

    unsigned char numcerts;
    X509 *cert;
    STACK_OF(X509) *chain;

    char *buffer;
    int buflen,len;
    int rc;

//    certinfo_t certinfo={NULL,"/etc/grid-security/certificates",NULL,NULL};
    certinfo_t certinfo={NULL,NULL,NULL,NULL};
//    certinfo_t certinfo={NULL,"/home/salle/server/demoCA",NULL,NULL};
    BIO *bio;

    if (argc<2)	{
	fprintf(stderr,"Usage: %s <dn>\n",argv[0]);
	return 1;
    }
    user=argv[1];
    pass=getpass("Enter myproxy password: ");

    if (_getcsr(&req, &pk, 1024, user))  {
	fprintf(stderr,"Could not create csr\n");
	goto error;
    }

    if ( (bio=_connect_ssl(SERVER, PORT,&certinfo))==NULL )    {
	fprintf(stderr,"_connect_ssl failed\n");
	goto error;
    }

    if (_myproxy_init(bio, user, pass, life)==1) {
	fprintf(stderr,"Could not initiate myproxy handshake\n");
	goto error;
    }
    
    if ((rc=_myproxy_getcerts(bio, req, &chain))<=0) {
	fprintf(stderr,"Could not get chain: %d\n",rc);
	goto error;
    }

    if ((rc=_write_proxy("/tmp/proxy",pk,chain))<0) {
	fprintf(stderr,"Could not write proxy: %d\n",rc);
	goto error;
    }

    _free_bio(&bio);
    _free_chain_key(&req, &pk, &chain);
    return 0;

error:
    _free_bio(&bio);
    _free_chain_key(&req, &pk, &chain);
    return 1;
}


