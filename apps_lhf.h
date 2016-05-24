#include "e_os.h"




#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/lhash.h>
#include <openssl/conf.h>
#include <openssl/txt_db.h>

#include <openssl/engine.h>

#include <openssl/ocsp.h>
#include <openssl/ossl_typ.h>
#include <netdb.h>

#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define INVALID_SOCKET	(-1)





BIO *bio_err;

#define openssl_fdset(a,b) FD_SET(a, b)

#define PW_MIN_LENGTH 4
typedef struct pw_cb_data
	{
	const void *password;
	const char *prompt_info;
	} PW_CB_DATA;

int password_callback(char *buf, int bufsiz, int verify,
	PW_CB_DATA *cb_data);
X509 *load_cert(BIO *err, const char *file, int format,
	const char *pass, ENGINE *e, const char *cert_descrip);
EVP_PKEY *load_key(BIO *err, const char *file, int format, int maybe_stdin,
	const char *pass, ENGINE *e, const char *key_descrip);

STACK_OF(X509) *load_certs(BIO *err, const char *file, int format,
	const char *pass, ENGINE *e, const char *cert_descrip);
STACK_OF(X509_CRL) *load_crls(BIO *err, const char *file, int format,
	const char *pass, ENGINE *e, const char *cert_descrip);


#define FORMAT_ASN1     1
#define FORMAT_TEXT     2
#define FORMAT_PEM      3



int raw_read_stdin(void *,int);
int raw_write_stdout(const void *,int);

