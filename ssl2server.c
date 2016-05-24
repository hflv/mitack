  

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/e_os2.h>
#include <sys/types.h>
#include <openssl/lhash.h>
#include <openssl/bn.h>

#include "apps_lhf.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>

#include <openssl/dh.h>
#include <sys/socket.h>

#include <openssl/rsa.h>


#include <openssl/srp.h>

#include "s_apps_lhf.h"






#define PORT_LHF 433

#define TestCAfile "rootca_cert.pem"
#define ServerCertfile "server_cert.pem"
#define ServerKeyfile "server_key.pem"



#ifdef FIONBIO
	static int s_nbio=0;
#endif

#undef BUFSIZZ
#define BUFSIZZ	16*1024
static int bufsize=BUFSIZZ;
static int accept_socket= -1;
extern int verify_depth, verify_return_error;

static char *cipher="EXP-RC4-MD5";
static int s_server_verify=SSL_VERIFY_NONE;
static int s_server_session_id_context = 1; /* anything will do */
static const *s_cert_file=ServerCertfile,*s_key_file=ServerKeyfile;
static SSL_CTX *ctx=NULL;
#ifndef OPENSSL_NO_ENGINE
static char *engine_id=NULL;
#endif
static int s_quiet=0;
static BIO *bio_s_out=NULL;

#ifndef OPENSSL_NO_ECDH
	char *named_curve = NULL;
#endif


#ifndef OPENSSL_NO_RSA
static RSA MS_CALLBACK *tmp_rsa_cb(SSL *s, int is_export, int keylength);
#endif
static int sv_body(char *hostname, int s, unsigned char *context);
static int init_ssl_connection(SSL *s);
static void print_stats(BIO *bp,SSL_CTX *ctx);
static int generate_session_id(const SSL *ssl, unsigned char *id,
				unsigned int *id_len);
#ifndef OPENSSL_NO_DH
static DH *load_dh_param(const char *dhfile);
static DH *get_dh512(void);
#endif


#ifndef OPENSSL_NO_DH
static unsigned char dh512_p[]={
	0xDA,0x58,0x3C,0x16,0xD9,0x85,0x22,0x89,0xD0,0xE4,0xAF,0x75,
	0x6F,0x4C,0xCA,0x92,0xDD,0x4B,0xE5,0x33,0xB8,0x04,0xFB,0x0F,
	0xED,0x94,0xEF,0x9C,0x8A,0x44,0x03,0xED,0x57,0x46,0x50,0xD3,
	0x69,0x99,0xDB,0x29,0xD7,0x76,0x27,0x6B,0xA2,0xD3,0xD4,0x12,
	0xE2,0x18,0xF4,0xDD,0x1E,0x08,0x4C,0xF6,0xD8,0x00,0x3E,0x7C,
	0x47,0x74,0xE8,0x33,
	};
static unsigned char dh512_g[]={
	0x02,
	};

static DH *get_dh512(void)
	{
	DH *dh=NULL;

	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
	dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		return(NULL);
	return(dh);
	}
#endif


#ifndef OPENSSL_NO_RSA
static RSA MS_CALLBACK *tmp_rsa_cb(SSL *s, int is_export, int keylength)
	{
	BIGNUM *bn = NULL;
	static RSA *rsa_tmp=NULL;

	if (!rsa_tmp && ((bn = BN_new()) == NULL))
		BIO_printf(bio_err,"Allocation error in generating RSA key\n");
	if (!rsa_tmp && bn)
		{
		if (!s_quiet)
			{
			BIO_printf(bio_err,"Generating temp (%d bit) RSA key...",keylength);
			(void)BIO_flush(bio_err);
			}
		if(!BN_set_word(bn, RSA_F4) || ((rsa_tmp = RSA_new()) == NULL) ||
				!RSA_generate_key_ex(rsa_tmp, keylength, bn, NULL))
			{
			if(rsa_tmp) RSA_free(rsa_tmp);
			rsa_tmp = NULL;
			}
		if (!s_quiet)
			{
			BIO_printf(bio_err,"\n");
			(void)BIO_flush(bio_err);
			}
		BN_free(bn);
		}
	return(rsa_tmp);
	}
#endif

int main(int, char **);
int main(int argc, char *argv[])
{
	short port=PORT_LHF;
	char *CApath=NULL,*CAfile=TestCAfile;
	unsigned char *context = NULL;
	int ret=1;
	int off=0;
	int no_tmp_rsa=0,no_dhe=0,no_ecdhe=0,nocert=0;
	int state=0;
	const SSL_METHOD *meth=NULL;
	int socket_type=SOCK_STREAM;
	ENGINE *e=NULL;
	char *inrand=NULL;
	int s_cert_format = FORMAT_PEM, s_key_format = FORMAT_PEM;
	char *passarg = NULL, *pass = "neldtv";
	char *dpassarg = NULL, *dpass = NULL;
	int s_dcert_format = FORMAT_PEM, s_dkey_format = FORMAT_PEM;
	X509 *s_cert = NULL, *s_dcert = NULL;
	EVP_PKEY *s_key = NULL, *s_dkey = NULL;
	int no_cache = 0;



	meth=SSLv2_server_method();
  //meth=TLSv1_server_method();
	if (bio_err == NULL)
		bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	verify_depth=0;
	
	argc--;
	argv++;
	while (argc >= 1)
	{
		if	((strcmp(*argv,"-port") == 0) ||
			 (strcmp(*argv,"-accept") == 0))
			{
			if (--argc < 1) goto end;
			if (!extract_port(*(++argv),&port))
				goto end;
			}
		
		else if	(strcmp(*argv,"-cert") == 0)
			{
			if (--argc < 1) goto end;
			s_cert_file= *(++argv);
			}
		
		else if	(strcmp(*argv,"-key") == 0)
			{
			if (--argc < 1) goto end;
			s_key_file= *(++argv);
			}
		else if	(strcmp(*argv,"-CAfile") == 0)
			{
			if (--argc < 1) goto end;
			CAfile= *(++argv);
			}
		else if	(strcmp(*argv,"-cipher") == 0)
			{
			if (--argc < 1) goto end;
			cipher= *(++argv);
			}
#ifndef OPENSSL_NO_SSL3
		else if	(strcmp(*argv,"-ssl3") == 0)
			{ meth=SSLv3_server_method(); }
#endif
#ifndef OPENSSL_NO_TLS1
		else if	(strcmp(*argv,"-tls1") == 0)
			{ meth=TLSv1_server_method(); }
		else if	(strcmp(*argv,"-tls1_1") == 0)
			{ meth=TLSv1_1_server_method(); }
		else if	(strcmp(*argv,"-tls1_2") == 0)
			{ meth=TLSv1_2_server_method(); }
#endif
		argc--;
		argv++;
		}

	
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();


		s_key = load_key(bio_err, s_key_file, s_key_format, 0, pass, e,
		       "server certificate private key file");
		if (!s_key)
			{
			ERR_print_errors(bio_err);
			goto end;
			}

		s_cert = load_cert(bio_err,s_cert_file,s_cert_format,
			NULL, e, "server certificate file");

		if (!s_cert)
			{
			ERR_print_errors(bio_err);
			goto end;
			}
		if (bio_s_out == NULL)
			bio_s_out=BIO_new_fp(stdout,BIO_NOCLOSE);
		
	printf("lhf:SSL_CTX_new start\n");
	ctx=SSL_CTX_new(meth);
	if (ctx == NULL)
		{
		ERR_print_errors(bio_err);
		goto end;
		}
	SSL_CTX_set_quiet_shutdown(ctx,1);
	SSL_CTX_set_options(ctx,off);//lhf:ssl_lib.c:SSL_CTX_ctrl:cmd=32
	//SSL_CTX_enable_tls_channel_id(ctx);

	SSL_CTX_sess_set_cache_size(ctx,128); 
		if ((!SSL_CTX_load_verify_locations(ctx,CAfile,CApath)) ||
		(!SSL_CTX_set_default_verify_paths(ctx)))
		{
		/* BIO_printf(bio_err,"X509_load_verify_locations\n"); */
		ERR_print_errors(bio_err);
		/* goto end; */
		}

		DH *dh=NULL;
		BIO_printf(bio_s_out,"Using default temp DH parameters\n");
		dh=get_dh512();
		(void)BIO_flush(bio_s_out);
		SSL_CTX_set_tmp_dh(ctx,dh);//lhf:ssl_lib.c:SSL_CTX_ctrl:cmd=3

#ifndef OPENSSL_NO_ECDH
	if (!no_ecdhe)
		{
		EC_KEY *ecdh=NULL;

		BIO_printf(bio_s_out,"Using default temp ECDH parameters\n");
		ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		(void)BIO_flush(bio_s_out);
		SSL_CTX_set_tmp_ecdh(ctx,ecdh);
		EC_KEY_free(ecdh);
		}
#endif
	if (cipher != NULL)
			if(!SSL_CTX_set_cipher_list(ctx,cipher))
				{
				BIO_printf(bio_err,"error setting cipher list\n");
				ERR_print_errors(bio_err);
				goto end;
	}

	if (!set_cert_key_stuff(ctx, s_cert, s_key))
		goto end;


	SSL_CTX_set_tmp_rsa_callback(ctx,tmp_rsa_cb);


	SSL_CTX_set_verify(ctx,s_server_verify,verify_callback);
	SSL_CTX_set_session_id_context(ctx,(void*)&s_server_session_id_context,
		sizeof s_server_session_id_context);

	/* Set DTLS cookie generation and verification callbacks */
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie_callback);
	SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie_callback);
	if (CAfile != NULL)
		{
		SSL_CTX_set_client_CA_list(ctx,SSL_load_client_CA_file(CAfile));
		}
	BIO_printf(bio_s_out,"ACCEPT\n");
	(void)BIO_flush(bio_s_out);
	printf("lhf:s_server.c:do_server start\n");
	do_server(port,socket_type,&accept_socket,sv_body, context);
	print_stats(bio_s_out,ctx);
	ret=0;
	printf("lhf:s_server.c:do_server end\n");
	if(accept_socket>=0)
		close(accept_socket);
	
end:
	if (ctx != NULL) SSL_CTX_free(ctx);
	if (s_cert)
		X509_free(s_cert);
	if (s_dcert)
		X509_free(s_dcert);
	if (s_key)
		EVP_PKEY_free(s_key);
	if (s_dkey)
		EVP_PKEY_free(s_dkey);
	if (pass)
		OPENSSL_free(pass);
	if (dpass)
		OPENSSL_free(dpass);
	if (bio_s_out != NULL)
		{
        BIO_free(bio_s_out);
		bio_s_out=NULL;
		}

	OPENSSL_EXIT(ret);
	
	
}


static void print_stats(BIO *bio, SSL_CTX *ssl_ctx)
	{
	BIO_printf(bio,"%4ld items in the session cache\n",
		SSL_CTX_sess_number(ssl_ctx));
	BIO_printf(bio,"%4ld client connects (SSL_connect())\n",
		SSL_CTX_sess_connect(ssl_ctx));
	BIO_printf(bio,"%4ld client renegotiates (SSL_connect())\n",
		SSL_CTX_sess_connect_renegotiate(ssl_ctx));
	BIO_printf(bio,"%4ld client connects that finished\n",
		SSL_CTX_sess_connect_good(ssl_ctx));
	BIO_printf(bio,"%4ld server accepts (SSL_accept())\n",
		SSL_CTX_sess_accept(ssl_ctx));
	BIO_printf(bio,"%4ld server renegotiates (SSL_accept())\n",
		SSL_CTX_sess_accept_renegotiate(ssl_ctx));
	BIO_printf(bio,"%4ld server accepts that finished\n",
		SSL_CTX_sess_accept_good(ssl_ctx));
	BIO_printf(bio,"%4ld session cache hits\n",SSL_CTX_sess_hits(ssl_ctx));
	BIO_printf(bio,"%4ld session cache misses\n",SSL_CTX_sess_misses(ssl_ctx));
	BIO_printf(bio,"%4ld session cache timeouts\n",SSL_CTX_sess_timeouts(ssl_ctx));
	BIO_printf(bio,"%4ld callback cache hits\n",SSL_CTX_sess_cb_hits(ssl_ctx));
	BIO_printf(bio,"%4ld cache full overflows (%ld allowed)\n",
		SSL_CTX_sess_cache_full(ssl_ctx),
		SSL_CTX_sess_get_cache_size(ssl_ctx));
	}

static int sv_body(char *hostname, int s, unsigned char *context)
{
	
	char *buf=NULL;
	fd_set readfds;
	int ret=1,width;
	int k,i;
	unsigned long l;
	SSL *con=NULL;
	BIO *sbio;

	struct timeval timeout;
	struct timeval *timeoutp;


	if ((buf=OPENSSL_malloc(bufsize)) == NULL)
		{
		BIO_printf(bio_err,"out of memory\n");
		goto err;
		}


	if (con == NULL) {
		con=SSL_new(ctx);
		if(context)
		      SSL_set_session_id_context(con, context,
						 strlen((char *)context));
	}
	SSL_clear(con);	
	sbio=BIO_new_socket(s,BIO_NOCLOSE);
	printf("lhf:s_server.c:BIO_new_socket end\n");
	SSL_set_bio(con,sbio,sbio);
	SSL_set_accept_state(con);
	/* SSL_set_fd(con,s); */
	width=s+1;
	int loop=0;
	for (;;)
		{
		int read_from_terminal;
		int read_from_sslcon;
		printf("-------lhf:s_server:for=%d---------\n",++loop);

		read_from_terminal = 0;
		read_from_sslcon = SSL_pending(con);
		
		if (!read_from_sslcon)
			{
			FD_ZERO(&readfds);
#if !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_NETWARE) && !defined(OPENSSL_SYS_BEOS_R5)
			openssl_fdset(fileno(stdin),&readfds);
#endif
			openssl_fdset(s,&readfds);
			
			timeoutp = NULL;

			i=select(width,(void *)&readfds,NULL,NULL,timeoutp);


			if (i <= 0) continue;
			if (FD_ISSET(fileno(stdin),&readfds))
				read_from_terminal = 1;

			if (FD_ISSET(s,&readfds))
				read_from_sslcon = 1;
			}
	
		if (read_from_terminal)
			{

				printf("1.1 send data to client\n");
				i=raw_read_stdin(buf,bufsize);
				printf("1.2 send data length:%d\n",i-1);
				
			l=k=0;
			for (;;)
				{
				/* should do a select for the write */

				/*raw_read_stdin(buf,bufsize);*/
			

				k=SSL_write(con,&(buf[l]),(unsigned int)i);

				switch (SSL_get_error(con,k))
					{
				case SSL_ERROR_NONE:
					break;
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_X509_LOOKUP:
					BIO_printf(bio_s_out,"Write BLOCK\n");
					break;
				case SSL_ERROR_SYSCALL:
				case SSL_ERROR_SSL:
					BIO_printf(bio_s_out,"ERROR\n");
					ERR_print_errors(bio_err);
					ret=1;
					goto err;
					/* break; */
				case SSL_ERROR_ZERO_RETURN:
					BIO_printf(bio_s_out,"DONE\n");
					ret=1;
					goto err;
					}
				l+=k;
				i-=k;
				if (i <= 0) break;
				}
			}
		
		if (read_from_sslcon)
			{
			if (!SSL_is_init_finished(con))
				{
				printf("lhf:s_server:init_ssl_connection start\n");
				i=init_ssl_connection(con);
				printf("lhf:s_server:init_ssl_connection end ret=%d\n",i);
				
				if (i < 0)
					{
					ret=0;
					goto err;
					}
				else if (i == 0)
					{
					ret=1;
					goto err;
					}
				}
			else
				{
again:	
				printf("2.1 accept data from client\n");
				i=SSL_read(con,(char *)buf,bufsize);
				printf("2.2 accept length:%d\n",i-1);

				switch (SSL_get_error(con,i))
					{
				case SSL_ERROR_NONE:
					printf("2.3 display data from client:%d\n",i);

					raw_write_stdout(buf,(unsigned int)i);
					if (SSL_pending(con)) goto again;
					break;
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
					BIO_printf(bio_s_out,"Read BLOCK\n");
					break;
				case SSL_ERROR_SYSCALL:
				case SSL_ERROR_SSL:
					BIO_printf(bio_s_out,"ERROR\n");
					ERR_print_errors(bio_err);
					ret=1;
					goto err;
				case SSL_ERROR_ZERO_RETURN:
					BIO_printf(bio_s_out,"DONE\n");
					ret=1;
					goto err;
					}
				}
			}
		printf("--------lhf:s_server:end for=%d----------\n",loop);
		}
err:
	if (con != NULL)
		{
		BIO_printf(bio_s_out,"shutting down SSL\n");
#if 1
		SSL_set_shutdown(con,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
#else
		SSL_shutdown(con);
#endif
		SSL_free(con);
		}
	BIO_printf(bio_s_out,"CONNECTION CLOSED\n");
	if (buf != NULL)
		{
		OPENSSL_cleanse(buf,bufsize);
		OPENSSL_free(buf);
		}
	if (ret >= 0)
		BIO_printf(bio_s_out,"ACCEPT\n");
	return(ret);
	
	
}

static int init_ssl_connection(SSL *con)
{
	
	int i;
	const char *str;
	X509 *peer;
	long verify_error;
	MS_STATIC char buf[BUFSIZ];

	i=SSL_accept(con);
	printf("lhf:s_server:SSL_accept return=%d\n",i);
	if (i <= 0)
		{
		if (BIO_sock_should_retry(i))
			{
			BIO_printf(bio_s_out,"DELAY\n");
			return(1);
			}

		BIO_printf(bio_err,"ERROR\n");
		verify_error=SSL_get_verify_result(con);
		if (verify_error != X509_V_OK)
			{
			BIO_printf(bio_err,"verify error:%s\n",
				X509_verify_cert_error_string(verify_error));
			}
		else
			ERR_print_errors(bio_err);
		return(0);
		}

	PEM_write_bio_SSL_SESSION(bio_s_out,SSL_get_session(con));

	peer=SSL_get_peer_certificate(con);
	if (peer != NULL)
		{
		BIO_printf(bio_s_out,"Client certificate\n");
		PEM_write_bio_X509(bio_s_out,peer);
		X509_NAME_oneline(X509_get_subject_name(peer),buf,sizeof buf);
		BIO_printf(bio_s_out,"subject=%s\n",buf);
		X509_NAME_oneline(X509_get_issuer_name(peer),buf,sizeof buf);
		BIO_printf(bio_s_out,"issuer=%s\n",buf);
		X509_free(peer);
		}

	if (SSL_get_shared_ciphers(con,buf,sizeof buf) != NULL)
		BIO_printf(bio_s_out,"Shared ciphers:%s\n",buf);
	str=SSL_CIPHER_get_name(SSL_get_current_cipher(con));
	BIO_printf(bio_s_out,"CIPHER is %s\n",(str != NULL)?str:"(NONE)");


	BIO_printf(bio_s_out, "Secure Renegotiation IS%s supported\n",
		      SSL_get_secure_renegotiation_support(con) ? "" : " NOT");
	return(1);
	
	
}

