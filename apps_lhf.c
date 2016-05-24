


#include <stdio.h>
#include <stdlib.h>
#include <string.h>



#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>

#include <openssl/engine.h>


#include <openssl/rsa.h>

#include <openssl/bn.h>

#include "apps_lhf.h"


static UI_METHOD *ui_method = NULL;
//define fileno(a) (int)_fileno(a)

int str2fmt(char *s)
	{
	
	if 	((*s == 'D') || (*s == 'd'))
		return(FORMAT_ASN1);
	else if((*s == 'p') || (*s == 'P'))
  			return(FORMAT_PEM);
 		}
	


int password_callback(char *buf, int bufsiz, int verify,
	PW_CB_DATA *cb_tmp)
	{
	UI *ui = NULL;
	int res = 0;
	const char *prompt_info = NULL;
	const char *password = NULL;
	PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

	if (cb_data)
		{
		if (cb_data->password)
			password = cb_data->password;
		if (cb_data->prompt_info)
			prompt_info = cb_data->prompt_info;
		}

	if (password)
		{
		res = strlen(password);
		if (res > bufsiz)
			res = bufsiz;
		memcpy(buf, password, res);
		return res;
		}

	ui = UI_new_method(ui_method);
	if (ui)
		{
		int ok = 0;
		char *buff = NULL;
		int ui_flags = 0;
		char *prompt = NULL;

		prompt = UI_construct_prompt(ui, "pass phrase",
			prompt_info);

		ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
		UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

		if (ok >= 0)
			ok = UI_add_input_string(ui,prompt,ui_flags,buf,
				PW_MIN_LENGTH,bufsiz-1);
		if (ok >= 0 && verify)
			{
			buff = (char *)OPENSSL_malloc(bufsiz);
			ok = UI_add_verify_string(ui,prompt,ui_flags,buff,
				PW_MIN_LENGTH,bufsiz-1, buf);
			}
		if (ok >= 0)
			do
				{
				ok = UI_process(ui);
				}
			while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

		if (buff)
			{
			OPENSSL_cleanse(buff,(unsigned int)bufsiz);
			OPENSSL_free(buff);
			}

		if (ok >= 0)
			res = strlen(buf);
		if (ok == -1)
			{
			BIO_printf(bio_err, "User interface error\n");
			ERR_print_errors(bio_err);
			OPENSSL_cleanse(buf,(unsigned int)bufsiz);
			res = 0;
			}
		if (ok == -2)
			{
			BIO_printf(bio_err,"aborted!\n");
			OPENSSL_cleanse(buf,(unsigned int)bufsiz);
			res = 0;
			}
		UI_free(ui);
		OPENSSL_free(prompt);
		}
	return res;
	}

X509 *load_cert(BIO *err, const char *file, int format,
	const char *pass, ENGINE *e, const char *cert_descrip)
	{
	X509 *x=NULL;
	BIO *cert;

	if ((cert=BIO_new(BIO_s_file())) == NULL)
		{
		ERR_print_errors(err);
		goto end;
		}

		if (BIO_read_filename(cert,file) <= 0)
			{
			BIO_printf(err, "Error opening %s %s\n",
				cert_descrip, file);
			ERR_print_errors(err);
			goto end;
			}
		

	if 	(format == FORMAT_ASN1)
		x=d2i_X509_bio(cert,NULL);
	else if (format == FORMAT_PEM)
		x=PEM_read_bio_X509_AUX(cert,NULL,
			(pem_password_cb *)password_callback, NULL);
	else	{
		BIO_printf(err,"bad input format specified for %s\n",
			cert_descrip);
		goto end;
		}
end:
	if (x == NULL)
		{
		BIO_printf(err,"unable to load certificate\n");
		ERR_print_errors(err);
		}
	if (cert != NULL) BIO_free(cert);
	return(x);
	}

EVP_PKEY *load_key(BIO *err, const char *file, int format, int maybe_stdin,
	const char *pass, ENGINE *e, const char *key_descrip)
	{
	BIO *key=NULL;
	EVP_PKEY *pkey=NULL;
	PW_CB_DATA cb_data;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	key=BIO_new(BIO_s_file());
	if (key == NULL)
		{
		ERR_print_errors(err);
		goto end;
		}

		if (BIO_read_filename(key,file) <= 0)
			{
			BIO_printf(err, "Error opening %s %s\n",
				key_descrip, file);
			ERR_print_errors(err);
			goto end;
			}
	if (format == FORMAT_ASN1)
		{
		pkey=d2i_PrivateKey_bio(key, NULL);
		}
	else if (format == FORMAT_PEM)
		{
		pkey=PEM_read_bio_PrivateKey(key,NULL,
			(pem_password_cb *)password_callback, &cb_data);
		}
	else
		{
		BIO_printf(err,"bad input format specified for key file\n");
		goto end;
		}
 end:
	if (key != NULL) BIO_free(key);
	if (pkey == NULL) 
		{
		BIO_printf(err,"unable to load %s\n", key_descrip);
		ERR_print_errors(err);
		}	
	return(pkey);
	}

EVP_PKEY *load_pubkey(BIO *err, const char *file, int format, int maybe_stdin,
	const char *pass, ENGINE *e, const char *key_descrip)
	{
	BIO *key=NULL;
	EVP_PKEY *pkey=NULL;
	PW_CB_DATA cb_data;

	cb_data.password = pass;
	cb_data.prompt_info = file;



	key=BIO_new(BIO_s_file());
	if (key == NULL)
		{
		ERR_print_errors(err);
		goto end;
		}
	if (file == NULL && maybe_stdin)
		{
		BIO_set_fp(key,stdin,BIO_NOCLOSE);
		}
	else
		if (BIO_read_filename(key,file) <= 0)
			{
			BIO_printf(err, "Error opening %s %s\n",
				key_descrip, file);
			ERR_print_errors(err);
			goto end;
		}
	if (format == FORMAT_ASN1)
		{
		pkey=d2i_PUBKEY_bio(key, NULL);
		}
	else if (format == FORMAT_PEM)
		{
		pkey=PEM_read_bio_PUBKEY(key,NULL,
			(pem_password_cb *)password_callback, &cb_data);
		}	else
		{
		BIO_printf(err,"bad input format specified for key file\n");
		goto end;
		}
 end:
	if (key != NULL) BIO_free(key);
	if (pkey == NULL)
		BIO_printf(err,"unable to load %s\n", key_descrip);
	return(pkey);
	}



static int load_certs_crls(BIO *err, const char *file, int format,
	const char *pass, ENGINE *e, const char *desc,
	STACK_OF(X509) **pcerts, STACK_OF(X509_CRL) **pcrls)
	{
	int i;
	BIO *bio;
	STACK_OF(X509_INFO) *xis = NULL;
	X509_INFO *xi;
	PW_CB_DATA cb_data;
	int rv = 0;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	if (format != FORMAT_PEM)
		{
		BIO_printf(err,"bad input format specified for %s\n", desc);
		return 0;
		}

	if (file == NULL)
		bio = BIO_new_fp(stdin,BIO_NOCLOSE);
	else
		bio = BIO_new_file(file, "r");

	if (bio == NULL)
		{
		BIO_printf(err, "Error opening %s %s\n",
				desc, file ? file : "stdin");
		ERR_print_errors(err);
		return 0;
		}

	xis = PEM_X509_INFO_read_bio(bio, NULL,
				(pem_password_cb *)password_callback, &cb_data);

	BIO_free(bio);

	if (pcerts)
		{
		*pcerts = sk_X509_new_null();
		if (!*pcerts)
			goto end;
		}

	if (pcrls)
		{
		*pcrls = sk_X509_CRL_new_null();
		if (!*pcrls)
			goto end;
		}

	for(i = 0; i < sk_X509_INFO_num(xis); i++)
		{
		xi = sk_X509_INFO_value (xis, i);
		if (xi->x509 && pcerts)
			{
			if (!sk_X509_push(*pcerts, xi->x509))
				goto end;
			xi->x509 = NULL;
			}
		if (xi->crl && pcrls)
			{
			if (!sk_X509_CRL_push(*pcrls, xi->crl))
				goto end;
			xi->crl = NULL;
			}
		}

	if (pcerts && sk_X509_num(*pcerts) > 0)
		rv = 1;

	if (pcrls && sk_X509_CRL_num(*pcrls) > 0)
		rv = 1;

	end:

	if (xis)
		sk_X509_INFO_pop_free(xis, X509_INFO_free);

	if (rv == 0)
		{
		if (pcerts)
			{
			sk_X509_pop_free(*pcerts, X509_free);
			*pcerts = NULL;
			}
		if (pcrls)
			{
			sk_X509_CRL_pop_free(*pcrls, X509_CRL_free);
			*pcrls = NULL;
			}
		BIO_printf(err,"unable to load %s\n",
				pcerts ? "certificates" : "CRLs");
		ERR_print_errors(err);
		}
	return rv;
	}

STACK_OF(X509) *load_certs(BIO *err, const char *file, int format,
	const char *pass, ENGINE *e, const char *desc)
	{
	STACK_OF(X509) *certs;
	if (!load_certs_crls(err, file, format, pass, e, desc, &certs, NULL))
		return NULL;
	return certs;
	}	

STACK_OF(X509_CRL) *load_crls(BIO *err, const char *file, int format,
	const char *pass, ENGINE *e, const char *desc)
	{
	STACK_OF(X509_CRL) *crls;
	if (!load_certs_crls(err, file, format, pass, e, desc, NULL, &crls))
		return NULL;
	return crls;
	}	


int raw_read_stdin(void *buf,int siz)
	{	return read(fileno(stdin),buf,siz);	}
int raw_write_stdout(const void *buf,int siz)
	{	return write(fileno(stdout),buf,siz);	}

