/*	Copyright (C) 2004  Stefano Frassi  <stefano.frassi@iit.cnr.it>
 *
 *  Third party code:
 *
 *  - RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki)
 *
 *  - The OpenSSL Secure Socket Layer library
 *    Copyright (c) 1998-2003 The OpenSSL Project.  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <iostream>
#include <iterator>

#include <termios.h>

#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include "cryptoki_ext.h"

#define MAX_PATH   1023
#define MAX_PASSWD_SIZE 63
char pkcs12_path_filename[MAX_PATH+1];
char pkcs11dll_path_filename[MAX_PATH+1];
char pkcs12_password[MAX_PASSWD_SIZE + 1];
char pkcs11_token_PIN[MAX_PASSWD_SIZE + 1];

static CK_SESSION_HANDLE		session;

static int loadPkcs12(const char *filename, const char *pkcs12pass, X509  **myCert, EVP_PKEY **privKey);

static int make_pkcs11_objects(unsigned char *cert_value, int scv, unsigned char *cert_sub_val, int lcsv,
			       unsigned char *cert_issuer, int lci, unsigned char *cert_serialnumb, int lsr,
			       unsigned char *pubk_modulus, int lpm, long pubk_modulusbits, 
			       unsigned char *pubk_exponent, int lpe,
			       unsigned char *privk_modulus,int lprm,unsigned char *privk_pubexponent,
			       int lprivpubexp,unsigned char *privk_privexponent,int lprivprivexp,
			       unsigned char *privk_primep,int lprimp,unsigned char *privk_primeq,int lprimq,
			       unsigned char *privk_exponent1,int lpexpo1,unsigned char *privk_exponent2,
			       int lpexpo2,unsigned char *privk_coefficient,int lpcoeff );

static void printError(const char *c)
{
	printf ("%s\n", (c == NULL ? "" : c));
}

static int mainfunction()
{
	int ret = 0;
	X509 *myCert = NULL;		// SO certificate (+ pub key)
	EVP_PKEY *privKey = NULL;	// private key associated to the previous cert

	/********** PKCS#12 loading ***********/
	ret = loadPkcs12(pkcs12_path_filename, pkcs12_password, &myCert, &privKey);
	if (ret == -1) 
	{
		printError("p12import: loadPkcs12 failed!\n");
		return -1;
	}
	
	assert(myCert != NULL);
	assert(privKey != NULL);
	///////////////////////////////////////////////////
	int len;
	unsigned char *cert_value, *p;

	len = i2d_X509(myCert, NULL);

	cert_value = (unsigned char *)malloc(len);

	p = cert_value;

	i2d_X509(myCert, &p);
	if (ERR_peek_error() != 0)
	{
		printf("i2d_X509: %s\n", ERR_error_string(ERR_get_error(), NULL) );
		return -1;
	}
	
	///////////////////////////////////////////////////////////
	X509_NAME *sub_name = X509_get_subject_name(myCert);

	unsigned char *cert_sub_name, *p2;

	int len2 = i2d_X509_NAME(sub_name, NULL);

	cert_sub_name = (unsigned char *)malloc(len2);

	p2 = cert_sub_name;

	i2d_X509_NAME(sub_name, &p2);
	if (ERR_peek_error() != 0)
	{
		printf("i2d_X509_NAME: %s\n", ERR_error_string(ERR_get_error(), NULL) );
		return -1;
	}

	////////////////////////////////////////////////////////////////
	X509_NAME *issuer_name = X509_get_issuer_name(myCert);

	unsigned char *cert_issuer_name, *p3;

	int len3 = i2d_X509_NAME(issuer_name, NULL);

	cert_issuer_name = (unsigned char *)malloc(len3);

	p3 = cert_issuer_name;

	i2d_X509_NAME(issuer_name, &p3);
	if (ERR_peek_error() != 0)
	{
		printf("i2d_X509_NAME: %s\n", ERR_error_string(ERR_get_error(), NULL) );
		return -1;
	}

	////////////////////////////////////////////////////////////////
	ASN1_INTEGER *ser_number = X509_get_serialNumber(myCert);

	unsigned char *cert_ser_number, *p4;

	int len4 = i2d_ASN1_INTEGER(ser_number, NULL);

	cert_ser_number = (unsigned char *)malloc(len4);

	p4 = cert_ser_number;

	i2d_ASN1_INTEGER(ser_number, &p4);
	if (ERR_peek_error() != 0)
	{
		printf("i2d_X509_NAME: %s\n", ERR_error_string(ERR_get_error(), NULL) );
		return -1;
	}
	
	////////////////////////////////////////////////////////////////
	EVP_PKEY *rsapubkey = X509_get_pubkey(myCert);
	RSA *rsapkey = EVP_PKEY_get1_RSA(rsapubkey);

	int lpm=0, lpe=0;

	unsigned char* pubk_modulus = (unsigned char *)malloc ((lpm=BN_num_bytes(rsapkey->n)));
	unsigned char* pubk_exponent = (unsigned char *)malloc ((lpe=BN_num_bytes(rsapkey->e)));

	BN_bn2bin(rsapkey->n, pubk_modulus);
	BN_bn2bin(rsapkey->e, pubk_exponent);

	long pubk_modulusbits = (RSA_size(rsapkey)*8);
	RSA *rsaprivatekey = EVP_PKEY_get1_RSA(privKey);
	int lprm=0, lprivpubexp=0, lprivprivexp=0,lprimp=0,lprimq=0,lpexpo1=0,lpexpo2=0,lpcoeff=0;
	
	unsigned char* privk_modulus = (unsigned char *)malloc ((lprm=BN_num_bytes(rsaprivatekey->n)));
	unsigned char* privk_pubexponent = (unsigned char *)malloc ((lprivpubexp=BN_num_bytes(rsaprivatekey->e)));
	unsigned char* privk_privexponent = (unsigned char *)malloc ((lprivprivexp=BN_num_bytes(rsaprivatekey->d)));
	
	BN_bn2bin(rsaprivatekey->n, privk_modulus);
	BN_bn2bin(rsaprivatekey->e, privk_pubexponent);
	BN_bn2bin(rsaprivatekey->d, privk_privexponent);

	unsigned char* privk_primep = NULL;
	unsigned char* privk_primeq = NULL;
	unsigned char* privk_exponent1 = NULL;
	unsigned char* privk_exponent2 = NULL;
	unsigned char* privk_coefficient = NULL;

	if (rsaprivatekey->p != NULL)
	{
		privk_primep = (unsigned char *)malloc ((lprimp=BN_num_bytes(rsaprivatekey->p)));
		privk_primeq = (unsigned char *)malloc ((lprimq=BN_num_bytes(rsaprivatekey->q)));
		privk_exponent1 = (unsigned char *)malloc ((lpexpo1=BN_num_bytes(rsaprivatekey->dmp1)));
		privk_exponent2 = (unsigned char *)malloc ((lpexpo2=BN_num_bytes(rsaprivatekey->dmq1)));
		privk_coefficient = (unsigned char *)malloc ((lpcoeff=BN_num_bytes(rsaprivatekey->iqmp)));

		BN_bn2bin(rsaprivatekey->p, privk_primep);
		BN_bn2bin(rsaprivatekey->q, privk_primeq);
		BN_bn2bin(rsaprivatekey->dmp1, privk_exponent1);
		BN_bn2bin(rsaprivatekey->dmq1, privk_exponent2);
		BN_bn2bin(rsaprivatekey->iqmp, privk_coefficient);
	}

	////////////////////////////////////////////////////////////
	ret = make_pkcs11_objects(cert_value, len, cert_sub_name, len2,
				  cert_issuer_name,len3, cert_ser_number, len4,
				  pubk_modulus, lpm, pubk_modulusbits, pubk_exponent, lpe,
				  privk_modulus,lprm,privk_pubexponent,lprivpubexp,privk_privexponent,lprivprivexp,
				  privk_primep,lprimp,privk_primeq,lprimq,privk_exponent1,lpexpo1,
				  privk_exponent2,lpexpo2,privk_coefficient,lpcoeff);
	
	///////////////////////////////////////////////////////////
	X509_free((X509 *)myCert);
	EVP_PKEY_free((EVP_PKEY *)privKey);
	if (ERR_peek_error() != 0)
	{
		printf("InitializeLib: %s\n", ERR_error_string(ERR_get_error(), NULL) );
		return -1;
	}
	EVP_cleanup();
	if (ERR_peek_error() != 0)
	{
		printf("FinalizeLib: %s\n", ERR_error_string(ERR_get_error(), NULL) );
		return -1;
	}
	
	free(cert_value);
	free(cert_sub_name);
	free(cert_issuer_name);
	free(cert_ser_number);
	free(pubk_modulus);
	free(pubk_exponent);
	free(privk_modulus);
	free(privk_pubexponent);
	free(privk_privexponent);
	free(privk_primep);
	free(privk_primeq);
	free(privk_exponent1);
	free(privk_exponent2);
	free(privk_coefficient);

	return ret;
}



/****************************************************************************	
	
 ****************************************************************************/
static int loadPkcs12(const char *filename, const char *pkcs12pass, X509  **myCert, EVP_PKEY **privKey)
{
	FILE *fp;
	PKCS12 *p12=NULL;
	EVP_PKEY *pkey;
	X509 *cert;
	
	unsigned char buf[10000];
	const unsigned char *p;
	int len;

	OpenSSL_add_all_algorithms();	// I add them all (is slower ?)
	ERR_load_ERR_strings();			// I'm not sure if it's necessary
	if (ERR_peek_error() != 0)
	{
		printf("InitializeLib: %s\n", ERR_error_string(ERR_get_error(), NULL) );
		return -1;
	}
	
	
	fp = fopen(filename,"rb");
	if (fp == NULL)
	{
		perror("loadPkcs12");
		return -1;
	}
	
	len = fread(buf, 1, 10000, fp);
	p = buf;
	
	p12 = d2i_PKCS12(NULL, &p, len);   //if (! d2i_PKCS12_fp(fp, &p12) )
	if (p12 == NULL)
	{
		if (ERR_peek_error() != 0)
		{
			printf("loadPkcs12: %s\n", ERR_error_string(ERR_get_error(), NULL) );
			return -1;
		}
	}
	
	PKCS12_parse(p12, pkcs12pass, &pkey, &cert, NULL); 	/* CAs not wanted */
	if (ERR_peek_error() != 0)
	{
		printf("loadPkcs12: %s\n", ERR_error_string(ERR_get_error(), NULL) );
		char errstr[100] = {0};
		sprintf(errstr, "loadPkcs12: %s\n", ERR_error_string(ERR_get_error(), NULL) );
		printError(errstr);
		return -1;
	}
	
	PKCS12_free(p12);
	if (ERR_peek_error() != 0)
	{
		printf("loadPkcs12: %s\n", ERR_error_string(ERR_get_error(), NULL) );
		return -1;
	}
		
	*myCert = cert; 
	*privKey = pkey;

	return 0;

}

#define AUTH_ID "jinshaohui_auth_tool"
#define AUTH_LABEL "jinshaohui Tech LTD"

static int makeCertificate(unsigned char *cert_value, int scv, unsigned char *cert_sub_val, int lcsv,
			    unsigned char *cert_issuer, int lci, unsigned char *cert_serialnumb, int lsr)
{
	CK_RV rv;
	// setup a PKCS #11 attribute list for constructing the
	// public user information we will put on the crypto Token
	//
	CK_OBJECT_CLASS  class_data    = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_CHAR label[] = AUTH_LABEL;
	CK_BYTE id[] = {AUTH_ID};
	
	// label and id are the same for cert, kpub, kpriv

	CK_BBOOL         bFalse = 0;
	CK_BBOOL         bTrue = 1;
	
	
	CK_OBJECT_HANDLE h;
	
	CK_ATTRIBUTE certTemplate[] = 
	{
		{ CKA_CLASS,		&class_data,	sizeof (class_data) },
		{ CKA_TOKEN,		&bTrue,			sizeof (bTrue) },
		{ CKA_PRIVATE,		&bFalse,		sizeof (bFalse) },
		{ CKA_MODIFIABLE,	&bTrue,			sizeof (bTrue) },
		{ CKA_LABEL,		label,			sizeof (label) },		// to change...

		{ CKA_CERTIFICATE_TYPE,	&certType,	sizeof (certType) },
		
		{ CKA_SUBJECT,		cert_sub_val,			lcsv },	
		{ CKA_ID,			id,						sizeof (id) },	// to change...
		{ CKA_ISSUER,		cert_issuer,			lci },  
		{ CKA_SERIAL_NUMBER,	cert_serialnumb,	lsr },			
		{ CKA_VALUE,		cert_value,		scv } 
		
	};
	
	
	if (CKR_OK != (rv = C_CreateObject (session, certTemplate, 11, &h)))
	{
		
		printError("Can not create object on token.\n");
		return -1;
	}
	
	return 0;
}


static int makePublicKey(unsigned char *cert_sub_val, int lcsv, 
			  unsigned char *modulus, int lm, 
			  CK_ULONG modulus_bits, unsigned char *public_exponent, int lpe)
{
	CK_RV rv;
	// setup a PKCS #11 attribute list for constructing the
	// public user information we will put on the crypto Token
	//
	CK_OBJECT_CLASS  class_data    = CKO_PUBLIC_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_CHAR label[] = AUTH_LABEL;
	CK_BYTE id[] = {AUTH_ID};
	// label and id are the same for cert, kpub, kpriv

	CK_BBOOL         bFalse = 0;
	CK_BBOOL         bTrue = 1;
	
	
	CK_OBJECT_HANDLE h;
	
	CK_ATTRIBUTE pubkeyTemplate[] = 
	{
		{ CKA_CLASS,		&class_data,	sizeof (class_data) },
		{ CKA_TOKEN,		&bTrue,			sizeof (bTrue) },
		{ CKA_PRIVATE,		&bFalse,		sizeof (bFalse) },
		{ CKA_MODIFIABLE,	&bTrue,			sizeof (bTrue) },
		{ CKA_LABEL,		label,			sizeof (label) },		// to change...

		{ CKA_KEY_TYPE,		&keyType,		sizeof (keyType) },
		{ CKA_ID,		id,			sizeof (id) },			// to change...
		{ CKA_DERIVE,		&bTrue,			sizeof (bTrue) },
		
		{ CKA_SUBJECT,		cert_sub_val,			lcsv },	
		{ CKA_ENCRYPT,		&bTrue,			sizeof (bTrue) },
		{ CKA_VERIFY,		&bTrue,			sizeof (bTrue) },
		{ CKA_VERIFY_RECOVER,	&bTrue,		sizeof (bTrue) },
		{ CKA_WRAP,			&bTrue,			sizeof (bTrue) },
		
		{ CKA_MODULUS,			modulus,			lm },
		{ CKA_PUBLIC_EXPONENT,	public_exponent,	lpe } 
		
	};
	
	
	if (CKR_OK != (rv = C_CreateObject (session, pubkeyTemplate, 15, &h)))
	{
		printError("Can not create object on token.\n");
		return -1;
	}
	
	
	return 0;
}


static int makePrivateKey(unsigned char *cert_sub_val, int lcsv, 
				   unsigned char *privk_modulus,int lprm,unsigned char *privk_pubexponent,
					 int lprivpubexp,unsigned char *privk_privexponent,int lprivprivexp,
					 unsigned char *privk_primep,int lprimp,unsigned char *privk_primeq,int lprimq,
					 unsigned char *privk_exponent1,int lpexpo1,unsigned char *privk_exponent2,
					 int lpexpo2,unsigned char *privk_coefficient,int lpcoeff )
{
	CK_RV rv;
	// setup a PKCS #11 attribute list for constructing the
	// public user information we will put on the crypto Token
	//
	CK_OBJECT_CLASS  class_data    = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_CHAR label[] = AUTH_LABEL;
	CK_BYTE id[] = {AUTH_ID};

	// label and id are the same for cert, kpub, kpriv

	CK_BBOOL         bFalse = 0;
	CK_BBOOL         bTrue = 1;
	
	
	CK_OBJECT_HANDLE h;
	
	CK_ATTRIBUTE privkeyTemplate[] = 
	{
		{ CKA_CLASS,		&class_data,	sizeof (class_data) },
		{ CKA_TOKEN,		&bTrue,			sizeof (bTrue) },
		{ CKA_PRIVATE,		&bTrue,			sizeof (bTrue) },
		{ CKA_MODIFIABLE,	&bTrue,			sizeof (bTrue) },
		{ CKA_LABEL,		label,			sizeof (label) },		// to change...

		{ CKA_KEY_TYPE,		&keyType,		sizeof (keyType) },
		{ CKA_ID,		id,			sizeof (id) },			// to change...
		{ CKA_DERIVE,		&bFalse,		sizeof (bFalse) },
		
		{ CKA_SUBJECT,		cert_sub_val,			lcsv },	
		{ CKA_SENSITIVE,	&bTrue,			sizeof (bTrue) },
		{ CKA_DECRYPT,		&bTrue,			sizeof (bTrue) },
		{ CKA_SIGN,			&bTrue,			sizeof (bTrue) },
		{ CKA_SIGN_RECOVER,	&bFalse,		sizeof (bFalse) },
		{ CKA_UNWRAP,		&bFalse,		sizeof (bFalse) },
		{ CKA_EXTRACTABLE,	&bFalse,		sizeof (bFalse) },
		
		{ CKA_MODULUS,			privk_modulus,			lprm },  
		{ CKA_PUBLIC_EXPONENT,	privk_pubexponent,		lprivpubexp }, 
		{ CKA_PRIVATE_EXPONENT,	privk_privexponent,		lprivprivexp }, 
		// these may be NULL
		{ CKA_PRIME_1,			privk_primep,			lprimp }, 
		{ CKA_PRIME_2,			privk_primeq,			lprimq }, 
		{ CKA_EXPONENT_1,		privk_exponent1,		lpexpo1 }, 
		{ CKA_EXPONENT_2,		privk_exponent2,		lpexpo2 }, 
		{ CKA_COEFFICIENT,		privk_coefficient,		lpcoeff } 
		
	};
	
	
	if (privk_primep != NULL)
	{
		if (CKR_OK != (rv = C_CreateObject (session, privkeyTemplate, 23, &h)))
		{
			printError("Can not create object on token.\n");
			return -1;
		}
	}
	else
	{
		if (CKR_OK != (rv = C_CreateObject (session, privkeyTemplate, 18, &h)))
		{
			printError("Can not create object on token.\n");
			return -1;
		}
	}
	
	
	return 0;
}

static int delete_cert_kpriv_kpub()	
{
	CK_RV rv;
	CK_OBJECT_HANDLE h;
	CK_ULONG objcount;
	
	static CK_CHAR   user_object[] = { "una prova" }; //parameterize

	CK_ATTRIBUTE user[] = 
	{
		
		{ CKA_LABEL,        user_object,    sizeof (user_object) },
			
	};

	
	rv = C_FindObjectsInit(session, user, 1);
	if (rv != CKR_OK)
	{
		printError("C_FindObjectsInit errore.\n");
		return -1;
	}
	
	while (1) //deleting all objects with the previous declarated label
	{
		rv = C_FindObjects(session, &h, 1, &objcount);
		if (rv != CKR_OK)
		{
			printError("C_FindObjects errore.\n");
			return -1;
		}
		if (objcount == 0) break;
		
		//printf("object found - deleting...\n");

		rv = C_DestroyObject(session, h);
		if (rv != CKR_OK)
		{
			printError("C_DestroyObject errore.\n");
			return -1;
		}
		
	}
	
	rv = C_FindObjectsFinal(session);
	if (rv != CKR_OK)
	{
		printError("C_FindObjectsInit errore.\n");
		return -1;
	}

	
	return 0;
}


static int make_pkcs11_objects(unsigned char *cert_value, int scv, unsigned char *cert_sub_val, int lcsv,
			unsigned char *cert_issuer, int lci, unsigned char *cert_serialnumb, int lsr,
			unsigned char *pubk_modulus, int lpm, long pubk_modulusbits, 
			unsigned char *pubk_exponent, int lpe,
			unsigned char *privk_modulus,int lprm,unsigned char *privk_pubexponent,
			int lprivpubexp,unsigned char *privk_privexponent,int lprivprivexp,
			unsigned char *privk_primep,int lprimp,unsigned char *privk_primeq,int lprimq,
			unsigned char *privk_exponent1,int lpexpo1,unsigned char *privk_exponent2,
			int lpexpo2,unsigned char *privk_coefficient,int lpcoeff )
{
	
	
	CK_C_GetFunctionList   pGFL  = 0;
	CK_RV                  rv;
	
	unsigned long slot_count = 100;
	CK_SLOT_ID slots[100];
	
	//Load PKCS#11 library
#if 0
	HINSTANCE hLib = LoadLibrary(pkcs11dll_path_filename);
	if (hLib == NULL)
	{
		printError("Cannot load DLL");
		return -1;
	}
	
	//Find the entry point.
	pGFL = (CK_C_GetFunctionList) GetProcAddress(hLib, "C_GetFunctionList");
	if (pGFL == NULL) 
	{
		printError("Cannot find GetFunctionList().");
		return -1;
	}
	
	rv = pGFL(&m_pFunctionList);
	if(rv != CKR_OK)
	{
		printError("Can't get function list. \n");
		return -1;
	}
#endif	
	//Initialize PKCS#11 library
	rv = C_Initialize(0); 
	if (CKR_OK != rv )
	{
		printError("C_Initialize failed...\n");
		return -1;
	}   
	
	//get all the occupied slots
	if (CKR_OK != C_GetSlotList(TRUE, slots, &slot_count))
	{
		printError("C_GetSlotList failed...\n");
		return -1;
	}                       
	
	if (slot_count < 1)
	{
		printError("No Token is available.\n");
		return -1;
	}
	
	//open a read/write session on the Token so we can write information to it
	if (CKR_OK != C_OpenSession(slots[0],(CKF_SERIAL_SESSION | CKF_RW_SESSION), 0, 0, &session))
	{
		printError("C_OpenSession failed...\n");
		return -1;
	}                       
	
	if (CKR_OK != (rv = C_Login(session, CKU_USER, (unsigned char *)pkcs11_token_PIN, strlen((const char *)pkcs11_token_PIN))))
	{
		C_CloseSession(session);
		printError("C_Login failed. \n");
		return -1;
	}
	
	{
		int retv = 0;
		//remove previously stored cert, privk, pubk
#if 0
		retv = delete_cert_kpriv_kpub();
		if (retv != 0) printError("delete_cert_kpriv_kpub failed. \n");
#endif				
		retv = makeCertificate(cert_value,  scv, cert_sub_val,  lcsv,
								cert_issuer,  lci, cert_serialnumb,  lsr);
		if (retv != 0) printError("makeCertificate failed. \n");
		
		retv = makePublicKey(cert_sub_val,  lcsv, pubk_modulus, lpm, 
								pubk_modulusbits, pubk_exponent, lpe);
		if (retv != 0) printError("makePublicKey failed. \n");
		
		retv = makePrivateKey(cert_sub_val, lcsv,
								privk_modulus, lprm,
								privk_pubexponent,lprivpubexp,
								privk_privexponent, lprivprivexp,
								privk_primep, lprimp,
								privk_primeq, lprimq,
								privk_exponent1, lpexpo1,
								privk_exponent2, lpexpo2,
								privk_coefficient, lpcoeff );
		if (retv != 0) printError("makePrivateKey failed. \n");
			
	}
	
	//logout from the Token
	C_Logout(session);
		
	//close PKCS#11 library
	C_Finalize(0);
	
	return 0;
}

static void set_stdin_echo(bool enable = true)
{
#ifdef WIN32
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
	DWORD mode;
	GetConsoleMode(hStdin, &mode);
	
	if( !enable )
		mode &= ~ENABLE_ECHO_INPUT;
	else
		mode |= ENABLE_ECHO_INPUT;
	
	SetConsoleMode(hStdin, mode );
	
#else
	struct termios tty;
	tcgetattr(STDIN_FILENO, &tty);
	if( !enable )
		tty.c_lflag &= ~ECHO;
	else
		tty.c_lflag |= ECHO;
	
	(void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

int main(int argv, char ** argc)
{
	memset(pkcs12_path_filename, 0, MAX_PATH+1);
	memset(pkcs12_password, 0, MAX_PASSWD_SIZE + 1);
	memset(pkcs11_token_PIN, 0, MAX_PASSWD_SIZE + 1);

	
	if(argv < 2){
		std::cout << "USAGE:" << std::endl;
		std::cout << "\t importcert CERTIFICATE_FILE_NAME" << std::endl;
		return 1;
	}

	set_stdin_echo(false);

	std::string pin;
	std::cout << "Please input the PIN of the UKEY" << std::endl ;
	std::cin >> pin;
	
	//std::cout << pin << std::endl;

	std::string passwd ;
	std::cout << "Please input the password of the certificate" << std::endl ;
	std::cin >> passwd;
	
	//std::cout << passwd << std::endl;
	set_stdin_echo();

	if(strlen(argc[1]) > MAX_PATH){
		printf("The file name of the certificate file is too long.Writing certificate file failed\n");
		return 1;
	}
	
	if(passwd.length() > MAX_PASSWD_SIZE){
		printf("The password for the certificate file is too long.\n");
		return 1;
	}

	if(pin.length() > MAX_PASSWD_SIZE){
		printf("The pin for the ukey is too long.\n");
		return 1;
	}
	
	sprintf(pkcs12_path_filename, "%s", argc[1]);
	sprintf(pkcs12_password, "%s", passwd.c_str());
	sprintf(pkcs11_token_PIN, "%s", pin.c_str());

	printf("Begin to write the certificate into the ukey. Please wait ...\n");
	
	if(0 == mainfunction()){
		printf("The certificate (%s) was successfully written into the ukey.\n", argc[1]);
	}else{
		printf("Sorry! The certificate (%s) cann't be written into the ukey.\n", argc[1]);
	}
	
	return 0 ;
}
