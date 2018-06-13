
#include <unistd.h>
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>

static int add_ext(X509* cert, int nid, char* value);

int generate_rsa_key(EVP_PKEY** key_out, int bits) {
	unsigned long e;
	BIGNUM* bn_e;
	RSA* rsa;
	EVP_PKEY* keypair;

	e = RSA_F4;

	bn_e = BN_new();
	if (bn_e == NULL) {
		return 0;
	}
	if (BN_set_word(bn_e, e) != 1) {
		BN_free(bn_e);
		return 0;
	}

	rsa = RSA_new();
	if (rsa == NULL) {
		BN_free(bn_e);
		return 0;
	}
	
	if (RSA_generate_key_ex(rsa, bits, bn_e, NULL) != 1) {
		BN_free(bn_e);
		RSA_free(rsa);
		return 0;
	}

	keypair = EVP_PKEY_new();
	if (keypair == NULL) {
		RSA_free(rsa);
		BN_free(bn_e);
		return 0;
	}

	if (EVP_PKEY_assign_RSA(keypair, rsa) != 1) {
		RSA_free(rsa);
		BN_free(bn_e);
		return 0;
	}

	*key_out = keypair;
	/*RSA_free(rsa); // apparently this gets freed with the key */
	BN_free(bn_e);
	return 1;
}

X509* generate_self_signed_certificate(EVP_PKEY* key, int serial, int days) {
	X509* new_cert;
	X509_NAME* name;
	STACK_OF(X509_EXTENSION)* exts;
	const unsigned char country[] = "US";
	const unsigned char org[] = "SSA";
	const unsigned char cn_name[] = "SSA Client Authentication";

	new_cert = X509_new();
	if (new_cert == NULL) {
		return NULL;
	}

	/* Version */
	X509_set_version(new_cert, 2);
	/* Serial Number */
	ASN1_INTEGER_set(X509_get_serialNumber(new_cert), serial);
	/* Validity dates */
	X509_gmtime_adj(X509_get_notBefore(new_cert), 0);
	X509_gmtime_adj(X509_get_notAfter(new_cert), (long)60 * 60 * 24 * days);

	/* Subject */
	if ((name = X509_get_subject_name(new_cert)) == NULL) {
		return NULL;
	}
	/* Country */
	if (X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
				country, -1, -1, 0) != 1) {
		return NULL;
	}
	/* Organization */
	if (X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
				org, -1, -1, 0) != 1) {
		return NULL;
	}
	/* Common Name */
	if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				cn_name, -1, -1, 0) != 1) {
		return NULL;
	}
	
	/* Issuer */
	X509_set_issuer_name(new_cert, name);

	exts = sk_X509_EXTENSION_new_null();
	if (exts == NULL) {
		return NULL;
	}


	/* Public key */
	if (X509_set_pubkey(new_cert, key) != 1) {
		return NULL;
	}

	/* Extensions */

	/* SAN */
	add_ext(new_cert, NID_subject_alt_name, "email:mto@byu.edu");


	/* Basic constraints */
	add_ext(new_cert, NID_basic_constraints, "critical,CA:FALSE");

	/* Key Usage */
	add_ext(new_cert, NID_key_usage, "critical,digitalSignature,keyEncipherment");

	/* Signature */
	if (X509_sign(new_cert, key, EVP_sha256()) == 0) {
		return NULL;
	}

	return new_cert;

}

int add_ext(X509* cert, int nid, char* value) {
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (ex == NULL) {
		return 0;
	}
	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}
