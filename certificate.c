#include <string.h>

#include "error.h"
#include "log.h"
#include "certificate.h"

/**
 * Check if null terminated string ends with ".pem".
 * @param path String to check for ".pem".
 * @return 1 if last four chars are ".pem", else 0.
 */
int is_pem_file(char* path) {
	int len = strlen(path);
	int pem_len = 4;
	if(len < pem_len)
		return 0;

	char* type = &path[len - pem_len];
	if(strcmp(type, ".pem") == 0) 
		return 1;
	else
		return 0;
}

/**
 * Searches cert_list for the certificate that isn't a CA (the end entity).
 * If a certificate is not a CA, it is assumed to be the end entity. 
 * @param cert_list Array of certificates to search.
 * @return The index of the end cert or -1 on error.
 */
int get_end_entity(X509** cert_list, int num_certs) {
	for(int i = 0; i < num_certs; ++i) {
		if(X509_check_ca(cert_list[i]) == 0) {
			return i;
		}
	}
	return -1;
}

/**
 * Frees num_certs certificates in cert_list and closes directory
 */
void free_certificates(X509** cert_list, int num_certs, DIR* directory) {
	for(int j = 0; j < num_certs; ++j) {
		X509_free(cert_list[j]);
	}
	closedir(directory);
}

/**
 * Get number of files in directory.
 * @param directory An open directory containing certificate files. 
 * @returns number of files in directory.
 */
int get_directory_size(DIR* directory) {
	int num_files = 0;
	struct dirent* file;

	while((file = readdir(directory))) {
		if (!strcmp (file->d_name, ".")) 
            continue;

        if (!strcmp (file->d_name, ".."))    
            continue;

		++num_files;
	}
	
	return num_files;
}

/**
 * Reads a directory of certificate files, converts them to X509 certificates, 
 * and adds them to cert_list. 
 * @param cert_list Array of certificate pointers to be populated with certificates in directory.
 * @param directory The directory containing certificates to put into cert_list.
 * @param dir_name Path of directory.
 * @return 0 on success, else -1. 
 */
int get_directory_certs(X509** cert_list, DIR* directory, char* dir_name) {
	struct dirent* in_file;
	int num_certs = 0; 
	int max_file_name_len = 128;
	char file_name[max_file_name_len];

	while ((in_file = readdir(directory))) {

		if (!strcmp (in_file->d_name, ".")) 
            continue;

        if (!strcmp (in_file->d_name, ".."))    
            continue;

		char* cert_name = in_file->d_name;
		file_name[0] = 0;
		sprintf(file_name, "%s/%s", dir_name, cert_name);
		FILE* current_file = fopen(file_name, "r"); 

		if(current_file == NULL) {
			log_printf(LOG_ERROR, "Error: Could not open file %s (Errno %d).\n", file_name, errno);
			free_certificates(cert_list, num_certs, directory);
			return -1;
		}
		
		if(is_pem_file(file_name)) {
			cert_list[num_certs] = PEM_read_X509(current_file, NULL, 0, NULL);
		}
		else { 
			cert_list[num_certs] = d2i_X509_fp(current_file, NULL);
		}

		if(cert_list[num_certs] == NULL) {
			log_printf(LOG_ERROR, "Error converting \"%s\" file to certificate.\n", cert_name);
			free_certificates(cert_list, num_certs, directory);
			return -1;
		}
		
		fclose(current_file); 
		++num_certs;
		errno = 0;
	}
	if(errno != 0) {
		log_printf(LOG_ERROR, "Error reading directory %s.\n", dir_name);
		return -1;
	}
	return 0;
}

/**
 * Sorts certificates and loads them in order (from end entity to root) into a context.
 * @param ctx Context to load certificates into.
 * @param cert_list Array of certificates to load into context.
 * @param num_certs Number of certificates in cert_list array.
 * @return 1 on success, 0 on error.
 */
int add_directory_certs(SSL_CTX* ctx, X509** cert_list, int num_certs) { 
	int end_index = get_end_entity(cert_list, num_certs);
	if(end_index < 0) {
		log_printf(LOG_ERROR, "Could not locate end entity certificate.\n");
		return 0;
	}

	if(SSL_CTX_use_certificate(ctx, cert_list[end_index]) != 1) {
		log_printf(LOG_ERROR, "Error loading end certificate.\n");
		return 0;
	}

	const ASN1_STRING* issuer = X509_get0_authority_key_id(cert_list[end_index]);
	if(issuer == NULL) {
		log_printf(LOG_ERROR, "X509 authority key extension not found.\n");
		return 0;
	}
	
	for(int j = 1; j < num_certs; ++j) {
		for(int k = 0; k < num_certs; ++k) {

			const ASN1_STRING* subject = X509_get0_subject_key_id(cert_list[k]);
			if(subject == NULL) {
				log_printf(LOG_ERROR, "X509 subject key extension not found.\n");
				return 0;
			}

			if(ASN1_STRING_cmp(issuer, subject) == 0) {
				if(SSL_CTX_add0_chain_cert(ctx, cert_list[k]) != 1) { 
					log_printf(LOG_ERROR, "Error adding CA to chain.\n");
					return 0;
				}
				issuer = X509_get0_authority_key_id(cert_list[k]);
				break;
			}
		}
	}

	return 1;
}

/**
 * Loads a private key into SSL_CTX, verifies the key matches the last certificate 
 * chain loaded in ctx, and builds the certificate chain. This function should be 
 * called after a certificate is loaded into the CTX. 
 * @param ctx The context the private key will be loaded into.
 * @param key_path Path to private key file. This file should be PEM or DER (ASN1).
 * @return 1 on success, 0 on error.
 */
int load_private_key(SSL_CTX* ctx, char* key_path) {
	int file_type;
	if(is_pem_file(key_path)) 
		file_type = SSL_FILETYPE_PEM;
	else 
		file_type = SSL_FILETYPE_ASN1;

	int ret = SSL_CTX_use_PrivateKey_file(ctx, key_path, file_type);
	if (ret != 1) { 
		log_printf(LOG_ERROR, "Couldn't use private key file\n");
		return 0;
	}

	ret = SSL_CTX_check_private_key(ctx);
	if (ret != 1) {
		log_printf(LOG_ERROR, "Loaded Private Key didn't match cert chain\n");
		return 0;
	}
	
	ret = SSL_CTX_build_cert_chain(ctx, 0); 
	if (ret != 1) {
		log_printf(LOG_ERROR, "Incomplete server certificate chain\n");
		return 0;
	}


	return 1;
}

/**
 * A certificate file or directory is loaded into ctx. The private key should
 * be loaded into ctx after this function is called. 
 * @param ctx The context that certificates will be loaded into.
 * @param path The path to a PEM file or directory containing all certificates
 * in the chain to be loaded into ctx.
 * @returns 1 on success, 0 on error.
 */
int load_certificates(SSL_CTX* ctx, char* path) {
	DIR* directory = opendir(path);

	if(is_pem_file(path)) {
		if(SSL_CTX_use_certificate_chain_file(ctx, path) != 1) {
			log_printf(LOG_ERROR, "Failed to load certificate chain file.\n");
			return 0;
		}
	}
	else if(directory != NULL) {
		int num_certs = get_directory_size(directory);
		closedir(directory);
		X509* cert_list[num_certs];
		directory = opendir(path);

		int ret = get_directory_certs(cert_list, directory, path);
		if(ret < 0) {
			log_printf(LOG_ERROR, "Failed to get certificates from directory.\n");
			return 0;
		}
		
		ret = add_directory_certs(ctx, cert_list, num_certs);
		if(ret < 1) {
			free_certificates(cert_list, num_certs, directory);
			log_printf(LOG_ERROR, "Failed to add certificates from directory.\n");
			return 0;
		}

		free_certificates(cert_list, num_certs, directory);
	}
	else {
		log_printf(LOG_ERROR, "[cert-path] must be a pem file or directory.\n");
		return 0;
	}

	return 1;
}