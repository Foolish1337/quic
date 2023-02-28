#define _WINSOCKAPI_
#include <stdlib.h>
#include <windows.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

#include "quic.h"
#include "client.h"

EVP_PKEY* generateKey() {
	/* Allocate memory for the EVP_PKEY structure. */
	EVP_PKEY* pkey = EVP_PKEY_new();
	if (!pkey) {
		printf("Unable to create EVP_PKEY structure.");
		return NULL;
	}

	/* Generate the RSA key and assign it to pkey. */
	RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
	if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
		printf("Unable to generate 2048-bit RSA key.");
		EVP_PKEY_free(pkey);
		return NULL;
	}

	/* The key has been generated, return it. */
	return pkey;
}

X509* generateClientKey(EVP_PKEY* pkey) {
    /* Allocate memory for the X509 structure. */
    X509* x509 = X509_new();
    if (!x509) {
        printf("Unable to create X509 structure.");
        return NULL;
    }

    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, pkey);

    /* We want to copy the subject name to the issuer name. */
    X509_NAME* name = X509_get_subject_name(x509);

    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);

    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);

    /* Actually sign the certificate with our key. */
    if (!X509_sign(x509, pkey, EVP_sha1())) {
		printf("Error signing certificate.");
        X509_free(x509);
        return NULL;
    }

    return x509;
}

PKCS12* createKey(void) {
	PKCS12* p12 = NULL;
	EVP_PKEY* pKey = generateKey();
	if (!pKey)
		return NULL;

	X509* clientKey = generateClientKey(pKey);

	if (!(p12 = PKCS12_new())) {
		printf("Error creating PKCS12 structure.\n");
		return NULL;
	}

	p12 = PKCS12_create(NULL, NULL, pKey, clientKey, NULL, 0, 0, 0, 0, 0);
	if (!p12) {
		printf("Error generating a valid PKCS12 certificate.\n");
		return NULL;
	}

	return p12;
}

uint8_t* pkcs12ToByteArray(PKCS12* p12, uint32_t Pkcs12Length) {
	uint8_t* Pkcs12Buffer = (uint8_t*)malloc(Pkcs12Length);
	// Need the following variable because OpenSSL will overwrite it
	uint8_t* Pkcs12BufferPtr = Pkcs12Buffer;
	// Actually serialize the PKCS12 data into a byte array.
	if (i2d_PKCS12(p12, &Pkcs12Buffer) < 0) {
		printf("Failed to export NewPkcs12!\n");
		return NULL;
	}

	return Pkcs12Buffer;
}

// TODO: add certificates so more secure.. retard
BOOLEAN clientLoadConfiguration(quicClientConfiguration_t* client) {
    // QUIC_SETTINGS - github.com/microsoft/msquic/blob/main/docs/api/QUIC_SETTINGS.md
	QUIC_SETTINGS settings = { 0 };
	settings.HandshakeIdleTimeoutMs = TIME_OUT;
	settings.IsSet.HandshakeIdleTimeoutMs = TRUE;

	settings.IdleTimeoutMs = TIME_OUT;
	settings.IsSet.IdleTimeoutMs = TRUE;

	QUIC_CREDENTIAL_CONFIG credConfig;
	memset(&credConfig, 0, sizeof(credConfig));
	credConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
	credConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;

	PKCS12* p12 = createKey();
	if (!p12) {
		printf("Error creating PKCS12 structure.\n");
		return FALSE;
	}

	uint32_t Pkcs12Length = i2d_PKCS12(p12, NULL); // Get the length needed to serialize the PKCS12 into a byte array.
	if (Pkcs12Length <= 0) {
		printf("Failed to get export buffer size of NewPkcs12!\n");
		return FALSE;
	}
	uint8_t* p12Blob = pkcs12ToByteArray(p12, Pkcs12Length);
	if (!p12Blob) {
		printf("Error converting PKCS12 to byte array.\n");
		return FALSE;
	}

	QUIC_CERTIFICATE_PKCS12* Pkcs12Info = (QUIC_CERTIFICATE_PKCS12*)malloc(sizeof(QUIC_CERTIFICATE_PKCS12));
	if (!Pkcs12Info) {
		printf("Error allocating memory for PKCS12 info.\n");
		return FALSE;
	}

	Pkcs12Info->Asn1Blob = p12Blob;
	Pkcs12Info->Asn1BlobLength = Pkcs12Length;
	Pkcs12Info->PrivateKeyPassword = NULL;
	credConfig.CertificatePkcs12 = Pkcs12Info;

	VERIFY_QUIC_SUCCESS(
		client->MsQuicApi->ConfigurationOpen(
			client->registrationHandle,
			client->clientAlpnBuffer,
			1,
			&settings,
			sizeof(settings),
			NULL,
			&client->configurationHandle)
	);

	VERIFY_QUIC_SUCCESS(
		client->MsQuicApi->ConfigurationLoadCredential(client->configurationHandle, &credConfig)
	);

	free(Pkcs12Info);
	return TRUE;
}

void startClient(void) {
	quicClientConfiguration_t* clientConfiguration = (quicClientConfiguration_t*)calloc(1, sizeof(quicClientConfiguration_t));
	if (!clientConfiguration) {
		printf("Couldn't calloc memory towards structure\n");
		return;
	}

	VERIFY_QUIC_SUCCESS(MsQuicOpen2(&clientConfiguration->MsQuicApi));

	QUIC_BUFFER Alpn = { sizeof("doq-i03") - 1, (uint8_t*)"doq-i03" };

	clientConfiguration->clientAlpnBuffer = &Alpn;
	clientConfiguration->clientRegistrationConfig.AppName = "quicsample";
	clientConfiguration->clientRegistrationConfig.ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;

	VERIFY_QUIC_SUCCESS(
		clientConfiguration->MsQuicApi->RegistrationOpen(&clientConfiguration->clientRegistrationConfig, &clientConfiguration->registrationHandle)
	);

	clientLoadConfiguration(clientConfiguration);
}