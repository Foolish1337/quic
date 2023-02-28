#pragma once
#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

#include <stdint.h>
#include <msquic.h>

#define TIME_OUT 1000

typedef struct _quicClientConfiguration {
	const QUIC_API_TABLE* MsQuicApi;
	const QUIC_BUFFER* clientAlpnBuffer;
	QUIC_REGISTRATION_CONFIG clientRegistrationConfig;
	QUIC_SETTINGS settings;
	uint8_t* resumptionTicket;
	unsigned int resumptionTicketLength;
	HQUIC registrationHandle;
	HQUIC configurationHandle;
} quicClientConfiguration_t;

void startClient(void);