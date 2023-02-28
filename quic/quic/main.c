/*
#include <iostream>
#include <msquic.hpp>
#include <msquic.h>

const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

const uint64_t IdleTimeoutMs = 1000;
const QUIC_API_TABLE* MsQuicApi;
//
// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
//
static HQUIC Registration;

//
// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
//
HQUIC Configuration;
const QUIC_BUFFER Alpn = { sizeof("doq-i03") - 1, (uint8_t*)"doq-i03" };

typedef struct _quicConfiguration {
	uint8_t *resumptionTicket;
	unsigned int resumptionTicketLength;
} quicConfiguration_t;

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
StreamCallback(_In_ HQUIC stream, _In_opt_ void* context, _Inout_ QUIC_STREAM_EVENT* event) {
	UNREFERENCED_PARAMETER(context);
	switch (event->Type) {
	case QUIC_STREAM_EVENT_SEND_COMPLETE:
		// previous streamsend call has finished freeing the client context
		free(event->SEND_COMPLETE.ClientContext);
		printf("[conn][stream][%p] data sent\n", stream);
		break;

	case QUIC_STREAM_EVENT_RECEIVE:
		// data was recieved from peer on the stream
		printf("[conn][stream][%p] data received: ", stream);
		for (uint64_t i = 0; i < event->RECEIVE.BufferCount; i++)
			for (unsigned int j = 0; j < event->RECEIVE.Buffers[i].Length; j++)
				printf("%c", (char)event->RECEIVE.Buffers[i].Buffer[j]);

		printf("\n");
		printf("[conn][stream][%p] flag recieved: %s\n", stream,
			(event->RECEIVE.Flags == QUIC_RECEIVE_FLAG_NONE ? "QUIC_RECEIVE_FLAG_NONE" :
				(event->RECEIVE.Flags == QUIC_RECEIVE_FLAG_0_RTT ? "QUIC_RECEIVE_FLAG_0_RTT" :
					(event->RECEIVE.Flags == QUIC_RECEIVE_FLAG_FIN ? "QUIC_RECEIVE_FLAG_FIN" : NULL)))
		);
		break;

	case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
		// shutting down send direction of the stream
		printf("[conn][stream][%p] Peer aborted\n", stream);
		break;

	case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
		// peer aborted its send direction of the stream
		printf("[conn][stream][%p] Peer shut down\n", stream);
		break;

	case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
		// Both directions of the stream have been shut downand MsQuic is done
		// with the stream. It can now be safely cleaned up.
		printf("[strm][%p] All done\n", stream);
		if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
			MsQuicApi->StreamClose(stream);
		}
		break;
	default:
		break;
	}
	return QUIC_STATUS_SUCCESS;
}

void StreamSend(_In_ HQUIC connection) {
	QUIC_STATUS status;
	uint8_t* SendBufferRaw;
	QUIC_BUFFER* SendBuffer;
	HQUIC stream = NULL;

	if (QUIC_FAILED(status = MsQuicApi->StreamOpen(connection, QUIC_STREAM_OPEN_FLAG_NONE, StreamCallback, NULL, &stream))) {
		printf("StreamOpen failed, 0x%x\n", status);
		goto Error;
	}
	
	if (QUIC_FAILED(status = MsQuicApi->StreamStart(stream, QUIC_STREAM_START_FLAG_NONE))) {
		printf("StreamStart failed, 0x%x\n", status);
		MsQuicApi->StreamClose(stream);
		goto Error;
	}

	printf("[conn][stream][%p] sending data", stream);
	SendBufferRaw = (uint8_t*)malloc(sizeof(QUIC_BUFFER) + 4);
	if (SendBufferRaw == NULL) {
		printf("SendBuffer allocation failed!\n");
		status = QUIC_STATUS_OUT_OF_MEMORY;
		goto Error;
	}
	SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
	SendBuffer->Buffer = (uint8_t*)"foo";
	SendBuffer->Length = 4;

	if (QUIC_FAILED(status = MsQuicApi->StreamSend(stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
		printf("StreamSend failed, 0x%x!\n", status);
		free(SendBufferRaw);
		goto Error;
	}

Error:
	if (QUIC_FAILED(status)) 
		MsQuicApi->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ClientConnectionCallback(_In_ HQUIC connection, _In_opt_ void* context, _Inout_ QUIC_CONNECTION_EVENT* event) {
	UNREFERENCED_PARAMETER(context);
	uint8_t* buffer = (uint8_t*)"sample";
	switch (event->Type) {
	case QUIC_CONNECTION_EVENT_CONNECTED:
		printf("[conn][%p] Connected\n", connection);
		StreamSend(connection);
		break;

	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
		if (event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE)
			printf("[conn][%p] Successfully shut down on idle.\n", connection);
		else 
			printf("[conn][%p] Shut down by transport, 0x%x\n", connection, event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
		
		break;

	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
		printf("[conn][%p] shut down by peer, 0x%llu\n", connection, event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
		break;

	case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
		printf("[conn][%p] state changed, SendEnabled=%d, MaxSendLength=%u\n", connection, event->DATAGRAM_STATE_CHANGED.SendEnabled, event->DATAGRAM_STATE_CHANGED.MaxSendLength);
		break;

	case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
		printf("[conn][%p] all completed\n", connection);
		if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress)
			MsQuicApi->ConnectionClose(connection);
		break;

	case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED: // TODO: figure out how to save and send back resumption ticket
		printf("[conn][%p] Resumption ticket received (%u bytes)\n", connection, event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
		for (uint32_t i = 0; i < event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++)
			printf("%.2X", (uint8_t)event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
		printf("\n");
		break;
	default:
		printf("[conn] error\n");
	}

	return QUIC_STATUS_SUCCESS;
}

BOOLEAN ClientLoadConfiguration() {
	QUIC_SETTINGS settings = { 0 };

	settings.IdleTimeoutMs = IdleTimeoutMs;
	settings.IsSet.IdleTimeoutMs = TRUE;

	QUIC_CREDENTIAL_CONFIG CredConfig;
	memset(&CredConfig, 0, sizeof(CredConfig));
	CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
	CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
	CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

	QUIC_STATUS status = QUIC_STATUS_SUCCESS;
	if (QUIC_FAILED(status = MsQuicApi->ConfigurationOpen(Registration, &Alpn, 1, &settings, sizeof(settings), NULL, &Configuration))) {
		printf("Registration failed, 0x%x\n", status);
		return FALSE;
	}

	if (QUIC_FAILED(status = MsQuicApi->ConfigurationLoadCredential(Configuration, &CredConfig))) {
		printf("ConfigurationLoadCredential failed, 0x%x!\n", status);
		return FALSE;
	}

	return TRUE;
}

void startClient() {
	if (!ClientLoadConfiguration())
		return;

	QUIC_STATUS status;
	const char* resumptionTicketString = NULL;
	HQUIC connection = NULL;

	// New connection object
	if (QUIC_FAILED(status = MsQuicApi->ConnectionOpen(Registration, ClientConnectionCallback, NULL, &connection))) {
		printf("ConnectionOpen failed, 0x%x!\n", status);
		goto Error;
	}

	printf("[conn][%p] connecting...\n", connection);

	if (QUIC_FAILED(status = MsQuicApi->ConnectionStart(connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, "127.0.0.1", 4242))) {
		printf("ConnectionStart failed, 0x%x\n", status);
		goto Error;
	}

Error:
	if (QUIC_FAILED(status) && connection)
		MsQuicApi->ConnectionClose(connection);
}

int main() {
	QUIC_STATUS status = QUIC_STATUS_SUCCESS;
	if (QUIC_FAILED(status = MsQuicOpen2(&MsQuicApi))) {
		printf("MsQuiCOpen2 failed, 0x%x\n", status);
		goto Error;
	}
	
	if (QUIC_FAILED(status = MsQuicApi->RegistrationOpen(&RegConfig, &Registration))) {
		printf("RegistrationOpen failed, 0x%x\n", status);
		goto Error; // here
	}
	startClient();

Error: // straight here
	if (MsQuicApi) {
		if (Configuration)
			MsQuicApi->ConfigurationClose(Configuration);

		//TODO: Figure out why registration close cannot close "Registration"
		if (Registration)
			MsQuicApi->RegistrationClose(Registration);

		uint64_t counters[QUIC_PERF_COUNTER_MAX] = { 0 };
		uint32_t buff = sizeof(counters);
		MsQuicApi->GetParam(NULL, QUIC_PARAM_GLOBAL_PERF_COUNTERS, &buff, counters);
		printf("Counter: 0x%x\n", counters);

		MsQuicClose(MsQuicApi);
	}

	return (int)status;
}

*/
#define _WINSOCKAPI_ 
#include <stdio.h>

#include "client.h"

int main(void) {
	startClient();
	return 0;
}