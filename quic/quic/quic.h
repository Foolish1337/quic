#pragma once

#define VERIFY_QUIC_SUCCESS(X) { \
    QUIC_STATUS s = X; \
    if (QUIC_FAILED(s)) { printf(#X " FAILURE: 0x%x!!\n", s); return FALSE; } \
}