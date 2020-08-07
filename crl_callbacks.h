#ifndef SSA_CRL_CALLBACKS_H
#define SSA_CRL_CALLBACKS_H

#include "daemon_structs.h"

int launch_crl_checks(revocation_ctx* rev_ctx, int cert_index);

#endif
