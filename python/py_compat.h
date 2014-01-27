/**
 * See: http://docs.python.org/3.3/howto/cporting.html
 */
#ifndef _SSLSCAN_PY_COMPAT_H
#define _SSLSCAN_PY_COMPAT_H

#if PY_MAJOR_VERSION >= 3
#define IS_PY3K
#endif

#ifdef IS_PY3K

#define PySSLSCAN_MODINIT(name) \
PyMODINIT_FUNC \
PyInit_##name(void)

#define PySSLSCAN_MODRETURN(module) { return module; }

#else /* IS_PY3K */

#define PySSLSCAN_MODINIT(name) \
void \
init##name(void)

#define PySSLSCAN_MODRETURN(module) { return; }

#endif /* IS_PY3K */

#include "capsulethunk.h"

#endif /* _SSLSCAN_PY_COMPAT_H_ */
