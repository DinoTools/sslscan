#ifndef _SSLSCAN_PY_COMPAT_H
#define _SSLSCAN_PY_COMPAT_H

#if (PY_VERSION_HEX >= 0x03000000)

#define PySSLSCAN_MODINIT(name) \
PyMODINIT_FUNC \
PyInit_##name(void)

#else /* (PY_VERSION_HEX >= 0x03000000) */

#define PySSLSCAN_MODINIT(name) \
void \
init##name(void)

#endif /* (PY_VERSION_HEX >= 0x03000000) */

#endif /* _SSLSCAN_PY_COMPAT_H_ */
