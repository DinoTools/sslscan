#include "sslscan_ssl.h"

PyDoc_STRVAR(ssl_m_doc, "");

static PyMethodDef ssl_m_methods[] = {
	{NULL} /* Sentinel */
};

int PyModule_AddType(PyObject *module, const char *name, PyTypeObject *type)
{
	if (PyType_Ready(type))
		return -1;
	Py_INCREF(type);
	if (PyModule_AddObject(module, name, (PyObject *)type)) {
		Py_DECREF(type);
		return -1;
	}
	return 0;
}


#if PY_MAJOR_VERSION >= 3
static PyModuleDef ssl_module = {
    PyModuleDef_HEAD_INIT,
    "ssl",                                   /*m_name*/
    ssl_m_doc,                               /*m_doc*/
    -1,                                       /*m_size*/
    ssl_m_methods,                           /*m_methods*/
};
#endif

PySSLSCAN_MODINIT(ssl)
{
	PyObject *py_ssl_obj;
	PyObject *py_tmp_obj;
#if PY_MAJOR_VERSION >= 3
	py_ssl_obj = PyModule_Create(&ssl_module);
#else
	py_ssl_obj = Py_InitModule3("sslscan.ssl", ssl_m_methods, ssl_m_doc);
#endif
	if(!py_ssl_obj)
		PySSLSCAN_MODRETURN(NULL)

	py_tmp_obj = PyErr_NewException("sslscan.Error", NULL, NULL);
        if (!py_tmp_obj || PyModule_AddObject(py_ssl_obj, "Error", py_tmp_obj)) {
		Py_XDECREF(py_tmp_obj);
		Py_DECREF(py_ssl_obj);
		PySSLSCAN_MODRETURN(NULL)
	}
	PyModule_AddType(py_ssl_obj, "Alert", &sslscan_ssl_alert_Type);
	PyModule_AddType(py_ssl_obj, "Cipher", &sslscan_ssl_cipher_Type);
	PyModule_AddType(py_ssl_obj, "X509", &sslscan_ssl_x509_Type);
	PyModule_AddType(py_ssl_obj, "X509Extension", &sslscan_ssl_x509ext_Type);
	PyModule_AddType(py_ssl_obj, "PublicKey", &sslscan_ssl_pkey_Type);
	PySSLSCAN_MODRETURN(py_ssl_obj)
}
