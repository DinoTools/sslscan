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

static PyObject * sslscan_ssl_module_init(void)
{
	PyObject *py_ssl_obj;
	PyObject *py_tmp_obj;
#if PY_MAJOR_VERSION >= 3
	py_ssl_obj = PyModule_Create(&ssl_module);
#else
	// TODO
#endif
	if(!py_ssl_obj)
		return NULL;

	py_tmp_obj = PyErr_NewException("sslscan.Error", NULL, NULL);
        if (!py_tmp_obj || PyModule_AddObject(py_ssl_obj, "Error", py_tmp_obj)) {
		Py_XDECREF(py_tmp_obj);
		Py_DECREF(py_ssl_obj);
		return NULL;
	}
	PyModule_AddType(py_ssl_obj, "X509", &sslscan_ssl_x509_Type);
	return py_ssl_obj;
}

#if PY_MAJOR_VERSION < 3
    PyMODINIT_FUNC PyInit_ssl(void)
    {
        sslscan_ssl_module_init();
    }
#else
    PyMODINIT_FUNC PyInit_ssl(void)
    {
        return sslscan_ssl_module_init();
    }
#endif
