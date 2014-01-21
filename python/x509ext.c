#include "sslscan_ssl.h"

static char sslscan_ssl_x509ext_get_critical_doc[] = "";

static PyObject * sslscan_ssl_x509ext_get_critical(sslscan_ssl_x509ext_obj *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ":get_critical"))
		return NULL;

	if (self->extension == NULL)
		return Py_BuildValue("");

	return PyLong_FromLong(X509_EXTENSION_get_critical(self->extension));
}

static char sslscan_ssl_x509ext_get_data_doc[] = "";

static PyObject * sslscan_ssl_x509ext_get_data(sslscan_ssl_x509ext_obj *self, PyObject *args)
{
	ASN1_OCTET_STRING *data;
	
	if (!PyArg_ParseTuple(args, ":get_data"))
		return NULL;

	if (self->extension == NULL)
		return Py_BuildValue("");

	data = X509_EXTENSION_get_data(self->extension);
	return PyBytes_FromStringAndSize((const char*)data->data, data->length);
}

static char sslscan_ssl_x509ext_get_name_doc[] = "";

static PyObject * sslscan_ssl_x509ext_get_name(sslscan_ssl_x509ext_obj *self, PyObject *args)
{
	char buffer[512];
	ASN1_OBJECT *asn1_obj;
	
	if (!PyArg_ParseTuple(args, ":get_data"))
		return NULL;

	if (self->extension == NULL)
		return Py_BuildValue("");

	asn1_obj = X509_EXTENSION_get_object(self->extension);

	i2t_ASN1_OBJECT(&buffer[0], sizeof(buffer), asn1_obj);

	return PyUnicode_FromString(&buffer[0]);
}

static char sslscan_ssl_x509ext_get_short_name_doc[] = "";

static PyObject * sslscan_ssl_x509ext_get_short_name(sslscan_ssl_x509ext_obj *self, PyObject *args)
{
	//char buffer[512];
	const char *name;
	ASN1_OBJECT *asn1_obj;
	
	if (!PyArg_ParseTuple(args, ":get_name"))
		return NULL;

	if (self->extension == NULL)
		return Py_BuildValue("");

	asn1_obj = X509_EXTENSION_get_object(self->extension);

	name = OBJ_nid2sn(OBJ_obj2nid(asn1_obj));
	
	return PyUnicode_FromString(name);
/*	

	i2t_ASN1_OBJECT(&buffer[0], sizeof(buffer), asn1_obj);

	return PyUnicode_FromString(&buffer[0]);*/
}

static char sslscan_ssl_x509ext_get_value_doc[] = "";

static PyObject * sslscan_ssl_x509ext_get_value(sslscan_ssl_x509ext_obj *self, PyObject *args)
{
	BIO *bp;
	char *buffer;
	long len;
	int i;
	int indent = 0;

	PyObject *result = Py_BuildValue("");
	
	if (!PyArg_ParseTuple(args, "|i:get_value", &indent))
		indent = 0;

	if (self->extension == NULL)
		return Py_BuildValue("");

	bp = BIO_new(BIO_s_mem());
	if (!bp)
		return Py_BuildValue("");

	if (!X509V3_EXT_print(bp, self->extension, X509_FLAG_COMPAT, indent)) {
		for (i = 0; i < indent; i++)
			BIO_puts(bp, " ");
		M_ASN1_OCTET_STRING_print(bp, self->extension->value);
	}

	len = BIO_get_mem_data(bp, &buffer);
	result = PyUnicode_FromStringAndSize(buffer, len);

	if(buffer != NULL) {
		free(buffer);
		buffer = NULL;
	}

	BIO_set_close(bp, BIO_NOCLOSE);
	BIO_free(bp);
	return result;
}

static PyObject * sslscan_ssl_x509ext_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	//PyObject *tmp_obj;
	sslscan_ssl_x509ext_obj *self;
	self = PyObject_New(sslscan_ssl_x509ext_obj, &sslscan_ssl_x509ext_Type);
	/*if (PyArg_ParseTuple(args, ":Extension", &tmp_obj)) {
	}*/

	if (self == NULL) {
		return NULL;
	}

	return (PyObject *)self;
}


static int sslscan_ssl_x509ext_tp_init(sslscan_ssl_x509ext_obj *self, PyObject *args, PyObject *kwargs)
{
	return 0;
}

#define ADD_METHOD(name) { #name, (PyCFunction)sslscan_ssl_x509ext_##name, METH_VARARGS, sslscan_ssl_x509ext_##name##_doc }

static PyMethodDef sslscan_ssl_x509ext_tp_methods[] = {
	ADD_METHOD(get_critical),
	ADD_METHOD(get_data),
	ADD_METHOD(get_name),
	ADD_METHOD(get_short_name),
	ADD_METHOD(get_value),
	{NULL, NULL}  /* Sentinel */
};
#undef ADD_METHOD

PyDoc_STRVAR(sslscan_ssl_x509ext_tp_doc,
		"Test");

PyTypeObject sslscan_ssl_x509ext_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"X509Extension",                       /*tp_name*/
	sizeof(sslscan_ssl_x509ext_obj),             /*tp_basicsize*/
	0,                                        /*tp_itemsize*/
	0,                                        /*tp_dealloc*/
	0,                                        /*tp_print*/
	0,                                        /*tp_getattr*/
	0,                                        /*tp_setattr*/
	0,                                        /*tp_compare*/
	0,                                        /*tp_repr*/
	0,                                        /*tp_as_number*/
	0,                                        /*tp_as_sequence*/
	0,                                        /*tp_as_mapping*/
	0,                                        /*tp_hash */
	0,                                        /*tp_call*/
	0,                                        /*tp_str*/
	0,                                        /*tp_getattro*/
	0,                                        /*tp_setattro*/
	0,                                        /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT, /*tp_flags*/
	sslscan_ssl_x509ext_tp_doc,                  /*tp_doc*/
	0,                                        /*tp_traverse*/
	0,                                        /*tp_clear*/
	0,                                        /*tp_richcompare*/
	0,                                        /*tp_weaklistoffset*/
	0,                                        /*tp_iter*/
	0,                                        /*tp_iternext*/
	sslscan_ssl_x509ext_tp_methods,                        /*tp_methods*/
	0,//sslscan_ssl_x509_tp_members,                        /*tp_members*/
	0,                                        /*tp_getsets*/
	0,                                        /*tp_base*/
	0,                                        /*tp_dict*/
	0,                                        /*tp_descr_get*/
	0,                                        /*tp_descr_set*/
	0,                                        /*tp_dictoffset*/
	(initproc)sslscan_ssl_x509ext_tp_init,                 /*tp_init*/
	0,                                        /*tp_alloc*/
	sslscan_ssl_x509ext_tp_new,                            /*tp_new*/
};

