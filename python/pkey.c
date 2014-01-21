#include "sslscan_ssl.h"

static char sslscan_ssl_pkey_get_algorithm_doc[] = "";

static PyObject * sslscan_ssl_pkey_get_algorithm(sslscan_ssl_pkey_obj *self, PyObject *args)
{
	char buffer[512];
	i2t_ASN1_OBJECT(&buffer[0], sizeof(buffer), self->x509->cert_info->key->algor->algorithm);
	return PyUnicode_FromString(&buffer[0]);
}

static char sslscan_ssl_pkey_get_bits_doc[] = "";

static PyObject * sslscan_ssl_pkey_get_bits(sslscan_ssl_pkey_obj *self, PyObject *args)
{
	if (self->key->type == EVP_PKEY_DSA && self->key->pkey.dsa)
		return PyLong_FromLong(DSA_size(self->key->pkey.dsa) * 8);

#if defined(EVP_PKEY_EC) && !defined(OPENSSL_NO_BIO) && !defined(OPENSSL_NO_EC)
	// ToDo:
	if (self->key->type == EVP_PKEY_EC && self->key->pkey.ec)
		return Py_BuildValue("");
#endif // #if defined(EVP_PKEY_EC) && !defined(OPENSSL_NO_BIO) && !defined(OPENSSL_NO_EC)
	if (self->key->type == EVP_PKEY_RSA && self->key->pkey.rsa)
		return PyLong_FromLong(RSA_size(self->key->pkey.rsa) * 8);
	return Py_BuildValue("");
}

static char sslscan_ssl_pkey_get_key_print_doc[] = "";

static PyObject * sslscan_ssl_pkey_get_key_print(sslscan_ssl_pkey_obj *self, PyObject *args)
{
	BIO *bp;
	char *buffer;
	long len;
	PyObject *res = Py_BuildValue("");
	int status = 0;
	int indent = 0;

	if(!PyArg_ParseTuple(args, "i:sslscan_ssl_pkey_get_key_print", &indent))
		indent = 0;

	bp = BIO_new(BIO_s_mem());
	if (!bp)
		return Py_BuildValue("");

	if (self->key->type == EVP_PKEY_DSA)
		status = DSA_print(bp, self->key->pkey.dsa, indent);
#if defined(EVP_PKEY_EC) && !defined(OPENSSL_NO_BIO) && !defined(OPENSSL_NO_EC)
	if (self->key->type == EVP_PKEY_EC)
		status = EC_KEY_print(bp, self->key->pkey.ec, indent);
#endif // #if defined(EVP_PKEY_EC) && !defined(OPENSSL_NO_BIO) && !defined(OPENSSL_NO_EC)
	if (self->key->type == EVP_PKEY_RSA)
		status = RSA_print(bp, self->key->pkey.rsa, indent);
	if (status == 1) {
		len = BIO_get_mem_data(bp, &buffer);
		res = PyUnicode_FromStringAndSize(buffer, len);
	}

	if(buffer != NULL) {
		free(buffer);
		buffer = NULL;
	}
	BIO_set_close(bp, BIO_NOCLOSE);
	BIO_free(bp);

	return res;
}

static char sslscan_ssl_pkey_get_type_name_doc[] = "";

static PyObject * sslscan_ssl_pkey_get_type_name(sslscan_ssl_pkey_obj *self, PyObject *args)
{
	if (self->key->type == EVP_PKEY_DSA)
		return PyUnicode_FromString("DSA");
#if defined(EVP_PKEY_EC) && !defined(OPENSSL_NO_BIO) && !defined(OPENSSL_NO_EC)
	if (self->key->type == EVP_PKEY_EC)
		return PyUnicode_FromString("EC");
#endif // #if defined(EVP_PKEY_EC) && !defined(OPENSSL_NO_BIO) && !defined(OPENSSL_NO_EC)
	if (self->key->type == EVP_PKEY_RSA)
		return PyUnicode_FromString("RSA");
	return Py_BuildValue("");
}

static PyObject * sslscan_ssl_pkey_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *tmp_obj;
	sslscan_ssl_pkey_obj *self;
	self = PyObject_New(sslscan_ssl_pkey_obj, &sslscan_ssl_pkey_Type);
	if (PyArg_ParseTuple(args, "O:test", &tmp_obj)) {
		self->x509 = (X509 *)PyCapsule_GetPointer(tmp_obj, "x509");
		self->key = X509_get_pubkey(self->x509);
	}
	if (self == NULL) {
		return NULL;
	}

	return (PyObject *)self;
}


static int sslscan_ssl_pkey_tp_init(sslscan_ssl_pkey_obj *self, PyObject *args, PyObject *kwargs)
{
	return 0;
}

static void sslscan_ssl_pkey_tp_dealloc(sslscan_ssl_pkey_obj *self)
{
	if (self->key != NULL)
		EVP_PKEY_free(self->key);
}

#define ADD_METHOD(name) { #name, (PyCFunction)sslscan_ssl_pkey_##name, METH_VARARGS, sslscan_ssl_pkey_##name##_doc }

static PyMethodDef sslscan_ssl_pkey_tp_methods[] = {
	ADD_METHOD(get_algorithm),
	ADD_METHOD(get_bits),
	ADD_METHOD(get_key_print),
	ADD_METHOD(get_type_name),
	{NULL, NULL}  /* Sentinel */
};
#undef ADD_METHOD

/*static PyMemberDef sslscan_ssl_x509_tp_members[] = {
	{NULL} 
};*/

PyDoc_STRVAR(sslscan_ssl_pkey_tp_doc,
		"Test");

PyTypeObject sslscan_ssl_pkey_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"PublicKey",                       /*tp_name*/
	sizeof(sslscan_ssl_pkey_obj),             /*tp_basicsize*/
	0,                                        /*tp_itemsize*/
	(destructor)sslscan_ssl_pkey_tp_dealloc,  /*tp_dealloc*/
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
	sslscan_ssl_pkey_tp_doc,                  /*tp_doc*/
	0,                                        /*tp_traverse*/
	0,                                        /*tp_clear*/
	0,                                        /*tp_richcompare*/
	0,                                        /*tp_weaklistoffset*/
	0,                                        /*tp_iter*/
	0,                                        /*tp_iternext*/
	sslscan_ssl_pkey_tp_methods,                        /*tp_methods*/
	0,//sslscan_ssl_x509_tp_members,                        /*tp_members*/
	0,                                        /*tp_getsets*/
	0,                                        /*tp_base*/
	0,                                        /*tp_dict*/
	0,                                        /*tp_descr_get*/
	0,                                        /*tp_descr_set*/
	0,                                        /*tp_dictoffset*/
	(initproc)sslscan_ssl_pkey_tp_init,                 /*tp_init*/
	0,                                        /*tp_alloc*/
	sslscan_ssl_pkey_tp_new,                            /*tp_new*/
};

