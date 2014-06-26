#include "sslscan_ssl.h"

static char sslscan_ssl_x509_get_extensions_doc[] = "";

static PyObject *sslscan_ssl_x509_get_extensions(sslscan_ssl_x509_obj *self, PyObject *args)
{
	int i;
	PyObject *py_extensions;
	sslscan_ssl_x509ext_obj *py_extension;

	if (!PyArg_ParseTuple(args, ":get_extensions"))
		return NULL;

	// X509 v3
	if ((X509_FLAG_COMPAT & X509_FLAG_NO_EXTENSIONS))
		return Py_BuildValue("");

	py_extensions = PyList_New(0);

	for (i = 0; i < sk_X509_EXTENSION_num(self->x509->cert_info->extensions); i++)
	{
		py_extension = PyObject_New(sslscan_ssl_x509ext_obj, &sslscan_ssl_x509ext_Type);
		py_extension->extension = sk_X509_EXTENSION_value(self->x509->cert_info->extensions, i);

		PyList_Append(py_extensions, (PyObject *)py_extension);
	}
	return py_extensions;
}

static char sslscan_ssl_x509_get_version_doc[] = "";

static PyObject *sslscan_ssl_x509_get_version(sslscan_ssl_x509_obj *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ":get_version"))
		return NULL;
	if (!(X509_FLAG_COMPAT & X509_FLAG_NO_VERSION))
		return PyLong_FromLong((long)X509_get_version(self->x509) + 1);
	else
		return Py_BuildValue("");
}

static char sslscan_ssl_x509_get_public_key_doc[] = "";

static PyObject *sslscan_ssl_x509_get_public_key(sslscan_ssl_x509_obj *self, PyObject *args)
{
	sslscan_ssl_pkey_obj *py_obj;
	if (!(X509_FLAG_COMPAT & X509_FLAG_NO_PUBKEY)) {
		py_obj = PyObject_New(sslscan_ssl_pkey_obj, &sslscan_ssl_pkey_Type);
		py_obj->x509 = self->x509;
		py_obj->key = X509_get_pubkey(self->x509);
	} else {
		return Py_BuildValue("");
	}
	return (PyObject*)py_obj;
}

static char sslscan_ssl_x509_get_serial_number_doc[] = "";

static PyObject * sslscan_ssl_x509_get_serial_number(sslscan_ssl_x509_obj *self, PyObject *args)
{
	ASN1_INTEGER *asn1_i;
	BIGNUM *bignum;
	char *hex;
	PyObject *res;

	if (!PyArg_ParseTuple(args, ":get_serial_number"))
		return Py_BuildValue("");

	if ((X509_FLAG_COMPAT & X509_FLAG_NO_SERIAL))
		return Py_BuildValue("");

	asn1_i = X509_get_serialNumber(self->x509);
	bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);
	hex = BN_bn2hex(bignum);
	res = PyLong_FromString(hex, NULL, 16);
	BN_free(bignum);
	free(hex);
	return res;
}

static char sslscan_ssl_x509_get_signature_algorithm_doc[] = "";

static PyObject * sslscan_ssl_x509_get_signature_algorithm(sslscan_ssl_x509_obj *self, PyObject *args)
{
	ASN1_OBJECT *alg;
	int nid;

	//char *tmp_buffer_ptr;
	//long tmp_long;
	//PyObject *res = Py_BuildValue("");

	if (!PyArg_ParseTuple(args, ":get_serial_number"))
		return Py_BuildValue("");

	if ((X509_FLAG_COMPAT & X509_FLAG_NO_SIGNAME))
		return Py_BuildValue("");

	/*bp = BIO_new(BIO_s_mem());
	if (!bp)
		return Py_BuildValue("");

	if (i2a_ASN1_OBJECT(bp, self->x509->cert_info->signature->algorithm) > 0) {
		tmp_long = BIO_get_mem_data(bp, &tmp_buffer_ptr);
		res = PyUnicode_FromStringAndSize(tmp_buffer_ptr, tmp_long);
	}
	if(tmp_buffer_ptr != NULL) {
		free(tmp_buffer_ptr);
		tmp_buffer_ptr = NULL;
	}
	BIO_set_close(bp, BIO_NOCLOSE);
	BIO_free(bp);

	return res;*/
	//ToDo: check
	if (!PyArg_ParseTuple(args, ":get_signature_algorithm")) {
		return NULL;
	}

	alg = self->x509->cert_info->signature->algorithm;
	nid = OBJ_obj2nid(alg);
	if (nid == NID_undef) {
		PyErr_SetString(PyExc_ValueError, "Undefined signature algorithm");
		return Py_BuildValue("");
	}
	return PyUnicode_FromString(OBJ_nid2ln(nid));
}

static char sslscan_ssl_x509_get_issuer_doc[] = "";

static PyObject * sslscan_ssl_x509_get_issuer(sslscan_ssl_x509_obj *self, PyObject *args)
{
	char buffer[512];
	PyObject *res = Py_BuildValue("");

	if (!PyArg_ParseTuple(args, ":get_issuer"))
		return Py_BuildValue("");

	if ((X509_FLAG_COMPAT & X509_FLAG_NO_ISSUER))
		return res;

	X509_NAME_oneline(X509_get_issuer_name(self->x509), buffer, sizeof(buffer) - 1);
	return PyUnicode_FromString(buffer);
}

static char sslscan_ssl_x509_get_subject_doc[] = "";

static PyObject * sslscan_ssl_x509_get_subject(sslscan_ssl_x509_obj *self, PyObject *args)
{
	char buffer[512];
	PyObject *res = Py_BuildValue("");

	if (!PyArg_ParseTuple(args, ":get_issuer"))
		return Py_BuildValue("");
	
	if ((X509_FLAG_COMPAT & X509_FLAG_NO_SUBJECT))
		return res;

	X509_NAME_oneline(X509_get_subject_name(self->x509), buffer, sizeof(buffer) - 1);
	return PyUnicode_FromString(buffer);
}

PyObject*
_get_asn1_time(char *format, ASN1_TIME* timestamp, PyObject *args)
{
	ASN1_GENERALIZEDTIME *gt_timestamp = NULL;
	PyObject *py_timestamp = NULL;

	if (!PyArg_ParseTuple(args, format)) {
		return NULL;
	}

	/*
	 * http://www.columbia.edu/~ariel/ssleay/asn1-time.html
	 */
	/*
	 * There must be a way to do this without touching timestamp->data
	 * directly. -exarkun
	 */
	if (timestamp->length == 0) {
	    Py_INCREF(Py_None);
	    return Py_None;
	} else if (timestamp->type == V_ASN1_GENERALIZEDTIME) {
		return PyBytes_FromString((char *)timestamp->data);
	} else {
		ASN1_TIME_to_generalizedtime(timestamp, &gt_timestamp);
		if (gt_timestamp == NULL) {
			//exception_from_error_queue(crypto_Error);
			return NULL;
		} else {
			py_timestamp = PyBytes_FromString((char *)gt_timestamp->data);
			ASN1_GENERALIZEDTIME_free(gt_timestamp);
			return py_timestamp;
		}
	}
}

static char sslscan_ssl_x509_get_not_after_doc[] = "";

static PyObject * sslscan_ssl_x509_get_not_after(sslscan_ssl_x509_obj *self, PyObject *args)
{
	BIO *bp;
	char *buffer;
	long tmp_long;
	PyObject *res = Py_BuildValue("");
	int mode=0;

	PyArg_ParseTuple(args, "i:get_not_after", &mode);
	
	if ((X509_FLAG_COMPAT & X509_FLAG_NO_VALIDITY))
		return Py_BuildValue("");

	if(mode == 3) {
		bp = BIO_new(BIO_s_mem());
		if (!bp)
			return Py_BuildValue("");

		ASN1_TIME_print(bp, X509_get_notAfter(self->x509));
		tmp_long = BIO_get_mem_data(bp, &buffer);
		res = PyUnicode_FromStringAndSize(buffer, tmp_long);
		if(buffer != NULL) {
			free(buffer);
			         buffer = NULL;
		}
		BIO_set_close(bp, BIO_NOCLOSE);
		BIO_free(bp);
		return res;
	}
	if(mode == 2)
		return _get_asn1_time(":get_not_after", X509_get_notAfter(self->x509), args);
	// ToDo:
	return res;
}

static char sslscan_ssl_x509_get_not_before_doc[] = "";

static PyObject * sslscan_ssl_x509_get_not_before(sslscan_ssl_x509_obj *self, PyObject *args)
{
	BIO *bp;
	char *buffer;
	long tmp_long;
	PyObject *res = Py_BuildValue("");
	int mode=0;

	PyArg_ParseTuple(args, "i:get_not_before", &mode);
	
	if ((X509_FLAG_COMPAT & X509_FLAG_NO_VALIDITY))
		return Py_BuildValue("");

	if(mode == 3) {
		bp = BIO_new(BIO_s_mem());
		if (!bp)
			return Py_BuildValue("");

		ASN1_TIME_print(bp, X509_get_notBefore(self->x509));
		tmp_long = BIO_get_mem_data(bp, &buffer);
		res = PyUnicode_FromStringAndSize(buffer, tmp_long);
		if(buffer != NULL) {
			free(buffer);
			buffer = NULL;
		}
		BIO_set_close(bp, BIO_NOCLOSE);
		BIO_free(bp);
		return res;
	}
	if(mode == 2)
		return _get_asn1_time(":get_not_before", X509_get_notBefore(self->x509), args);
	// ToDo:
	return res;
}

static char sslscan_ssl_x509_get_certificate_blob_doc[] = "";

static PyObject * sslscan_ssl_x509_get_certificate_blob(sslscan_ssl_x509_obj *self, PyObject *args)
{
	BIO *bp;
	char *buffer;
	long tmp_long;
	PyObject *res = Py_BuildValue("");

	if (!PyArg_ParseTuple(args, ":get_serial_number"))
		return Py_BuildValue("");

	bp = BIO_new(BIO_s_mem());
	if (!bp)
		return Py_BuildValue("");

	PEM_write_bio_X509(bp, self->x509);
	tmp_long = BIO_get_mem_data(bp, &buffer);
	res = PyUnicode_FromStringAndSize(buffer, tmp_long);

	if(buffer != NULL) {
		free(buffer);
		      buffer = NULL;
	}
	BIO_set_close(bp, BIO_NOCLOSE);
	BIO_free(bp);

	return res;
}

static PyObject * sslscan_ssl_x509_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *tmp_obj;
	sslscan_ssl_x509_obj *self;
	self = PyObject_New(sslscan_ssl_x509_obj, &sslscan_ssl_x509_Type);
	if (PyArg_ParseTuple(args, "O:test", &tmp_obj)) {
		self->x509 = (X509*)PyCapsule_GetPointer(tmp_obj, "x509");
	}
	if (self == NULL) {
		return NULL;
	}

	return (PyObject *)self;
}


static int sslscan_ssl_x509_tp_init(sslscan_ssl_x509_obj *self, PyObject *args, PyObject *kwargs)
{
	return 0;
}

#define ADD_METHOD(name) { #name, (PyCFunction)sslscan_ssl_x509_##name, METH_VARARGS, sslscan_ssl_x509_##name##_doc }

static PyMethodDef sslscan_ssl_x509_tp_methods[] = {
	ADD_METHOD(get_extensions),
	ADD_METHOD(get_version),
	ADD_METHOD(get_serial_number),
	ADD_METHOD(get_signature_algorithm),
	ADD_METHOD(get_issuer),
	ADD_METHOD(get_subject),
	ADD_METHOD(get_not_after),
	ADD_METHOD(get_not_before),
	ADD_METHOD(get_certificate_blob),
	ADD_METHOD(get_public_key),
	{NULL, NULL}  /* Sentinel */
};

#undef ADD_METHOD

/*static PyMemberDef sslscan_ssl_x509_tp_members[] = {
	{NULL} 
};*/

PyDoc_STRVAR(sslscan_ssl_x509_tp_doc,
		"Test");

PyTypeObject sslscan_ssl_x509_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"X509",                       /*tp_name*/
	sizeof(sslscan_ssl_x509_obj),             /*tp_basicsize*/
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
	sslscan_ssl_x509_tp_doc,                  /*tp_doc*/
	0,                                        /*tp_traverse*/
	0,                                        /*tp_clear*/
	0,                                        /*tp_richcompare*/
	0,                                        /*tp_weaklistoffset*/
	0,                                        /*tp_iter*/
	0,                                        /*tp_iternext*/
	sslscan_ssl_x509_tp_methods,                        /*tp_methods*/
	0,//sslscan_ssl_x509_tp_members,                        /*tp_members*/
	0,                                        /*tp_getsets*/
	0,                                        /*tp_base*/
	0,                                        /*tp_dict*/
	0,                                        /*tp_descr_get*/
	0,                                        /*tp_descr_set*/
	0,                                        /*tp_dictoffset*/
	(initproc)sslscan_ssl_x509_tp_init,                 /*tp_init*/
	0,                                        /*tp_alloc*/
	sslscan_ssl_x509_tp_new,                            /*tp_new*/
};

