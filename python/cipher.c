#include "sslscan_ssl.h"

static char sslscan_ssl_cipher_get_alerts_doc[] = "";

static PyObject * sslscan_ssl_cipher_get_alerts(sslscan_ssl_cipher_obj *self, PyObject *args)
{
	PyObject *py_alerts;
	sslscan_ssl_alert_obj *py_obj;
	struct ssl_alert_info *p;

	if (!PyArg_ParseTuple(args, ":get_alerts"))
		return Py_BuildValue("");

	py_alerts = PyList_New(0);
	p = self->alerts;

	while (p != NULL) {
		py_obj = PyObject_New(sslscan_ssl_alert_obj, &sslscan_ssl_alert_Type);
		py_obj->ret = p->ret;
		
		PyList_Append(py_alerts, (PyObject *)py_obj);
		p = p->next;
	}

	return py_alerts;
}

static char sslscan_ssl_cipher_get_bits_doc[] = "";

static PyObject * sslscan_ssl_cipher_get_bits(sslscan_ssl_cipher_obj *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ":get_bits"))
		return Py_BuildValue("");;

	return PyLong_FromLong(self->cipher->bits);
}

static char sslscan_ssl_cipher_get_method_name_doc[] = "";

static PyObject * sslscan_ssl_cipher_get_method_name(sslscan_ssl_cipher_obj *self, PyObject *args)
{
	char method_name[32];

	if (!PyArg_ParseTuple(args, ":get_method_name"))
		return Py_BuildValue("");

	get_ssl_method_name(self->cipher->sslMethod, method_name, sizeof(method_name));

	return PyUnicode_FromString(method_name);
}

static char sslscan_ssl_cipher_get_name_doc[] = "";

static PyObject * sslscan_ssl_cipher_get_name(sslscan_ssl_cipher_obj *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ":get_name"))
		return Py_BuildValue("");

	return PyUnicode_FromString(self->cipher->name);
}

static char sslscan_ssl_cipher_get_status_doc[] = "";

static PyObject * sslscan_ssl_cipher_get_status(sslscan_ssl_cipher_obj *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ":get_status"))
		return Py_BuildValue("");

	return PyLong_FromLong(self->status);
}

static char sslscan_ssl_cipher_get_status_name_doc[] = "";

static PyObject * sslscan_ssl_cipher_get_status_name(sslscan_ssl_cipher_obj *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ":get_status_name"))
		return Py_BuildValue("");

	if (self->status == SSLSCAN_CIPHER_STATUS_FAILED)
		return PyUnicode_FromString("failed");
	if (self->status == SSLSCAN_CIPHER_STATUS_REJECTED)
		return PyUnicode_FromString("rejected");
	if (self->status == SSLSCAN_CIPHER_STATUS_ACCEPTED)
		return PyUnicode_FromString("accepted");

	return PyUnicode_FromString("unknown");
}

static PyObject * sslscan_ssl_cipher_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *py_cipher;
	PyObject *py_alerts;
	PyObject *py_status;
	sslscan_ssl_cipher_obj *self;
	self = PyObject_New(sslscan_ssl_cipher_obj, &sslscan_ssl_cipher_Type);
	if (PyArg_ParseTuple(args, "OOO:Alert", &py_cipher, &py_alerts, &py_status)) {
		self->cipher = (struct sslCipher*)PyCapsule_GetPointer(py_cipher, "cipher");
		if (py_alerts == NULL)
			self->alerts = NULL;
		else
			self->alerts = (struct ssl_alert_info*)PyCapsule_GetPointer(py_alerts, "alerts");
		self->status = *(int*)PyCapsule_GetPointer(py_status, "status");
	}

	if (self == NULL) {
		return NULL;
	}

	return (PyObject *)self;
}


static int sslscan_ssl_cipher_tp_init(sslscan_ssl_cipher_obj *self, PyObject *args, PyObject *kwargs)
{
	return 0;
}

#define ADD_METHOD(name) { #name, (PyCFunction)sslscan_ssl_cipher_##name, METH_VARARGS, sslscan_ssl_cipher_##name##_doc }

static PyMethodDef sslscan_ssl_cipher_tp_methods[] = {
	ADD_METHOD(get_alerts),
	ADD_METHOD(get_bits),
	ADD_METHOD(get_method_name),
	ADD_METHOD(get_name),
	ADD_METHOD(get_status),
	ADD_METHOD(get_status_name),
	{NULL, NULL}  /* Sentinel */
};
#undef ADD_METHOD

PyDoc_STRVAR(sslscan_ssl_cipher_tp_doc,
		"Test");

PyTypeObject sslscan_ssl_cipher_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"Cipher",                                  /*tp_name*/
	sizeof(sslscan_ssl_cipher_obj),            /*tp_basicsize*/
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
	Py_TPFLAGS_DEFAULT,                       /*tp_flags*/
	sslscan_ssl_cipher_tp_doc,                 /*tp_doc*/
	0,                                        /*tp_traverse*/
	0,                                        /*tp_clear*/
	0,                                        /*tp_richcompare*/
	0,                                        /*tp_weaklistoffset*/
	0,                                        /*tp_iter*/
	0,                                        /*tp_iternext*/
	sslscan_ssl_cipher_tp_methods,             /*tp_methods*/
	0,                                        /*tp_members*/
	0,                                        /*tp_getsets*/
	0,                                        /*tp_base*/
	0,                                        /*tp_dict*/
	0,                                        /*tp_descr_get*/
	0,                                        /*tp_descr_set*/
	0,                                        /*tp_dictoffset*/
	(initproc)sslscan_ssl_cipher_tp_init,      /*tp_init*/
	0,                                        /*tp_alloc*/
	sslscan_ssl_cipher_tp_new,                 /*tp_new*/
};

