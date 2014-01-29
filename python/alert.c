#include "sslscan_ssl.h"

static char sslscan_ssl_alert_get_description_doc[] = "";

static PyObject * sslscan_ssl_alert_get_description(sslscan_ssl_alert_obj *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ":get_description"))
		return Py_BuildValue("");;

	return PyUnicode_FromString(SSL_alert_desc_string_long(self->ret));
}

static char sslscan_ssl_alert_get_value_doc[] = "";

static PyObject * sslscan_ssl_alert_get_value(sslscan_ssl_alert_obj *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ":get_value"))
		return Py_BuildValue("");

	return PyLong_FromLong(self->ret);
}

static char sslscan_ssl_alert_get_type_doc[] = "";

static PyObject * sslscan_ssl_alert_get_type(sslscan_ssl_alert_obj *self, PyObject *args)
{	
	if (!PyArg_ParseTuple(args, ":get_type"))
		return Py_BuildValue("");;

	return PyUnicode_FromString(SSL_alert_type_string_long(self->ret));
}

static PyObject * sslscan_ssl_alert_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	

	
	PyObject *tmp_obj;
	//PyObject *tmp_obj;
	sslscan_ssl_alert_obj *self;
	self = PyObject_New(sslscan_ssl_alert_obj, &sslscan_ssl_alert_Type);
	if (PyArg_ParseTuple(args, "O:Alert", &tmp_obj)) {
		self->ret = *(int*)PyCapsule_GetPointer(tmp_obj, "ret");
	}

	if (self == NULL) {
		return NULL;
	}

	return (PyObject *)self;
}


static int sslscan_ssl_alert_tp_init(sslscan_ssl_alert_obj *self, PyObject *args, PyObject *kwargs)
{
	return 0;
}

#define ADD_METHOD(name) { #name, (PyCFunction)sslscan_ssl_alert_##name, METH_VARARGS, sslscan_ssl_alert_##name##_doc }

static PyMethodDef sslscan_ssl_alert_tp_methods[] = {
	ADD_METHOD(get_description),
	ADD_METHOD(get_type),
	ADD_METHOD(get_value),
	{NULL, NULL}  /* Sentinel */
};
#undef ADD_METHOD

PyDoc_STRVAR(sslscan_ssl_alert_tp_doc,
		"Test");

PyTypeObject sslscan_ssl_alert_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"Alert",                                  /*tp_name*/
	sizeof(sslscan_ssl_alert_obj),            /*tp_basicsize*/
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
	sslscan_ssl_alert_tp_doc,                 /*tp_doc*/
	0,                                        /*tp_traverse*/
	0,                                        /*tp_clear*/
	0,                                        /*tp_richcompare*/
	0,                                        /*tp_weaklistoffset*/
	0,                                        /*tp_iter*/
	0,                                        /*tp_iternext*/
	sslscan_ssl_alert_tp_methods,             /*tp_methods*/
	0,                                        /*tp_members*/
	0,                                        /*tp_getsets*/
	0,                                        /*tp_base*/
	0,                                        /*tp_dict*/
	0,                                        /*tp_descr_get*/
	0,                                        /*tp_descr_set*/
	0,                                        /*tp_dictoffset*/
	(initproc)sslscan_ssl_alert_tp_init,      /*tp_init*/
	0,                                        /*tp_alloc*/
	sslscan_ssl_alert_tp_new,                 /*tp_new*/
};

