#include <Python.h>

/**
 * Wrapper to call a python function. It prepares all required objects and handles errors.
 *
 * @param py_object The object
 * @param name The name of the function to call
 * @param py_args Arguments to pass to the python function. NULL if nothing to pass.
 * @param py_result Pointer to a result object. NULL if not used.
 * @return 0 = no errors; 1 = an error occurred
 */
int py_call_function(PyObject *py_obj, const char *name, PyObject *py_args, PyObject **py_result)
{
	PyObject *py_func;
	PyObject *py_tmp;

	py_func = PyObject_GetAttrString(py_obj, name);
	if (py_func == NULL) {
		PyErr_Print();
		return 1;
	}

	if (py_args == NULL)
		py_args = PyTuple_New(0);

	py_tmp = PyObject_CallObject(py_func, py_args);

	if (py_tmp == NULL) {
		PyErr_Print();
		return 1;
	}

	if (py_result != NULL) {
		*py_result = py_tmp;
	}

	return 0;
}

