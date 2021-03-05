/*
 * This file is part of rcsparse.
 *
 * rcsparse is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * rcsparse is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with rcsparse.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <Python.h>

#include <sys/types.h>
#include <stdint.h>

#include "queue.h"

#include "rcsparse.h"


#if PY_MAJOR_VERSION >= 3
#define PyString_AsStringAndSize	_PyUnicode_AsUTF8AndSize
#define PyString_CheckExact		PyUnicode_CheckExact
#define PyString_FromString		PyUnicode_FromString
#define PyString_FromStringAndSize	PyUnicode_FromStringAndSize
#endif

static void
_PyUnicode_AsUTF8AndSize(PyObject *obj, char **strp, Py_ssize_t *sizep)
{
	*strp = PyUnicode_AsUTF8AndSize(obj, sizep);
}

static PyObject *
rcstoken2pystr(struct rcstoken *tok)
{
	if (tok == NULL)
		Py_RETURN_NONE;

	return PyString_FromStringAndSize(tok->str, tok->len);
}

static PyObject *
rcstoklist2py(struct rcstoklist *head)
{
	PyObject *list;
	struct rcstoken *tok;

	list = PyList_New(0);
	if (list == NULL)
		return NULL;

	for (tok = SLIST_FIRST(head); tok != NULL; tok = SLIST_NEXT(tok, link)) {
		PyObject *o;

		o = rcstoken2pystr(tok);
		if (PyList_Append(list, o) < 0) {
			Py_XDECREF(o);
			Py_XDECREF(list);
			return NULL;
		}
		Py_XDECREF(o);
	}

	return list;
}

struct pyrcsrevtree {
	PyObject_HEAD
	struct pyrcsfile *pyrcs;
	struct rcsrevtree *tree;
};

static int
pyrcsrevtree_find_internal(struct pyrcsrevtree *self, PyObject *key, struct rcsrev **frev)
{
	struct rcsrev rev;
	struct rcstoken tok;
	Py_ssize_t l;

	if (!PyString_CheckExact(key))
		return -1;

	PyString_AsStringAndSize(key, &tok.str, &l);
	if (l < 0)
		return -1;
	tok.len = (unsigned)l;
	rev.rev = &tok;
	*frev = RB_FIND(rcsrevtree, self->tree, &rev);
	return *frev != NULL;
}

static PyObject *
rcsrev2py(struct rcsrev *rev)
{
	struct tm tm;
	const char *month;

	bzero(&tm, sizeof(struct tm));

#define	readdate(str, dest, len)	do {	\
	const char *pos;			\
	int scale;				\
	for (pos = str + len - 1, scale = 1; pos >= str; pos--, scale *= 10)	\
		if (*pos < '0' || *pos > '9')	\
			return PyErr_Format(PyExc_RuntimeError, "Invalid date format");	\
		else				\
			dest += scale * (*pos - '0');	\
	} while (0)

	if (rev->date->len == 17) {
		/* 2-digit year */
		readdate(rev->date->str, tm.tm_year, 2);
		month = rev->date->str + 3;
	} else {
		/* 4-digit year */
		readdate(rev->date->str, tm.tm_year, 4);
		tm.tm_year -= 1900;
		month = rev->date->str + 5;
	}

	readdate(month, tm.tm_mon, 2);
	tm.tm_mon--;
	readdate(month + 3, tm.tm_mday, 2);
	readdate(month + 6, tm.tm_hour, 2);
	readdate(month + 9, tm.tm_min, 2);
	readdate(month + 12, tm.tm_sec, 2);

#undef readdate

	return Py_BuildValue("NNNNNNN",
			rcstoken2pystr(rev->rev),
#if PY_MAJOR_VERSION >= 3
			PyLong_FromLong(timegm(&tm)),
#else
			PyInt_FromLong(timegm(&tm)),
#endif
			rcstoken2pystr(rev->author),
			rcstoken2pystr(rev->state),
			rcstoklist2py(&rev->branches),
			rcstoken2pystr(rev->next),
			rcstoken2pystr(rev->commitid));
}

static PyObject *
pyrcsrevtree_find(struct pyrcsrevtree *self, PyObject *key)
{
	struct rcsrev *frev;

	switch (pyrcsrevtree_find_internal(self, key, &frev))
	{
	case 1:
		return rcsrev2py(frev);
	case 0:
		PyErr_SetObject(PyExc_KeyError, key);
		return NULL;
	case -1:
	default:
		return NULL;
	}
}

static PyObject *
pyrcsrevtree_get(struct pyrcsrevtree *self, PyObject *args)
{
	PyObject *key, *def = Py_None;
	struct rcsrev *frev;

	if (!PyArg_ParseTuple(args, "O|O", &key, &def))
		return NULL;

	switch (pyrcsrevtree_find_internal(self, key, &frev)) {
	case 1:
		return rcsrev2py(frev);
	case 0:
		return Py_INCREF(def), def;
	case -1:
	default:
		return NULL;
	}
}

static int
pyrcsrevtree_contains(struct pyrcsrevtree *self, PyObject *key)
{
	struct rcsrev *rev;

	return pyrcsrevtree_find_internal(self, key, &rev);
}

static PyObject *
pyrcsrevtree_has_key(struct pyrcsrevtree *self, PyObject *key)
{
	switch (pyrcsrevtree_contains(self, key)) {
	case 1:
		Py_RETURN_TRUE;
	case 0:
		Py_RETURN_FALSE;
	case -1:
	default:
		return NULL;
	}
}

static PyObject *
pyrcsrevtree_items(struct pyrcsrevtree *self)
{
	PyObject *list;
	struct rcsrev *rev;

	list = PyList_New(0);
	if (list == NULL)
		return NULL;

	for (rev = RB_MIN(rcsrevtree, self->tree); rev != NULL; rev = RB_NEXT(rcsrevtree, self->tree, rev)) {
		PyObject *f, *s, *p;

		f = rcstoken2pystr(rev->rev);
		s = rcsrev2py(rev);
		p = PyTuple_Pack(2, f, s);
		Py_XDECREF(f);
		Py_XDECREF(s);
		if (PyList_Append(list, p) < 0) {
			Py_XDECREF(p);
			Py_DECREF(list);
			return NULL;
		}
		Py_XDECREF(p);
	}

	return list;
}

static PyObject *
pyrcsrevtree_keys(struct pyrcsrevtree *self)
{
	PyObject *list;
	struct rcsrev *rev;

	list = PyList_New(0);
	if (list == NULL)
		return NULL;

	for (rev = RB_MIN(rcsrevtree, self->tree); rev != NULL; rev = RB_NEXT(rcsrevtree, self->tree, rev)) {
		PyObject *i;

		i = rcstoken2pystr(rev->rev);
		if (PyList_Append(list, i) < 0) {
			Py_XDECREF(i);
			Py_DECREF(list);
			return NULL;
		}
		Py_XDECREF(i);
	}

	return list;
}

static PyObject *
pyrcsrevtree_values(struct pyrcsrevtree *self)
{
	PyObject *list;
	struct rcsrev *rev;

	list = PyList_New(0);
	if (list == NULL)
		return NULL;

	for (rev = RB_MIN(rcsrevtree, self->tree); rev != NULL; rev = RB_NEXT(rcsrevtree, self->tree, rev)) {
		PyObject *i;

		i = rcsrev2py(rev);
		if (PyList_Append(list, i) < 0) {
			Py_XDECREF(i);
			Py_DECREF(list);
			return NULL;
		}
		Py_XDECREF(i);
	}

	return list;
}

static void
pyrcsrevtree_dealloc(struct pyrcsrevtree *self)
{
	Py_DECREF((PyObject *)self->pyrcs);
	Py_TYPE(self)->tp_free(self);
}

static PyMappingMethods pyrcsrevtree_mapmethods = {
	NULL,
	(binaryfunc)pyrcsrevtree_find,
	NULL
};

static PySequenceMethods pyrcsrevtree_seqmethods = {
	.sq_contains=	(objobjproc)pyrcsrevtree_contains
};

static PyMethodDef pyrcsrevtree_methods[] = {
	{"__contains__",(PyCFunction)pyrcsrevtree_has_key,	METH_O | METH_COEXIST, NULL},
	{"__getitem__",	(PyCFunction)pyrcsrevtree_find,		METH_O | METH_COEXIST, NULL},
	{"has_key",	(PyCFunction)pyrcsrevtree_has_key,	METH_O, NULL},
	{"get",		(PyCFunction)pyrcsrevtree_get,		METH_VARARGS, NULL},
	{"keys",	(PyCFunction)pyrcsrevtree_keys,		METH_NOARGS, NULL},
	{"items",	(PyCFunction)pyrcsrevtree_items,	METH_NOARGS, NULL},
	{"values",	(PyCFunction)pyrcsrevtree_values,	METH_NOARGS, NULL},
	{NULL}
};

static PyTypeObject pyrcsrevtree_type = {
	PyVarObject_HEAD_INIT(&PyType_Type, 0)
	.tp_name=		"rcsparse.rcsrevtree",
	.tp_basicsize=		sizeof(struct pyrcsrevtree),
	.tp_dealloc=		(destructor)pyrcsrevtree_dealloc,
	.tp_as_mapping=		&pyrcsrevtree_mapmethods,
	.tp_as_sequence=	&pyrcsrevtree_seqmethods,
	.tp_flags=		Py_TPFLAGS_DEFAULT,
	.tp_doc=		"RCS Revision Tree Map",
	.tp_new=		PyType_GenericNew,
	.tp_methods=		pyrcsrevtree_methods
};

static PyObject *
rcsrevtree2py(struct pyrcsfile *pyrcs, struct rcsrevtree *tree)
{
	struct pyrcsrevtree *pytree;

	if (tree == NULL)
		Py_RETURN_NONE;

	pytree = PyObject_New(struct pyrcsrevtree, &pyrcsrevtree_type);
	pytree->pyrcs = pyrcs;
	Py_INCREF((PyObject *)pyrcs);
	pytree->tree = tree;
	return (PyObject *)pytree;
}


struct pyrcstokmap {
	PyObject_HEAD
	struct pyrcsfile *pyrcs;
	struct rcstokmap *map;
};

static int
pyrcstokmap_find_internal(struct pyrcstokmap *self, PyObject *key, struct rcstokpair **fpair)
{
	struct rcstokpair pair;
	struct rcstoken tok;
	Py_ssize_t l;

	if (!PyString_CheckExact(key))
		return -1;

	PyString_AsStringAndSize(key, &tok.str, &l);
	if (l < 0)
		return -1;
	tok.len = (unsigned)l;
	pair.first = &tok;
	*fpair = RB_FIND(rcstokmap, self->map, &pair);
	return *fpair != NULL;
}

static PyObject *
pyrcstokmap_find(struct pyrcstokmap *self, PyObject *key)
{
	struct rcstokpair *fpair;

	switch (pyrcstokmap_find_internal(self, key, &fpair))
	{
	case 1:
		return rcstoken2pystr(fpair->second);
	case 0:
		PyErr_SetObject(PyExc_KeyError, key);
		return NULL;
	case -1:
	default:
		return NULL;
	}
}

static PyObject *
pyrcstokmap_get(struct pyrcstokmap *self, PyObject *args)
{
	PyObject *key, *def = Py_None;
	struct rcstokpair *fpair;

	if (!PyArg_ParseTuple(args, "O|O", &key, &def))
		return NULL;

	switch (pyrcstokmap_find_internal(self, key, &fpair)) {
	case 1:
		return rcstoken2pystr(fpair->second);
	case 0:
		return Py_INCREF(def), def;
	case -1:
	default:
		return NULL;
	}
}

static int
pyrcstokmap_contains(struct pyrcstokmap *self, PyObject *key)
{
	struct rcstokpair *pair;

	return pyrcstokmap_find_internal(self, key, &pair);
}

static PyObject *
pyrcstokmap_has_key(struct pyrcstokmap *self, PyObject *key)
{
	switch (pyrcstokmap_contains(self, key)) {
	case 1:
		Py_RETURN_TRUE;
	case 0:
		Py_RETURN_FALSE;
	case -1:
	default:
		return NULL;
	}
}

static PyObject *
pyrcstokmap_items(struct pyrcstokmap *self)
{
	PyObject *list;
	struct rcstokpair *pair;

	list = PyList_New(0);
	if (list == NULL)
		return NULL;

	for (pair = RB_MIN(rcstokmap, self->map); pair != NULL; pair = RB_NEXT(rcstokmap, self->map, pair)) {
		PyObject *f, *s, *p;

		f = rcstoken2pystr(pair->first);
		s = rcstoken2pystr(pair->second);
		p = PyTuple_Pack(2, f, s);
		Py_XDECREF(f);
		Py_XDECREF(s);
		if (PyList_Append(list, p) < 0) {
			Py_XDECREF(p);
			Py_DECREF(list);
			return NULL;
		}
		Py_XDECREF(p);
	}

	return list;
}

static PyObject *
pyrcstokmap_keys(struct pyrcstokmap *self)
{
	PyObject *list;
	struct rcstokpair *pair;

	list = PyList_New(0);
	if (list == NULL)
		return NULL;

	for (pair = RB_MIN(rcstokmap, self->map); pair != NULL; pair = RB_NEXT(rcstokmap, self->map, pair)) {
		PyObject *i;

		i = rcstoken2pystr(pair->first);
		if (PyList_Append(list, i) < 0) {
			Py_XDECREF(i);
			Py_DECREF(list);
			return NULL;
		}
		Py_XDECREF(i);
	}

	return list;
}

static PyObject *
pyrcstokmap_values(struct pyrcstokmap *self)
{
	PyObject *list;
	struct rcstokpair *pair;

	list = PyList_New(0);
	if (list == NULL)
		return NULL;

	for (pair = RB_MIN(rcstokmap, self->map); pair != NULL; pair = RB_NEXT(rcstokmap, self->map, pair)) {
		PyObject *i;

		i = rcstoken2pystr(pair->second);
		if (PyList_Append(list, i) < 0) {
			Py_XDECREF(i);
			Py_DECREF(list);
			return NULL;
		}
		Py_XDECREF(i);
	}

	return list;
}

static void
pyrcstokmap_dealloc(struct pyrcstokmap *self)
{
	Py_DECREF((PyObject *)self->pyrcs);
	Py_TYPE(self)->tp_free(self);
}

static PyMappingMethods pyrcstokmap_mapmethods = {
	NULL,
	(binaryfunc)pyrcstokmap_find,
	NULL
};

static PySequenceMethods pyrcstokmap_seqmethods = {
	.sq_contains=	(objobjproc)pyrcstokmap_contains
};

static PyMethodDef pyrcstokmap_methods[] = {
	{"__contains__",(PyCFunction)pyrcstokmap_has_key,	METH_O | METH_COEXIST, NULL},
	{"__getitem__",	(PyCFunction)pyrcstokmap_find,		METH_O | METH_COEXIST, NULL},
	{"has_key",	(PyCFunction)pyrcstokmap_has_key,	METH_O, NULL},
	{"get",		(PyCFunction)pyrcstokmap_get,		METH_VARARGS, NULL},
	{"keys",	(PyCFunction)pyrcstokmap_keys,		METH_NOARGS, NULL},
	{"items",	(PyCFunction)pyrcstokmap_items,		METH_NOARGS, NULL},
	{"values",	(PyCFunction)pyrcstokmap_values,	METH_NOARGS, NULL},
	{NULL}
};

static PyTypeObject pyrcstokmap_type = {
	PyVarObject_HEAD_INIT(&PyType_Type, 0)
	.tp_name=		"rcsparse.rcstokmap",
	.tp_basicsize=		sizeof(struct pyrcstokmap),
	.tp_dealloc=		(destructor)pyrcstokmap_dealloc,
	.tp_as_mapping=		&pyrcstokmap_mapmethods,
	.tp_as_sequence=	&pyrcstokmap_seqmethods,
	.tp_flags=		Py_TPFLAGS_DEFAULT,
	.tp_doc=		"RCS Token Map",
	.tp_new=		PyType_GenericNew,
	.tp_methods=		pyrcstokmap_methods
};

static PyObject *
rcstokmap2py(struct pyrcsfile *pyrcs, struct rcstokmap *map)
{
	struct pyrcstokmap *pymap;

	if (map == NULL)
		Py_RETURN_NONE;

	pymap = PyObject_New(struct pyrcstokmap, &pyrcstokmap_type);
	pymap->pyrcs = pyrcs;
	Py_INCREF((PyObject *)pyrcs);
	pymap->map = map;
	return (PyObject *)pymap;
}


struct pyrcsfile {
	PyObject_HEAD
	struct rcsfile *rcs;
};

enum {
	PYRCSADM_HEAD,
	PYRCSADM_BRANCH,
	PYRCSADM_SYMBOLS,
	PYRCSADM_LOCKS,
	PYRCSADM_COMMENT,
	PYRCSADM_EXPAND,
	PYRCSADM_DESC,
};

static PyObject *
pyrcsfile_getstr(struct pyrcsfile *self, void *closure)
{
	struct rcstoken *tok;
	struct rcsadmin *adm;

	if (rcsparseadmin(self->rcs) < 0)
		return PyErr_Format(PyExc_RuntimeError, "Error parsing");

	adm = &self->rcs->admin;

	switch ((int)(uintptr_t)closure) {
	case PYRCSADM_HEAD:	tok = adm->head; break;
	case PYRCSADM_BRANCH:	tok = adm->branch; break;
	case PYRCSADM_COMMENT:	tok = adm->comment; break;
	case PYRCSADM_EXPAND:	tok = adm->expand; break;
	case PYRCSADM_DESC:	tok = adm->desc; break;
	default:
		return PyErr_Format(PyExc_RuntimeError, "Wrong closure");
	}

	return rcstoken2pystr(tok);
}

static PyObject *
pyrcsfile_gettokmap(struct pyrcsfile *self, void *closure)
{
	struct rcstokmap *map;
	struct rcsadmin *adm;

	if (rcsparseadmin(self->rcs) < 0)
		return PyErr_Format(PyExc_RuntimeError, "Error parsing");

	adm = &self->rcs->admin;

	switch ((int)(uintptr_t)closure) {
	case PYRCSADM_SYMBOLS:	map = &adm->symbols; break;
	case PYRCSADM_LOCKS:	map = &adm->locks; break;
	default:
		return PyErr_Format(PyExc_RuntimeError, "Wrong closure");
	}

	return rcstokmap2py(self, map);
}

static PyObject *
pyrcsfile_getaccess(struct pyrcsfile *self, void *closure)
{
	if (rcsparseadmin(self->rcs) < 0)
		return PyErr_Format(PyExc_RuntimeError, "Error parsing");

	return rcstoklist2py(&self->rcs->admin.access);
}

static PyObject *
pyrcsfile_getstrict(struct pyrcsfile *self, void *closure)
{
	if (rcsparseadmin(self->rcs) < 0)
		return PyErr_Format(PyExc_RuntimeError, "Error parsing");

	if (self->rcs->admin.strict)
		Py_RETURN_TRUE;
	else
		Py_RETURN_FALSE;
}

static PyObject *
pyrcsfile_checkout(struct pyrcsfile *self, PyObject *args)
{
	PyObject *o;
	const char *rev = "HEAD";
	char *buf;
	size_t len;

	if (!PyArg_ParseTuple(args, "|s", &rev))
		return NULL;

	buf = rcscheckout(self->rcs, rev, &len);
	if (buf == NULL)
		return PyErr_Format(PyExc_RuntimeError, "Error parsing");

#if PY_MAJOR_VERSION >= 3
	o = PyBytes_FromStringAndSize(buf, len);
#else
	o = PyString_FromStringAndSize(buf, len);
#endif
	free(buf);
	return o;
}

static PyObject *
pyrcsfile_getlog(struct pyrcsfile *self, PyObject *args)
{
	PyObject *o;
	const char *rev;
	char *buf;

	if (!PyArg_ParseTuple(args, "s", &rev))
		return NULL;

	buf = rcsgetlog(self->rcs, rev);
	if (buf == NULL)
		return PyErr_Format(PyExc_RuntimeError, "Error parsing");

#if PY_MAJOR_VERSION >= 3
	o = PyBytes_FromString(buf);
#else
	o = PyString_FromString(buf);
#endif
	free(buf);
	return o;
}

static PyObject *
pyrcsfile_sym2rev(struct pyrcsfile *self, PyObject *args)
{
	PyObject *o;
	const char *rev = "HEAD";
	char *buf;

	if (!PyArg_ParseTuple(args, "|s", &rev))
		return NULL;

	buf = rcsrevfromsym(self->rcs, rev);
	if (buf == NULL)
		return PyErr_Format(PyExc_RuntimeError, "Error parsing");

	o = PyString_FromString(buf);
	free(buf);
	return o;
}

static PyObject *
pyrcsfile_getrevs(struct pyrcsfile *self, void *closure)
{
	if (rcsparsetree(self->rcs) < 0)
		return PyErr_Format(PyExc_RuntimeError, "Error parsing");

	return rcsrevtree2py(self, &self->rcs->admin.revs);
}

static int
pyrcsfile_init(struct pyrcsfile *pyrcs, PyObject *args)
{
	const char *filename;

	if (!PyArg_ParseTuple(args, "s", &filename))
		return -1;

	pyrcs->rcs = rcsopen(filename);
	if (pyrcs->rcs == NULL) {
		PyErr_SetFromErrnoWithFilename(PyExc_IOError, (char *)(long)filename);
		return -1;
	}

	return 0;
}

static void
pyrcsfile_dealloc(struct pyrcsfile *self)
{
	if (self->rcs != NULL)
		rcsclose(self->rcs);

	Py_TYPE(self)->tp_free(self);
}

static PyGetSetDef pyrcsfile_getseters[] = {
	{"head",	(getter)pyrcsfile_getstr,	NULL,	"rcsfile head data",	(void *)PYRCSADM_HEAD},
	{"branch",	(getter)pyrcsfile_getstr,	NULL,	"rcsfile branch data",	(void *)PYRCSADM_BRANCH},
	{"access",	(getter)pyrcsfile_getaccess,	NULL,	"rcsfile access data",	NULL},
	{"symbols",	(getter)pyrcsfile_gettokmap,	NULL,	"rcsfile symbols data",	(void *)PYRCSADM_SYMBOLS},
	{"locks",	(getter)pyrcsfile_gettokmap,	NULL,	"rcsfile locks data",	(void *)PYRCSADM_LOCKS},
	{"strict",	(getter)pyrcsfile_getstrict,	NULL,	"rcsfile strict data",	NULL},
	{"comment",	(getter)pyrcsfile_getstr,	NULL,	"rcsfile comment data",	(void *)PYRCSADM_COMMENT},
	{"expand",	(getter)pyrcsfile_getstr,	NULL,	"rcsfile expand data",	(void *)PYRCSADM_EXPAND},
	{"revs",	(getter)pyrcsfile_getrevs,	NULL,	"rcsfile revs data",	NULL},
	{"desc",	(getter)pyrcsfile_getstr,	NULL,	"rcsfile desc data",	(void *)PYRCSADM_DESC},
	{NULL}
};

static PyMethodDef pyrcsfile_methods[] = {
	{"checkout",	(PyCFunction)pyrcsfile_checkout,	METH_VARARGS,	NULL},
	{"getlog",	(PyCFunction)pyrcsfile_getlog,		METH_VARARGS,	NULL},
	{"sym2rev",	(PyCFunction)pyrcsfile_sym2rev,		METH_VARARGS,	NULL},
	{NULL}
};

static PyTypeObject pyrcsfile_type = {
	PyObject_HEAD_INIT(&PyType_Type)
	.tp_name=		"rcsparse.rcsfile",
	.tp_basicsize=		sizeof(struct pyrcsfile),
	.tp_dealloc=		(destructor)pyrcsfile_dealloc,
	.tp_flags=		Py_TPFLAGS_DEFAULT,
	.tp_doc=		"RCS File",
	.tp_getset=		pyrcsfile_getseters,
	.tp_init=		(initproc)pyrcsfile_init,
	.tp_new=		PyType_GenericNew,
	.tp_methods=		pyrcsfile_methods,
};

static PyMethodDef pyrcsparse_methods[] = {
	{NULL}
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"rcsparse",		/* m_name */
	"RCS file parser",	/* m_doc */
	-1,			/* m_size */
	pyrcsparse_methods,	/* m_methods */
	NULL,			/* m_reload */
	NULL,			/* m_traverse */
	NULL,			/* m_clear */
	NULL,			/* m_free */
};
#endif

#if PY_MAJOR_VERSION >= 3
#define retnull return NULL

PyMODINIT_FUNC
PyInit_rcsparse(void)
#else
#define retnull return

PyMODINIT_FUNC
initrcsparse(void)
#endif
{
	PyObject *m;

	if (PyType_Ready(&pyrcsfile_type) < 0)
		retnull;
	if (PyType_Ready(&pyrcstokmap_type) < 0)
		retnull;
	if (PyType_Ready(&pyrcsrevtree_type) < 0)
		retnull;

#if PY_MAJOR_VERSION >= 3
	m = PyModule_Create(&moduledef);
#else
	m = Py_InitModule3("rcsparse", pyrcsparse_methods, "RCS file parser");
#endif
	if (m == NULL)
		retnull;

	Py_INCREF(&pyrcsfile_type);
	PyModule_AddObject(m, "rcsfile", (PyObject *)&pyrcsfile_type);
	Py_INCREF(&pyrcstokmap_type);
	PyModule_AddObject(m, "rcstokmap", (PyObject *)&pyrcstokmap_type);
	Py_INCREF(&pyrcsrevtree_type);
	PyModule_AddObject(m, "rcsrevtree", (PyObject *)&pyrcsrevtree_type);

#if PY_MAJOR_VERSION >= 3
	return m;
#endif
}
