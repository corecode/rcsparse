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

#include <ruby.h>
#include <time.h>

#include "rcsparse.h"


/* Global Variables {{{1 */
static VALUE rb_cRCSFile;
static VALUE rb_cRev;


/* Gobal Helper Functions {{{1 */
static VALUE
str_from_tok(struct rcstoken *tok)
{
	if (tok == NULL)
		rb_raise(rb_eRuntimeError, "Token is NULL");
	return rb_tainted_str_new(tok->str, tok->len);
}

static VALUE
str_from_tok2(struct rcstoken *tok)
{
	if (tok == NULL)
		return Qnil;
	return rb_tainted_str_new(tok->str, tok->len);
}

static VALUE
ary_from_toklist(struct rcstoklist *tl)
{
	VALUE ret;
	struct rcstoken *t;

	ret = rb_ary_new();
	SLIST_FOREACH(t, tl, link)
		rb_ary_push(ret, str_from_tok(t));
	return ret;
}

static VALUE
hash_from_tokmap(struct rcstokmap *map)
{
	VALUE hash;
	struct rcstokpair *p;

	hash = rb_hash_new();
	RB_FOREACH(p, rcstokmap, map)
		rb_hash_aset(hash, str_from_tok(p->first),
			     str_from_tok(p->second));
	return hash;
}

static void
rb_attr2(VALUE klass, const char *attr, int read, int write)
{
	rb_attr(klass, rb_intern(attr), read, write, 0);
}


/* Definition of RCSFile::Rev {{{1 */
static void
readdate(const char *str, int *dest, size_t len)
{
	const char *pos;

	*dest = 0;
	for (pos = str; pos < str + len; pos++) {
		if (*pos < '0' || *pos > '9')
			rb_raise(rb_eRuntimeError, "Invalid date format");
		*dest *= 10;
		*dest += *pos - '0';
	}
}

static VALUE
rb_rcsrev_new(struct rcsrev *rev)
{
	struct tm tm;
	const char *month;
	VALUE self;
	VALUE date;

	memset(&tm, 0, sizeof(tm));
	if (rev->date->len == 17) {
		/* 2-digit year */
		readdate(rev->date->str, &tm.tm_year, 2);
		month = rev->date->str + 3;
	} else {
		/* 4-digit year */
		readdate(rev->date->str, &tm.tm_year, 4);
		tm.tm_year -= 1900;
		month = rev->date->str + 5;
	}

	readdate(month, &tm.tm_mon, 2);
	tm.tm_mon--;
	readdate(month + 3, &tm.tm_mday, 2);
	readdate(month + 6, &tm.tm_hour, 2);
	readdate(month + 9, &tm.tm_min, 2);
	readdate(month + 12, &tm.tm_sec, 2);
	date = rb_time_new(timegm(&tm), 0);
	/*
	 * rb_time_new returns a Time object in local time, so convert
	 * it to GMT, what RCS/CVS uses everywhere.
	 */
	date = rb_funcall(date, rb_intern("gmtime"), 0);

	self = rb_obj_alloc(rb_cRev);
	rb_iv_set(self, "@rev", str_from_tok(rev->rev));
	rb_iv_set(self, "@date", date);
	rb_iv_set(self, "@author", str_from_tok(rev->author));
	rb_iv_set(self, "@state", str_from_tok2(rev->state));
	rb_iv_set(self, "@branches", ary_from_toklist(&rev->branches));
	rb_iv_set(self, "@next", str_from_tok2(rev->next));
	rb_iv_set(self, "@commitid", str_from_tok2(rev->commitid));
	return self;
}


/* Definition of RCSFile {{{1 */
/* Generic functions {{{2 */
struct rb_rcsfile {
	struct rcsfile *rf;
	VALUE symbols;
};

static void
rcsfile_free(struct rb_rcsfile *rb_rf)
{
	if (rb_rf != NULL) {
		if (rb_rf->rf != NULL)
			rcsclose(rb_rf->rf);
		free(rb_rf);
	}
}

static void
rcsfile_mark(struct rb_rcsfile *rb_rf)
{
	rb_gc_mark(rb_rf->symbols);
}

static struct rb_rcsfile *
rcsfile_data(VALUE self)
{
	struct rb_rcsfile *rb_rf;

	Data_Get_Struct(self, struct rb_rcsfile, rb_rf);
	if (rb_rf->rf == NULL)
		rb_raise(rb_eIOError, "closed file");
	return rb_rf;
}

static VALUE
rb_rcsfile_s_alloc(VALUE klass)
{
	struct rb_rcsfile *rb_rf;

	return Data_Make_Struct(klass, struct rb_rcsfile,
				rcsfile_mark, rcsfile_free, rb_rf);
}

static VALUE
rb_rcsfile_initialize(int argc, VALUE *argv, VALUE self)
{
	VALUE fname;
	struct rb_rcsfile *rb_rf;

	Data_Get_Struct(self, struct rb_rcsfile, rb_rf);
	rb_scan_args(argc, argv, "1", &fname);
	SafeStringValue(fname);
	rb_rf->rf = rcsopen(RSTRING_PTR(fname));
	if (rb_rf->rf == NULL)
		rb_sys_fail(RSTRING_PTR(fname));
	rb_rf->symbols = Qnil;
	return self;
}

static VALUE
rb_rcsfile_close(VALUE self)
{
	struct rb_rcsfile *rb_rf = rcsfile_data(self);

	rcsclose(rb_rf->rf);
	rb_rf->rf = NULL;
	return Qnil;
}

static VALUE
rb_rcsfile_s_open(int argc, VALUE *argv, VALUE klass)
{
	VALUE obj;

	obj = rb_rcsfile_s_alloc(klass);
	obj = rb_rcsfile_initialize(argc, argv, obj);

	if (rb_block_given_p())
		return rb_ensure(rb_yield, obj, rb_rcsfile_close, obj);
	else
		return obj;
}

/* Interface to admin fields {{{2 */
static struct rcsadmin *
rb_rcsfile_admin_generic(VALUE self)
{
	struct rb_rcsfile *rb_rf = rcsfile_data(self);

	if (rcsparseadmin(rb_rf->rf) < 0)
		rb_raise(rb_eRuntimeError, "Cannot parse RCS file");

	return &rb_rf->rf->admin;
}

static VALUE
rb_rcsfile_head(VALUE self)
{
	struct rcstoken *tok = rb_rcsfile_admin_generic(self)->head;

	if (tok == NULL)
		return Qnil;
	return str_from_tok(tok);
}

static VALUE
rb_rcsfile_branch(VALUE self)
{
	struct rcstoken *tok = rb_rcsfile_admin_generic(self)->branch;

	if (tok == NULL)
		return Qnil;
	return str_from_tok(tok);
}

static VALUE
rb_rcsfile_comment(VALUE self)
{
	struct rcstoken *tok = rb_rcsfile_admin_generic(self)->comment;

	if (tok == NULL)
		return Qnil;
	return str_from_tok(tok);
}

static VALUE
rb_rcsfile_expand(VALUE self)
{
	struct rcstoken *tok = rb_rcsfile_admin_generic(self)->expand;

	if (tok == NULL)
		return Qnil;
	return str_from_tok(tok);
}

static VALUE
rb_rcsfile_desc(VALUE self)
{
	struct rcstoken *tok = rb_rcsfile_admin_generic(self)->desc;

	if (tok == NULL)
		return Qnil;
	return str_from_tok(tok);
}

static VALUE
rb_rcsfile_access(VALUE self)
{
	return ary_from_toklist(
	    &rb_rcsfile_admin_generic(self)->access);
}

static VALUE
rb_rcsfile_strict(VALUE self)
{
	int strict = rb_rcsfile_admin_generic(self)->strict;

	if (strict)
		return Qtrue;
	else
		return Qfalse;
}

static VALUE
rb_rcsfile_symbols(VALUE self)
{
	struct rb_rcsfile *rb_rf = rcsfile_data(self);

	if (NIL_P(rb_rf->symbols)) {
		rb_rf->symbols = hash_from_tokmap(
		    &rb_rcsfile_admin_generic(self)->symbols);
	}
	return rb_rf->symbols;
}

static VALUE
rb_rcsfile_locks(VALUE self)
{
	return hash_from_tokmap(&rb_rcsfile_admin_generic(self)->locks);
}

static VALUE
rb_rcsfile_checkout(int argc, VALUE *argv, VALUE self)
{
	struct rb_rcsfile *rb_rf = rcsfile_data(self);
	VALUE rev;
	VALUE ret;
	size_t len;
	const char *revstr = NULL;
	char *data;

	if (rb_scan_args(argc, argv, "01", &rev) == 1) {
		StringValue(rev);
		revstr = RSTRING_PTR(rev);
	}
	data = rcscheckout(rb_rf->rf, revstr, &len);
	if (data == NULL)
		rb_raise(rb_eRuntimeError, "Cannot parse RCS file");
	ret = rb_tainted_str_new(data, len);
	free(data);
	return ret;
}

static VALUE
rb_rcsfile_resolve_sym(int argc, VALUE *argv, VALUE self)
{
	struct rb_rcsfile *rb_rf = rcsfile_data(self);
	VALUE sym;
	VALUE ret;
	const char *symstr = "HEAD";
	char *rev;

	if (rb_scan_args(argc, argv, "01", &sym) == 1) {
		StringValue(sym);
		symstr = RSTRING_PTR(sym);
	}
	rev = rcsrevfromsym(rb_rf->rf, symstr);
	if (rev == NULL)
		return Qnil;
	ret = rb_tainted_str_new2(rev);
	free(rev);
	return ret;
}

static VALUE
rb_rcsfile_getlog(VALUE self, VALUE rev)
{
	struct rb_rcsfile *rb_rf = rcsfile_data(self);
	VALUE ret;
	char *data;

	StringValue(rev);
	data = rcsgetlog(rb_rf->rf, RSTRING_PTR(rev));
	if (data == NULL)
		return Qnil;
	ret = rb_tainted_str_new2(data);
	free(data);
	return ret;
}

/* Hash-like interface {{{2 */
static struct rcsrevtree *
rb_rcsfile_revs(VALUE self)
{
	struct rb_rcsfile *rb_rf = rcsfile_data(self);

	if (rcsparsetree(rb_rf->rf) < 0)
		rb_raise(rb_eRuntimeError, "Cannot parse RCS file");

	return &rb_rf->rf->admin.revs;
}

static VALUE
rb_revtree_aref(VALUE self, VALUE index)
{
	struct rcsrev s, *f;
	struct rcstoken st;

	StringValue(index);
	s.rev = &st;
	st.str = RSTRING_PTR(index);
	st.len = RSTRING_LEN(index);
	f = RB_FIND(rcsrevtree, rb_rcsfile_revs(self), &s);
	if (f == NULL)
		return Qnil;
	else
		return rb_rcsrev_new(f);
}


static void
revtree_foreach(VALUE self, void (*it)(struct rcsrev *, VALUE), VALUE arg)
{
	struct rcsrev *i;

	RB_FOREACH(i, rcsrevtree, rb_rcsfile_revs(self))
		it(i, arg);
}

static void
revtree_each_i(struct rcsrev *r, VALUE dummy)
{
	rb_yield(rb_assoc_new(str_from_tok(r->rev), rb_rcsrev_new(r)));
}

static VALUE
rb_revtree_each(VALUE self)
{
	revtree_foreach(self, revtree_each_i, 0);
	return self;
}

static void
revtree_each_pair_i(struct rcsrev *r, VALUE dummy)
{
	rb_yield_values(2, str_from_tok(r->rev), rb_rcsrev_new(r));
}

static VALUE
rb_revtree_each_pair(VALUE self)
{
	revtree_foreach(self, revtree_each_pair_i, 0);
	return self;
}

static void
revtree_each_key_i(struct rcsrev *r, VALUE dummy)
{
	rb_yield(str_from_tok(r->rev));
}

static VALUE
rb_revtree_each_key(VALUE self)
{
	revtree_foreach(self, revtree_each_key_i, 0);
	return self;
}

static void
revtree_each_value_i(struct rcsrev *r, VALUE dummy)
{
	rb_yield(rb_rcsrev_new(r));
}

static VALUE
rb_revtree_each_value(VALUE self)
{
	revtree_foreach(self, revtree_each_value_i, 0);
	return self;
}

static VALUE
rb_revtree_empty_p(VALUE self)
{
	if (RB_EMPTY(rb_rcsfile_revs(self)))
		return Qtrue;
	else
		return Qfalse;
}

static VALUE
rb_revtree_key_p(VALUE self, VALUE index)
{
	struct rcsrev s, *f;
	struct rcstoken st;

	StringValue(index);
	s.rev = &st;
	st.str = RSTRING_PTR(index);
	st.len = RSTRING_LEN(index);
	f = RB_FIND(rcsrevtree, rb_rcsfile_revs(self), &s);
	if (f == NULL)
		return Qfalse;
	else
		return Qtrue;
}

static void
revtree_keys_i(struct rcsrev *r, VALUE ary)
{
	rb_ary_push(ary, str_from_tok(r->rev));
}

static VALUE
rb_revtree_keys(VALUE self)
{
	VALUE ary;

	ary = rb_ary_new();
	revtree_foreach(self, revtree_keys_i, ary);
	return ary;
}

static void
revtree_values_i(struct rcsrev *r, VALUE ary)
{
	rb_ary_push(ary, rb_rcsrev_new(r));
}

static VALUE
rb_revtree_values(VALUE self)
{
	VALUE ary;

	ary = rb_ary_new();
	revtree_foreach(self, revtree_values_i, ary);
	return ary;
}

static void
revtree_to_a_i(struct rcsrev *r, VALUE ary)
{
	rb_ary_push(ary, rb_assoc_new(str_from_tok(r->rev), rb_rcsrev_new(r)));
}

static VALUE
rb_revtree_to_a(VALUE self)
{
	VALUE ary;

	ary = rb_ary_new();
	revtree_foreach(self, revtree_to_a_i, ary);
	return ary;
}

static void
revtree_to_hash_i(struct rcsrev *r, VALUE hash)
{
	rb_hash_aset(hash, str_from_tok(r->rev), rb_rcsrev_new(r));
}

static VALUE
rb_revtree_to_hash(VALUE self)
{
	VALUE hash;

	hash = rb_hash_new();
	revtree_foreach(self, revtree_to_hash_i, hash);
	return hash;
}



/* Module initialization {{{1 */
void
Init_rcsfile(void)
{
	rb_cRCSFile = rb_define_class("RCSFile", rb_cObject);
	rb_define_alloc_func(rb_cRCSFile, rb_rcsfile_s_alloc);
	rb_define_singleton_method(rb_cRCSFile, "open", rb_rcsfile_s_open, -1);
	rb_define_method(rb_cRCSFile, "initialize", rb_rcsfile_initialize, -1);
	rb_define_method(rb_cRCSFile, "close", rb_rcsfile_close, 0);
	rb_define_method(rb_cRCSFile, "head", rb_rcsfile_head, 0);
	rb_define_method(rb_cRCSFile, "branch", rb_rcsfile_branch, 0);
	rb_define_method(rb_cRCSFile, "access", rb_rcsfile_access, 0);
	rb_define_method(rb_cRCSFile, "symbols", rb_rcsfile_symbols, 0);
	rb_define_method(rb_cRCSFile, "locks", rb_rcsfile_locks, 0);
	rb_define_method(rb_cRCSFile, "strict", rb_rcsfile_strict, 0);
	rb_define_method(rb_cRCSFile, "comment", rb_rcsfile_comment, 0);
	rb_define_method(rb_cRCSFile, "expand", rb_rcsfile_expand, 0);
	rb_define_method(rb_cRCSFile, "desc", rb_rcsfile_desc, 0);
	rb_define_method(rb_cRCSFile, "checkout", rb_rcsfile_checkout, -1);
	rb_define_method(rb_cRCSFile, "resolve_sym", rb_rcsfile_resolve_sym, -1);
	rb_define_method(rb_cRCSFile, "getlog", rb_rcsfile_getlog, 1);

	/* Hash-like interface to revs */
	rb_include_module(rb_cRCSFile, rb_mEnumerable);
	rb_define_method(rb_cRCSFile, "[]", rb_revtree_aref, 1);
	rb_define_method(rb_cRCSFile, "each", rb_revtree_each, 0);
	rb_define_method(rb_cRCSFile, "each_pair", rb_revtree_each_pair, 0);
	rb_define_method(rb_cRCSFile, "each_key", rb_revtree_each_key, 0);
	rb_define_method(rb_cRCSFile, "each_value", rb_revtree_each_value, 0);
	rb_define_method(rb_cRCSFile, "empty?", rb_revtree_empty_p, 0);
	rb_define_method(rb_cRCSFile, "key?", rb_revtree_key_p, 1);
	rb_define_method(rb_cRCSFile, "has_key?", rb_revtree_key_p, 1);
	rb_define_method(rb_cRCSFile, "include?", rb_revtree_key_p, 1);
	rb_define_method(rb_cRCSFile, "member?", rb_revtree_key_p, 1);
	rb_define_method(rb_cRCSFile, "keys", rb_revtree_keys, 0);
	rb_define_method(rb_cRCSFile, "values", rb_revtree_values, 0);
	rb_define_method(rb_cRCSFile, "to_a", rb_revtree_to_a, 0);
	rb_define_method(rb_cRCSFile, "to_hash", rb_revtree_to_hash, 0);

	rb_cRev = rb_define_class_under(rb_cRCSFile, "Rev", rb_cObject);
	rb_attr2(rb_cRev, "rev", 1, 0);
	rb_attr2(rb_cRev, "date", 1, 0);
	rb_attr2(rb_cRev, "author", 1, 0);
	rb_attr2(rb_cRev, "state", 1, 0);
	rb_attr2(rb_cRev, "branches", 1, 0);
	rb_attr2(rb_cRev, "next", 1, 0);
	rb_attr2(rb_cRev, "commitid", 1, 0);
	rb_attr2(rb_cRev, "log", 1, 1);
}
