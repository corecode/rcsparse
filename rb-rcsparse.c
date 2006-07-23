#include <ruby.h>

#include "rcsparse.h"


/* Global Variables {{{1 */
static VALUE rb_cRCSFile;
static VALUE rb_cTokMap;
static VALUE rb_cRev;
static VALUE rb_cRevTree;


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

static void
rb_attr2(VALUE klass, const char *attr, int read, int write)
{
	rb_attr(klass, rb_intern(attr), read, write, 0);
}


/* Definition of RCSFile::TokMap {{{1 */
struct rb_tokmap {
	VALUE rb_rf;
	struct rcstokmap *map;
};

static void
rb_tokmap_mark(struct rb_tokmap *tm)
{
	rb_gc_mark(tm->rb_rf);
}

static VALUE
rb_tokmap_new(VALUE rb_rf, struct rcstokmap *map)
{
	struct rb_tokmap *rb_tm;
	VALUE ret;

	ret = Data_Make_Struct(rb_cTokMap, struct rb_tokmap,
				rb_tokmap_mark, free, rb_tm);
	rb_tm->rb_rf = rb_rf;
	rb_tm->map = map;
	return ret;
}

static VALUE
rb_tokmap_aref(VALUE self, VALUE index)
{
	struct rb_tokmap *rb_tm;
	struct rcstokpair s, *f;
	struct rcstoken st;

	Data_Get_Struct(self, struct rb_tokmap, rb_tm);
	StringValue(index);
	s.first = &st;
	st.str = RSTRING(index)->ptr;
	st.len = RSTRING(index)->len;
	f = RB_FIND(rcstokmap, rb_tm->map, &s);
	if (f == NULL)
		return Qnil;
	else
		return str_from_tok(f->second);
}


static void
tokmap_foreach(VALUE self, void (*it)(struct rcstokpair *, VALUE), VALUE arg)
{
	struct rb_tokmap *rb_tm;
	struct rcstokpair *i;

	Data_Get_Struct(self, struct rb_tokmap, rb_tm);
	RB_FOREACH(i, rcstokmap, rb_tm->map)
		it(i, arg);
}

static void
tokmap_each_i(struct rcstokpair *p, VALUE dummy)
{
	rb_yield(rb_assoc_new(str_from_tok(p->first), str_from_tok(p->second)));
}

static VALUE
rb_tokmap_each(VALUE self)
{
	tokmap_foreach(self, tokmap_each_i, 0);
	return self;
}

static void
tokmap_each_pair_i(struct rcstokpair *p, VALUE dummy)
{
	rb_yield_values(2, str_from_tok(p->first), str_from_tok(p->second));
}

static VALUE
rb_tokmap_each_pair(VALUE self)
{
	tokmap_foreach(self, tokmap_each_pair_i, 0);
	return self;
}

static void
tokmap_each_key_i(struct rcstokpair *p, VALUE dummy)
{
	rb_yield(str_from_tok(p->first));
}

static VALUE
rb_tokmap_each_key(VALUE self)
{
	tokmap_foreach(self, tokmap_each_key_i, 0);
	return self;
}

static void
tokmap_each_value_i(struct rcstokpair *p, VALUE dummy)
{
	rb_yield(str_from_tok(p->second));
}

static VALUE
rb_tokmap_each_value(VALUE self)
{
	tokmap_foreach(self, tokmap_each_value_i, 0);
	return self;
}

static VALUE
rb_tokmap_empty_p(VALUE self)
{
	struct rb_tokmap *rb_tm;

	Data_Get_Struct(self, struct rb_tokmap, rb_tm);
	if (RB_EMPTY(rb_tm->map))
		return Qtrue;
	else
		return Qfalse;
}

static VALUE
rb_tokmap_key_p(VALUE self, VALUE index)
{
	struct rb_tokmap *rb_tm;
	struct rcstokpair s, *f;
	struct rcstoken st;

	Data_Get_Struct(self, struct rb_tokmap, rb_tm);
	StringValue(index);
	s.first = &st;
	st.str = RSTRING(index)->ptr;
	st.len = RSTRING(index)->len;
	f = RB_FIND(rcstokmap, rb_tm->map, &s);
	if (f == NULL)
		return Qfalse;
	else
		return Qtrue;
}

static void
tokmap_keys_i(struct rcstokpair *p, VALUE ary)
{
	rb_ary_push(ary, str_from_tok(p->first));
}

static VALUE
rb_tokmap_keys(VALUE self)
{
	VALUE ary;

	ary = rb_ary_new();
	tokmap_foreach(self, tokmap_keys_i, ary);
	return ary;
}

static void
tokmap_values_i(struct rcstokpair *p, VALUE ary)
{
	rb_ary_push(ary, str_from_tok(p->second));
}

static VALUE
rb_tokmap_values(VALUE self)
{
	VALUE ary;

	ary = rb_ary_new();
	tokmap_foreach(self, tokmap_values_i, ary);
	return ary;
}

static void
tokmap_to_a_i(struct rcstokpair *p, VALUE ary)
{
	rb_ary_push(ary, rb_assoc_new(str_from_tok(p->first), str_from_tok(p->second)));
}

static VALUE
rb_tokmap_to_a(VALUE self)
{
	VALUE ary;

	ary = rb_ary_new();
	tokmap_foreach(self, tokmap_to_a_i, ary);
	return ary;
}

static void
tokmap_to_hash_i(struct rcstokpair *p, VALUE hash)
{
	rb_hash_aset(hash, str_from_tok(p->first), str_from_tok(p->second));
}

static VALUE
rb_tokmap_to_hash(VALUE self)
{
	VALUE hash;

	hash = rb_hash_new();
	tokmap_foreach(self, tokmap_to_hash_i, hash);
	return hash;
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

	memset(&tm, 0, sizeof(&tm));
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

	self = rb_obj_alloc(rb_cRev);
	rb_iv_set(self, "@rev", str_from_tok(rev->rev));
	rb_iv_set(self, "@date", rb_time_new(timegm(&tm), 0));
	rb_iv_set(self, "@author", str_from_tok(rev->author));
	rb_iv_set(self, "@state", str_from_tok2(rev->state));
	rb_iv_set(self, "@branches", ary_from_toklist(&rev->branches));
	rb_iv_set(self, "@next", str_from_tok2(rev->next));
	return self;
}


/* Definition of RCSFile::RevTree {{{1 */
struct rb_revtree {
	VALUE rb_rf;
	struct rcsrevtree *tree;
};

static void
rb_revtree_mark(struct rb_revtree *tm)
{
	rb_gc_mark(tm->rb_rf);
}

static VALUE
rb_revtree_new(VALUE rb_rf, struct rcsrevtree *tree)
{
	struct rb_revtree *rb_tm;
	VALUE ret;

	ret = Data_Make_Struct(rb_cRevTree, struct rb_revtree,
				rb_revtree_mark, free, rb_tm);
	rb_tm->rb_rf = rb_rf;
	rb_tm->tree = tree;
	return ret;
}

static VALUE
rb_revtree_aref(VALUE self, VALUE index)
{
	struct rb_revtree *rb_tm;
	struct rcsrev s, *f;
	struct rcstoken st;

	Data_Get_Struct(self, struct rb_revtree, rb_tm);
	StringValue(index);
	s.rev = &st;
	st.str = RSTRING(index)->ptr;
	st.len = RSTRING(index)->len;
	f = RB_FIND(rcsrevtree, rb_tm->tree, &s);
	if (f == NULL)
		return Qnil;
	else
		return rb_rcsrev_new(f);
}


static void
revtree_foreach(VALUE self, void (*it)(struct rcsrev *, VALUE), VALUE arg)
{
	struct rb_revtree *rb_tm;
	struct rcsrev *i;

	Data_Get_Struct(self, struct rb_revtree, rb_tm);
	RB_FOREACH(i, rcsrevtree, rb_tm->tree)
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
	struct rb_revtree *rb_tm;

	Data_Get_Struct(self, struct rb_revtree, rb_tm);
	if (RB_EMPTY(rb_tm->tree))
		return Qtrue;
	else
		return Qfalse;
}

static VALUE
rb_revtree_key_p(VALUE self, VALUE index)
{
	struct rb_revtree *rb_tm;
	struct rcsrev s, *f;
	struct rcstoken st;

	Data_Get_Struct(self, struct rb_revtree, rb_tm);
	StringValue(index);
	s.rev = &st;
	st.str = RSTRING(index)->ptr;
	st.len = RSTRING(index)->len;
	f = RB_FIND(rcsrevtree, rb_tm->tree, &s);
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


/* Definition of RCSFile {{{1 */
static void
rcsfile_free(struct rcsfile *rf)
{
	if (rf != NULL)
		rcsclose(rf);
}

static VALUE
rb_rcsfile_s_alloc(VALUE klass)
{
	return Data_Wrap_Struct(klass, 0, rcsfile_free, 0);
}

static VALUE
rb_rcsfile_initialize(int argc, VALUE *argv, VALUE self)
{
	VALUE fname;
	struct rcsfile *rf;

	rb_scan_args(argc, argv, "1", &fname);
	SafeStringValue(fname);
	rf = rcsopen(RSTRING(fname)->ptr);
	if (rf == NULL)
		rb_sys_fail(RSTRING(fname)->ptr);
	DATA_PTR(self) = rf;
	return self;
}

static struct rcsadmin *
rb_rcsfile_admin_generic(VALUE self)
{
	struct rcsfile *rf;

	Data_Get_Struct(self, struct rcsfile, rf);
	if (rcsparseadmin(rf) < 0)
		rb_raise(rb_eRuntimeError, "Cannot parse RCS file");

	return &rf->admin;
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
	return rb_tokmap_new(self, &rb_rcsfile_admin_generic(self)->symbols);
}

static VALUE
rb_rcsfile_locks(VALUE self)
{
	return rb_tokmap_new(self, &rb_rcsfile_admin_generic(self)->locks);
}

static VALUE
rb_rcsfile_revs(VALUE self)
{
	struct rcsfile *rf;

	Data_Get_Struct(self, struct rcsfile, rf);
	if (rcsparsetree(rf) < 0)
		rb_raise(rb_eRuntimeError, "Cannot parse RCS file");

	return rb_revtree_new(self, &rf->admin.revs);
}

static VALUE
rb_rcsfile_checkout(int argc, VALUE *argv, VALUE self)
{
	VALUE rev;
	VALUE ret;
	struct rcsfile *rf;
	size_t len;
	const char *revstr = NULL;
	char *data;

	Data_Get_Struct(self, struct rcsfile, rf);
	if (rb_scan_args(argc, argv, "01", &rev) == 1) {
		StringValue(rev);
		revstr = RSTRING(rev)->ptr;
	}
	data = rcscheckout(rf, revstr, &len);
	if (data == NULL)
		rb_sys_fail("checkout");
	ret = rb_tainted_str_new(data, len);
	free(data);
	return ret;
}

static VALUE
rb_rcsfile_resolve_sym(int argc, VALUE *argv, VALUE self)
{
	VALUE sym;
	VALUE ret;
	struct rcsfile *rf;
	const char *symstr = "HEAD";
	char *rev;

	Data_Get_Struct(self, struct rcsfile, rf);
	if (rb_scan_args(argc, argv, "01", &sym) == 1) {
		StringValue(sym);
		symstr = RSTRING(sym)->ptr;
	}
	rev = rcsrevfromsym(rf, symstr);
	if (rev == NULL)
		return Qnil;
	ret = rb_tainted_str_new2(rev);
	free(rev);
	return ret;
}

static VALUE
rb_rcsfile_getlog(VALUE self, VALUE rev)
{
	VALUE ret;
	struct rcsfile *rf;
	char *data;

	Data_Get_Struct(self, struct rcsfile, rf);
	StringValue(rev);
	data = rcsgetlog(rf, RSTRING(rev)->ptr);
	if (data == NULL)
		return Qnil;
	ret = rb_tainted_str_new2(data);
	free(data);
	return ret;
}


/* Module initialization {{{1 */
void
Init_rcsparse(void)
{
	rb_cRCSFile = rb_define_class("RCSFile", rb_cObject);
	rb_define_alloc_func(rb_cRCSFile, rb_rcsfile_s_alloc);
	rb_define_method(rb_cRCSFile, "initialize", rb_rcsfile_initialize, -1);
	rb_define_method(rb_cRCSFile, "head", rb_rcsfile_head, 0);
	rb_define_method(rb_cRCSFile, "branch", rb_rcsfile_branch, 0);
	rb_define_method(rb_cRCSFile, "access", rb_rcsfile_access, 0);
	rb_define_method(rb_cRCSFile, "symbols", rb_rcsfile_symbols, 0);
	rb_define_method(rb_cRCSFile, "locks", rb_rcsfile_locks, 0);
	rb_define_method(rb_cRCSFile, "strict", rb_rcsfile_strict, 0);
	rb_define_method(rb_cRCSFile, "comment", rb_rcsfile_comment, 0);
	rb_define_method(rb_cRCSFile, "expand", rb_rcsfile_expand, 0);
	rb_define_method(rb_cRCSFile, "revs", rb_rcsfile_revs, 0);
	rb_define_method(rb_cRCSFile, "desc", rb_rcsfile_desc, 0);
	rb_define_method(rb_cRCSFile, "checkout", rb_rcsfile_checkout, -1);
	rb_define_method(rb_cRCSFile, "resolve_sym", rb_rcsfile_resolve_sym, -1);
	rb_define_method(rb_cRCSFile, "getlog", rb_rcsfile_getlog, 1);

	rb_cTokMap = rb_define_class_under(rb_cRCSFile, "TokMap", rb_cObject);
	rb_include_module(rb_cTokMap, rb_mEnumerable);
	rb_undef_alloc_func(rb_cTokMap);
	rb_define_method(rb_cTokMap, "[]", rb_tokmap_aref, 1);
	rb_define_method(rb_cTokMap, "each", rb_tokmap_each, 0);
	rb_define_method(rb_cTokMap, "each_pair", rb_tokmap_each_pair, 0);
	rb_define_method(rb_cTokMap, "each_key", rb_tokmap_each_key, 0);
	rb_define_method(rb_cTokMap, "each_value", rb_tokmap_each_value, 0);
	rb_define_method(rb_cTokMap, "empty?", rb_tokmap_empty_p, 0);
	rb_define_method(rb_cTokMap, "key?", rb_tokmap_key_p, 1);
	rb_define_method(rb_cTokMap, "has_key?", rb_tokmap_key_p, 1);
	rb_define_method(rb_cTokMap, "include?", rb_tokmap_key_p, 1);
	rb_define_method(rb_cTokMap, "member?", rb_tokmap_key_p, 1);
	rb_define_method(rb_cTokMap, "keys", rb_tokmap_keys, 0);
	rb_define_method(rb_cTokMap, "values", rb_tokmap_values, 0);
	rb_define_method(rb_cTokMap, "to_a", rb_tokmap_to_a, 0);
	rb_define_method(rb_cTokMap, "to_hash", rb_tokmap_to_hash, 0);

	rb_cRev = rb_define_class_under(rb_cRCSFile, "Rev", rb_cObject);
	rb_attr2(rb_cRev, "rev", 1, 0);
	rb_attr2(rb_cRev, "date", 1, 0);
	rb_attr2(rb_cRev, "author", 1, 0);
	rb_attr2(rb_cRev, "state", 1, 0);
	rb_attr2(rb_cRev, "branches", 1, 0);
	rb_attr2(rb_cRev, "next", 1, 0);
	rb_attr2(rb_cRev, "log", 1, 1);

	rb_cRevTree = rb_define_class_under(rb_cRCSFile, "RevTree", rb_cObject);
	rb_include_module(rb_cRevTree, rb_mEnumerable);
	rb_undef_alloc_func(rb_cRevTree);
	rb_define_method(rb_cRevTree, "[]", rb_revtree_aref, 1);
	rb_define_method(rb_cRevTree, "each", rb_revtree_each, 0);
	rb_define_method(rb_cRevTree, "each_pair", rb_revtree_each_pair, 0);
	rb_define_method(rb_cRevTree, "each_key", rb_revtree_each_key, 0);
	rb_define_method(rb_cRevTree, "each_value", rb_revtree_each_value, 0);
	rb_define_method(rb_cRevTree, "empty?", rb_revtree_empty_p, 0);
	rb_define_method(rb_cRevTree, "key?", rb_revtree_key_p, 1);
	rb_define_method(rb_cRevTree, "has_key?", rb_revtree_key_p, 1);
	rb_define_method(rb_cRevTree, "include?", rb_revtree_key_p, 1);
	rb_define_method(rb_cRevTree, "member?", rb_revtree_key_p, 1);
	rb_define_method(rb_cRevTree, "keys", rb_revtree_keys, 0);
	rb_define_method(rb_cRevTree, "values", rb_revtree_values, 0);
	rb_define_method(rb_cRevTree, "to_a", rb_revtree_to_a, 0);
	rb_define_method(rb_cRevTree, "to_hash", rb_revtree_to_hash, 0);
}
