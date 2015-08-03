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

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "queue.h"
#include "tree.h"

#include "rcsparse.h"

struct line {
	char		*str;
	size_t		len;
	size_t		atcount;
};

struct stringinfo {
	size_t		size;
	size_t		pos;
	struct line	lines[0];
};

#define	STRNFO_LINES	8

struct rcsdelta {
	SLIST_ENTRY(rcsdelta) link;
	int		action;
	size_t		pos;
	size_t		len;
	struct line	*lines;
};


static int cmprev(struct rcsrev *, struct rcsrev *);
static int cmptokpair(struct rcstokpair *, struct rcstokpair *);
static struct rcstoken *checktok(struct rcsfile *);
static int skipws(struct rcsfile *);
static struct rcstoken *parsestring(struct rcsfile *, struct stringinfo **);
static struct rcstoken *parsetoken(struct rcsfile *);
static int tokcmp(struct rcstoken *, struct rcstoken *);
static int tokeqtok(struct rcstoken *, struct rcstoken *);
static int tokeqstr(struct rcstoken *, const char *);
static int tokeqstrn(struct rcstoken *, const char *, size_t);
static int expecttok(struct rcsfile *, int);
static int opttok(struct rcsfile *, int);
static int expecttokstr(struct rcsfile *, const char *);
static int opttokstr(struct rcsfile *, const char *);
static char *strnfo2txtbuf(struct stringinfo *, size_t *);
static int applydelta(struct stringinfo **, struct stringinfo *);


RB_GENERATE(rcsrevtree, rcsrev, link, cmprev);
RB_GENERATE(rcstokmap, rcstokpair, link, cmptokpair);

static int
cmprev(struct rcsrev *rev1, struct rcsrev *rev2)
{
	return tokcmp(rev1->rev, rev2->rev);
}

static int
cmptokpair(struct rcstokpair *pair1, struct rcstokpair *pair2)
{
	return tokcmp(pair1->first, pair2->first);
}

static struct rcstoken *
checktok(struct rcsfile *rcs)
{
	if (rcs->tok == NULL)
		rcs->lasttok = rcs->tok = calloc(1, sizeof(struct rcstoken));

	return rcs->tok;
}

static int
resizestrnfo(struct stringinfo **si, size_t len)
{
	size_t newsize;

	newsize = (*si)->size;
	while (len > newsize)
		newsize *= 2;

	if (newsize > (*si)->size) {
		struct stringinfo *nsi;

		nsi = realloc(*si, sizeof(struct stringinfo) +
		    newsize * sizeof(struct line));
		if (nsi == NULL)
			return -1;
		nsi->size = newsize;
		*si = nsi;
	}

	return 0;
}

static struct stringinfo *
copystrnfo(struct stringinfo *si)
{
	struct stringinfo *nsi;
	size_t size;

	size = sizeof(*si) + si->size * sizeof(si->lines[0]);
	nsi = malloc(size);
	if (nsi == NULL)
		return NULL;
	memcpy(nsi, si, size);
	return nsi;
}

static int
skipws(struct rcsfile *rcs)
{
	for (; rcs->pos < rcs->end; rcs->pos++) {
		switch (*rcs->pos) {
		case ' ':
		case '\b':
		case '\t':
		case '\n':
		case '\r':
		case '\v':
		case '\f':
			continue;
		}

		break;
	}

	return rcs->pos == rcs->end ? -1 : 0;
}

static struct rcstoken *
parsestring(struct rcsfile *rcs, struct stringinfo **sip)
{
	int atcount;
	struct stringinfo *si = NULL;
	struct rcstoken *tok;

	if (skipws(rcs) < 0)
		return NULL;

	if (*rcs->pos != '@')
		return NULL;

	tok = checktok(rcs);
	if (tok == NULL)
		return NULL;

	rcs->pos++;

	if (sip != NULL) {
		*sip = NULL;
		si = malloc(sizeof(struct stringinfo) + STRNFO_LINES * sizeof(struct line));
		if (si == NULL)
			return NULL;

		si->size = STRNFO_LINES;
		si->pos = 0;
		si->lines[0].str = rcs->pos;
		si->lines[0].atcount = 0;
	}

	tok->str = rcs->pos;
	atcount = 0;
	for (; rcs->pos < rcs->end; rcs->pos++) {
		switch (*rcs->pos) {
		case '\n':
			if (si != NULL) {
				if (resizestrnfo(&si, si->pos + 2) < 0)
					goto fail;

				si->lines[si->pos].len = rcs->pos - si->lines[si->pos].str + 1;
				si->pos++;
				si->lines[si->pos].str = rcs->pos + 1;
				si->lines[si->pos].atcount = 0;
			}
			continue;

		case '@':
			if (rcs->pos + 1 == rcs->end)
				goto fail;

			rcs->pos++;
			if (*rcs->pos != '@')
				break;

			atcount++;
			if (si != NULL)
				si->lines[si->pos].atcount++;
			continue;

		default:
			continue;
		}

		/* If we reached this point, we need to finish */

		break;
	}

	if (si != NULL) {
		si->lines[si->pos].len = rcs->pos - si->lines[si->pos].str - 1;
		if (si->lines[si->pos].len != 0)	/* last line didn't end with '\n' */
			si->pos++;
		*sip = si;
	}

	tok->len = rcs->pos - tok->str - 1;
	tok->type = atcount > 0 ? TOK_STRINGAT : TOK_STRING;

	return tok;

fail:
	if (si != NULL)
		free(si);

	return NULL;
}

static struct rcstoken *
parsetoken(struct rcsfile *rcs)
{
	int ch;
	int type;
	int finish;
	struct rcstoken *tok;

	if (skipws(rcs) < 0)
		return NULL;

	tok = checktok(rcs);

	ch = *rcs->pos;
	switch (ch) {
	case ';':
	case ':':
	case ',':
	case '$':
		tok->type = ch;
		tok->str = rcs->pos;
		rcs->pos++;
		tok->len = 1;
		return tok;

	case '@':
		return parsestring(rcs, NULL);
	}

	tok->str = rcs->pos;
	type = 0;
	finish = 0;
	while (rcs->pos < rcs->end && !finish) {
		ch = *rcs->pos;
		switch (ch) {
		case ' ':
		case '\b':
		case '\t':
		case '\n':
		case '\r':
		case '\v':
		case '\f':
		case ';':
		case ':':
		case ',':
		case '$':
		case '@':
			finish = 1;
			continue;
		}

		if (isdigit(ch))
			type |= TOK_DIGIT;
		else if (ch == '.')
			type |= TOK_DOT;
		else
			type |= TOK_PRINT;

		rcs->pos++;
	}

	tok->type = type;
	tok->len = rcs->pos - tok->str;

	return tok;
}

static int
tokcmp(struct rcstoken *tok1, struct rcstoken *tok2)
{
	char *pos1, *pos2, *end1, *end2;

	pos1 = tok1->str;
	end1 = pos1 + tok1->len;
	pos2 = tok2->str;
	end2 = pos2 + tok2->len;
	for (; pos1 < end1 && pos2 < end2; pos1++, pos2++)
		if (*pos1 != *pos2)
			return *pos1 - *pos2;

	if (pos1 == end1) {
		if (pos2 == end2)
			return 0;
		else
			return -1;
	} else {
		return 1;
	}
}

static int
tokeqtok(struct rcstoken *tok1, struct rcstoken *tok2)
{
	return tokcmp(tok1, tok2) == 0;
}

static int
tokeqstr(struct rcstoken *tok, const char *str)
{
	char *pos, *endpos;

	pos = tok->str;
	endpos = pos + tok->len;
	for (; pos < endpos && *str; pos++, str++) {
		if (*str != *pos)
			return 0;
	}

	if (pos == endpos && *str == '\0')
		return 1;
	else
		return 0;
}

static int
tokeqstrn(struct rcstoken *tok, const char *str, size_t len)
{
	char *pos, *endpos;

	if (tok->len < len)
		return 0;

	pos = tok->str;
	endpos = pos + tok->len;
	for (; len && *str; pos++, str++, len--) {
		if (*str != *pos)
			return 0;
	}

	return len == 0 ? 1 : 0;
}

static int
expecttok(struct rcsfile *rcs, int type)
{
	if (parsetoken(rcs) == NULL)
		return -2;

	if (rcs->tok->type == type)
		return 0;
	else
		return -1;
}

static int
opttok(struct rcsfile *rcs, int type)
{
	return expecttok(rcs, type) + 1;
}

static int
expecttokstr(struct rcsfile *rcs, const char *str)
{
	if (parsetoken(rcs) == NULL)
		return -2;

	return tokeqstr(rcs->tok, str) ? 0 : -1;
}

static int
opttokstr(struct rcsfile *rcs, const char *str)
{
	int ret;

	ret = expecttokstr(rcs, str);
	if (ret == -1)
		rcs->pos = rcs->tok->str;

	return ret + 1;
}

static char *
tokstripat(struct rcstoken *tok)
{
	char *ret;

	ret = malloc(tok->len + 1);
	if (ret == NULL)
		return NULL;

	if (tok->type == TOK_STRING) {
		bcopy(tok->str, ret, tok->len);
		ret[tok->len] = '\0';
	} else {
		char *endpos, *at, *ipos, *opos;

		ipos = tok->str;
		endpos = ipos + tok->len;
		opos = ret;
		while ((at = memchr(ipos, '@', endpos - ipos)) != NULL) {
			bcopy(ipos, opos, at - ipos + 1);
			opos += at - ipos + 1;
			ipos = at + 2;
		}
		bcopy(ipos, opos, endpos - ipos);
		opos += endpos - ipos;
		*opos = '\0';
	}

	return ret;
}

static char *
strnfo2txtbuf(struct stringinfo *si, size_t *plen)
{
	struct line *curline;
	size_t lineno, len;
	char *pos, *ret;

	for (len = lineno = 0; lineno < si->pos; lineno++)
		len += si->lines[lineno].len;

	ret = malloc(len + 1);
	if (ret == NULL)
		return NULL;
	ret[len] = '\0';

	pos = ret;
	for (lineno = 0, curline = si->lines; lineno < si->pos; lineno++, curline++) {
		if (curline->atcount == 0) {
			bcopy(curline->str, pos, curline->len);
			pos += curline->len;
		} else {
			char *oldpos, *newpos, *endpos;
			size_t atn;

			oldpos = curline->str;
			endpos = oldpos + curline->len;
			for (atn = 0; atn < curline->atcount; atn++) {
				newpos = memchr(oldpos, '@', endpos - oldpos);
				bcopy(oldpos, pos, newpos - oldpos + 1);
				pos += newpos - oldpos + 1;
				oldpos = newpos + 2;
			}
			bcopy(oldpos, pos, endpos - oldpos);
			pos += endpos - oldpos;
		}
	}

	if (plen != NULL)
		*plen = pos - ret;

	return ret;
}

static int
applydelta(struct stringinfo **text, struct stringinfo *deltatext)
{
	SLIST_HEAD(, rcsdelta) deltas;
	struct rcsdelta *curdelta;
	struct stringinfo *curtext;
	size_t lineno;
	int ret = -1;

	curdelta = NULL;
	SLIST_INIT(&deltas);

	curtext = *text;
	for (lineno = 0; lineno < deltatext->pos; lineno++) {
		char *pos, *endpos;

		pos = deltatext->lines[lineno].str;
		endpos = pos + deltatext->lines[lineno].len;
		if (endpos - pos < 5)	/* check for minimum */
			goto fail;

		curdelta = calloc(1, sizeof(struct rcsdelta));
		if (curdelta == NULL)
			goto fail;

		if (*pos != 'a' && *pos != 'd')
			goto fail;
		curdelta->action = *pos;
		pos++;
		for (curdelta->pos = 0; pos < endpos && isdigit(*pos); pos++)
			curdelta->pos = curdelta->pos * 10 + *pos - '0';

		if (pos == endpos || *pos++ != ' ' || pos == endpos)
			goto fail;

		for (curdelta->len = 0; pos < endpos && isdigit(*pos); pos++)
			curdelta->len = curdelta->len * 10 + *pos - '0';

		if (pos == endpos || *pos != '\n')
			goto fail;

		if (curdelta->len == 0)
			goto fail;

		if (curdelta->action == 'a') {
			curdelta->lines = &deltatext->lines[lineno + 1];
			lineno += curdelta->len;
		}

		SLIST_INSERT_HEAD(&deltas, curdelta, link);
		curdelta = NULL;
	}

	if (lineno != deltatext->pos)
		goto fail;

	while ((curdelta = SLIST_FIRST(&deltas)) != NULL) {
		SLIST_REMOVE_HEAD(&deltas, link);

		switch (curdelta->action) {
		case 'a':
			if (resizestrnfo(&curtext, curtext->pos + curdelta->len) < 0)
				goto fail;

			bcopy(&curtext->lines[curdelta->pos],
			    &curtext->lines[curdelta->pos + curdelta->len],
			    (curtext->pos - curdelta->pos) * sizeof(struct line));
			bcopy(curdelta->lines,
			    &curtext->lines[curdelta->pos],
			    curdelta->len * sizeof(struct line));
			curtext->pos += curdelta->len;
			break;
		case 'd':
			if (curdelta->pos <= 0 ||
			    curdelta->pos > curtext->pos ||
			    curdelta->pos + curdelta->len - 1 > curtext->pos)
				goto fail;
			bcopy(&curtext->lines[curdelta->pos + curdelta->len - 1],
			    &curtext->lines[curdelta->pos - 1],
			    (curtext->pos - curdelta->pos - curdelta->len + 1) *
			    sizeof(struct line));
			curtext->pos -= curdelta->len;
			break;
		}

		free(curdelta);
	}

	ret = 0;

fail:
	if (curdelta != NULL)
		free(curdelta);
	while ((curdelta = SLIST_FIRST(&deltas)) != NULL) {
		SLIST_REMOVE_HEAD(&deltas, link);
		free(curdelta);
	}
	*text = curtext;

	return ret;
}

static void
rcsfreerev(struct rcsrev *rev)
{
	struct rcstoken *tok;

	free(rev->rev);
	free(rev->date);
	free(rev->author);
	if (rev->state != NULL)
		free(rev->state);
	if (rev->next != NULL)
		free(rev->next);
	while ((tok = SLIST_FIRST(&rev->branches)) != NULL) {
		SLIST_REMOVE_HEAD(&rev->branches, link);
		free(tok);
	}
	if (rev->commitid != NULL)
		free(rev->commitid);
	if (rev->log != NULL)
		free(rev->log);
	if (rev->rawtext != NULL)
		free(rev->rawtext);
	if (rev->text != NULL)
		free(rev->text);

	free(rev);
}

int
rcsparseadmin(struct rcsfile *rcs)
{
	if (rcs->revpos != NULL)
		return 0;

	if (expecttokstr(rcs, "head") < 0)
		return -1;

	if (opttok(rcs, ';') == 0) {
		if ((rcs->tok->type & ~TOK_NUM) != 0)
			return -1;

		rcs->admin.head = rcs->tok;
		rcs->tok = NULL;
		if (expecttok(rcs, ';') < 0)
			return -1;
	}

	if (opttokstr(rcs, "branch") > 0) {
		if (opttok(rcs, ';') == 0) {
			if ((rcs->tok->type & ~TOK_NUM) != 0)
				return -1;

			rcs->admin.branch = rcs->tok;
			rcs->tok = NULL;
			if (expecttok(rcs, ';') < 0)
				return -1;
		}
	}

	if (expecttokstr(rcs, "access") < 0)
		return -1;
	while (opttok(rcs, ';') == 0) {
		SLIST_INSERT_HEAD(&rcs->admin.access, rcs->tok, link);
		rcs->tok = NULL;
	}

	if (expecttokstr(rcs, "symbols") < 0)
		return -1;
	while (opttok(rcs, ';') == 0) {
		struct rcstokpair *pair;

		if ((rcs->tok->type & TOK_DOT) != 0)
			return -1;
		pair = calloc(1, sizeof(struct rcstokpair));
		if (pair == NULL)
			return -1;

		pair->first = rcs->tok;
		rcs->tok = NULL;

		if (expecttok(rcs, ':') < 0 ||
		    parsetoken(rcs) == NULL ||
		    (rcs->tok->type & ~TOK_NUM) != 0) {
			free(pair);
			return -1;
		}

		pair->second = rcs->tok;
		rcs->tok = NULL;

		RB_INSERT(rcstokmap, &rcs->admin.symbols, pair);
	}

	if (expecttokstr(rcs, "locks") < 0)
		return -1;
	while (opttok(rcs, ';') == 0) {
		struct rcstokpair *pair;

		pair = calloc(1, sizeof(struct rcstokpair));
		if (pair == NULL)
			return -1;

		pair->first = rcs->tok;
		rcs->tok = NULL;

		if (expecttok(rcs, ':') < 0 ||
		    parsetoken(rcs) == NULL ||
		    (rcs->tok->type & ~TOK_NUM) != 0) {
			free(pair);
			return -1;
		}

		pair->second = rcs->tok;
		rcs->tok = NULL;

		RB_INSERT(rcstokmap, &rcs->admin.locks, pair);
	}

	if (opttokstr(rcs, "strict") > 0) {
		rcs->admin.strict = 1;
		if (expecttok(rcs, ';') < 0)
			return -1;
	}

	if (opttokstr(rcs, "comment") > 0) {
		if (opttok(rcs, ';') == 0) {
			rcs->admin.comment = rcs->tok;
			rcs->tok = NULL;
			if (expecttok(rcs, ';') < 0)
			    return -1;
		}
	}

	if (opttokstr(rcs, "expand") > 0) {
		if (opttok(rcs, ';') == 0) {
			rcs->admin.expand = rcs->tok;
			rcs->tok = NULL;
			if (expecttok(rcs, ';') < 0)
			    return -1;
		}
	}

	for (;;) {
		rcs->revpos = rcs->pos;

		if (parsetoken(rcs) == NULL)
			return -1;
		if (tokeqstr(rcs->tok, "desc")) {
			rcs->pos = rcs->tok->str;
			break;
		}
		if ((rcs->tok->type & ~TOK_NUM) == 0) {
			rcs->pos = rcs->tok->str;
			break;
		}

		while (opttok(rcs, ';') == 0)
			;
	}

	return 0;
}

int
rcsparsetree(struct rcsfile *rcs)
{
	struct rcsrev searchrev;
	struct rcsrev *rev = NULL;

	if (rcs->deltapos != NULL)
		return 0;

	if (rcsparseadmin(rcs) < 0)
		return -1;

	rcs->pos = rcs->revpos;

	for (;;) {
		if (parsetoken(rcs) == NULL)
			return -1;

		if (tokeqstr(rcs->tok, "desc")) {
			rcs->pos = rcs->tok->str;
			break;
		}

		rev = calloc(1, sizeof(struct rcsrev));
		if (rev == NULL)
			return -1;

		if ((rcs->tok->type & ~TOK_NUM) != 0)
			goto fail;
		rev->rev = rcs->tok;
		rcs->tok = NULL;

		if (expecttokstr(rcs, "date") < 0)
			goto fail;
		if (expecttok(rcs, TOK_NUM) < 0)
			goto fail;
		if (rcs->tok->len != 17 && rcs->tok->len != 19)
			goto fail;
		rev->date = rcs->tok;
		rcs->tok = NULL;
		if (expecttok(rcs, ';') < 0)
			goto fail;

		if (expecttokstr(rcs, "author") < 0)
			goto fail;
		if (parsetoken(rcs) == NULL)
			goto fail;
		if ((rcs->tok->type & (TOK_STRING | TOK_PRINT)) != TOK_PRINT)
			goto fail;
		rev->author = rcs->tok;
		rcs->tok = NULL;
		if (expecttok(rcs, ';') < 0)
			goto fail;

		if (expecttokstr(rcs, "state") < 0)
			goto fail;
		if (opttok(rcs, ';') == 0) {
			rev->state = rcs->tok;
			rcs->tok = NULL;
			if (expecttok(rcs, ';') < 0)
				goto fail;
		}

		if (expecttokstr(rcs, "branches") < 0)
			goto fail;
		while (opttok(rcs, ';') == 0) {
			SLIST_INSERT_HEAD(&rev->branches, rcs->tok, link);
			rcs->tok = NULL;
		}

		if (expecttokstr(rcs, "next") < 0)
			goto fail;
		if (opttok(rcs, ';') == 0) {
			rev->next = rcs->tok;
			rcs->tok = NULL;
			if (expecttok(rcs, ';') < 0)
				goto fail;
		}
		if (expecttokstr(rcs, "commitid") < 0) {
			/* No hit, rewind */
			rcs->pos = rcs->tok->str;
		} else {
			if (parsetoken(rcs) == NULL)
				goto fail;
			rev->commitid = rcs->tok;
			rcs->tok = NULL;
			if (expecttok(rcs, ';') < 0)
				goto fail;
		}

		for (;;) {
			if (parsetoken(rcs) == NULL)
				return -1;
			if (tokeqstr(rcs->tok, "desc")) {
				rcs->pos = rcs->tok->str;
				break;
			}
			if ((rcs->tok->type & ~TOK_NUM) == 0) {
				rcs->pos = rcs->tok->str;
				break;
			}

			while (opttok(rcs, ';') == 0)
				;
		}

		RB_INSERT(rcsrevtree, &rcs->admin.revs, rev);
		rev = NULL;
	}

	parsetoken(rcs);		/* We *know* it is good */
	if (parsetoken(rcs) == NULL)
		return -1;
	rcs->admin.desc = rcs->tok;
	rcs->tok = NULL;

	rcs->deltapos = rcs->pos;

	/* There are empty RCS files around */
	if (rcs->admin.head == NULL)
		return 0;

	if (parsetoken(rcs) == NULL)
		goto fail;
	if ((rcs->tok->type & ~TOK_NUM) != 0)
		goto fail;
	if (!tokeqtok(rcs->tok, rcs->admin.head))
		goto fail;

	searchrev.rev = rcs->tok;
	rev = RB_FIND(rcsrevtree, &rcs->admin.revs, &searchrev);
	if (rev == NULL)
		goto fail;

	rev->logpos = rcs->pos;

	return 0;

fail:
	if (rev != NULL)
		rcsfreerev(rev);

	return -1;
}

static int
rcsparsetext(struct rcsfile *rcs, struct rcsrev *rrev)
{
	struct rcsrev searchrev;

	if (rrev->log != NULL)
		return 0;

	if (rrev->logpos == NULL)
		return -1;

	rcs->pos = rrev->logpos;

	if (expecttokstr(rcs, "log") < 0)
		return -1;

	if (parsestring(rcs, NULL) == NULL)
		return -1;

	if (rrev->log == NULL) {
		rrev->log = rcs->tok;
		rcs->tok = NULL;
	}

	for (;;) {
		if (parsetoken(rcs) == NULL)
			return -1;
		if (tokeqstr(rcs->tok, "text"))
			break;

		while (opttok(rcs, ';') == 0)
			;
	}

	if (parsestring(rcs, &rrev->rawtext) == NULL)
		return -1;

	if (parsetoken(rcs) == NULL)
		return (0);	/* could be end of file */
	if ((rcs->tok->type & ~TOK_NUM) != 0)
		return -1;

	searchrev.rev = rcs->tok;
	rrev->nextlog = RB_FIND(rcsrevtree, &rcs->admin.revs, &searchrev);
	if (rrev->nextlog == NULL)
		return (-1);

	rrev->nextlog->logpos = rcs->pos;
	return 0;
}

char *
rcscheckout(struct rcsfile *rcs, const char *revstr, size_t *len)
{
	struct rcsrev searchrev;
	struct rcstoken searchtok;
	struct rcsrev *currcsrev, *curtextrev;
	struct stringinfo *curtext;
	struct rcstoken *nextrev;
	char *branchrev, *tmpstr;
	char *retbuf, *rev;

	if (rcsparsetree(rcs) < 0)
		return NULL;

	curtextrev = NULL;
	curtext = NULL;
	nextrev = NULL;
	branchrev = NULL;
	retbuf = NULL;

	rev = rcsrevfromsym(rcs, revstr);
	if (rev == NULL)
		goto fail;

	searchtok.str = rev;
	searchtok.len = strlen(rev);
	searchrev.rev = &searchtok;
	currcsrev = RB_FIND(rcsrevtree, &rcs->admin.revs, &searchrev);
	if (currcsrev == NULL)
		goto fail;

	curtext = currcsrev->text;
	if (curtext != NULL)
		goto done;

	branchrev = strdup(rev);
	if (branchrev == NULL)
		goto fail;
	tmpstr = strchr(branchrev, '.');
	if (tmpstr != NULL)
		tmpstr = strchr(tmpstr + 1, '.');
	if (tmpstr != NULL)
		*tmpstr = '\0';

	searchrev.rev = rcs->admin.head;
	currcsrev = RB_FIND(rcsrevtree, &rcs->admin.revs, &searchrev);
	if (currcsrev == NULL)
		goto fail;

	for (; currcsrev != NULL; currcsrev = currcsrev->nextlog) {
		if (rcsparsetext(rcs, currcsrev) < 0)
			goto fail;

		if (curtext == NULL) {
			curtext = currcsrev->rawtext;
			curtextrev = currcsrev;
		} else {
			if (nextrev == NULL)
				goto fail;

			if (!tokeqtok(currcsrev->rev, nextrev))
				continue;

			if (currcsrev->text) {
				/* Was expanded before */
				if (curtextrev != NULL) {
					free(curtextrev->text);
					curtextrev->text = NULL;
				}
				curtext = currcsrev->text;
				curtextrev = currcsrev;
			} else {
				if (currcsrev->rawtext == NULL)
					goto fail;
				currcsrev->text = copystrnfo(curtext);
				if (currcsrev->text == NULL)
					goto fail;
				if (applydelta(&currcsrev->text, currcsrev->rawtext) < 0)
					goto fail;
				if (curtextrev != NULL) {
					free(curtextrev->text);
					curtextrev->text = NULL;
				}
				curtext = currcsrev->text;
				curtextrev = currcsrev;
			}
		}

		if (tokeqstr(currcsrev->rev, rev))
			break;

		if (tokeqstr(currcsrev->rev, branchrev)) {
			size_t cmplen;

			*tmpstr = '.';
			tmpstr = strchr(tmpstr + 1, '.');
			if (tmpstr != NULL)
				cmplen = tmpstr - branchrev + 1;
			else
				cmplen = strlen(branchrev) + 1;

			SLIST_FOREACH(nextrev, &currcsrev->branches, link)
				if (tokeqstrn(nextrev, branchrev, cmplen))
					break;

			if (tmpstr != NULL) {
				tmpstr = strchr(tmpstr + 1, '.');
				if (tmpstr != NULL)
					*tmpstr = '\0';
			}
		} else {
			nextrev = currcsrev->next;
		}
	}

	if (currcsrev == NULL)
		goto fail;

done:
	if (tokeqstr(currcsrev->state, "dead")) {
		/* TODO: optimize this case */
		retbuf = strdup("");
		if (len != NULL)
			*len = 0;
	} else {
		retbuf = strnfo2txtbuf(curtext, len);
	}

fail:
	if (rev != NULL)
		free(rev);

	free(branchrev);
	return retbuf;
}

char *
rcsrevfromsym(struct rcsfile *rcs, const char *sym)
{
	struct rcsrev findrev, *rev;
	struct rcstokpair findpair, *pair;
	struct rcstoken findtok, branchtok, *tok;
	char *pos, *endpos;
	char *lastdot, *last2dot;
	char *retrev;
	size_t dotcount;
	int issym, searchbranch;

	/* To check head we only need admin info */
	if (rcsparseadmin(rcs) < 0)
		return NULL;

	/* Handle special symbol "HEAD" */
	if (sym == NULL || strcmp(sym, "HEAD") == 0) {
		if (rcs->admin.branch == NULL) {
			tok = rcs->admin.head;
			goto found;
		} else {
			findtok = *rcs->admin.branch;
		}
	} else {
		findtok.str = (char *)(unsigned long)sym;
		findtok.len = strlen(sym);
	}

	/* We really need to wade in the revs, so parse them as well */
	if (rcsparsetree(rcs) < 0)
		return NULL;

	dotcount = 0;
	issym = 0;
	lastdot = last2dot = NULL;
	for (pos = findtok.str, endpos = pos + findtok.len; pos < endpos; pos++) {
		if (*pos == '.') {
			/* Two adjacent dots are invalid */
			if (pos == lastdot + 1)
				return NULL;
			dotcount++;
			last2dot = lastdot;
			lastdot = pos;
		} else if (!isdigit(*pos)) {
			issym = 1;
		}
	}

	if (issym && dotcount > 0)
		return NULL;
	if (*findtok.str == '.' || findtok.len == 0 || findtok.str[findtok.len - 1] == '.')
		return NULL;

	if (issym) {
		findpair.first = &findtok;
		pair = RB_FIND(rcstokmap, &rcs->admin.symbols, &findpair);
		if (pair == NULL)
			return NULL;

		findtok = *pair->second;
		for (pos = findtok.str, endpos = pos + findtok.len; pos < endpos; pos++) {
			if (*pos == '.') {
				/* Two adjacent dots are invalid */
				if (pos == lastdot + 1)
					return NULL;
				dotcount++;
				last2dot = lastdot;
				lastdot = pos;
			} else if (!isdigit(*pos)) {
				return NULL;
			}
		}
	}

	searchbranch = 0;
	if (dotcount == 0) {
		branchtok = findtok;
		findtok = *rcs->admin.head;
	} else if (dotcount % 2 == 0 ||
	    (last2dot != NULL && lastdot - last2dot == 2 && *(last2dot + 1) == '0')) {
		/*
		 * We are explicitly searching for a branch or
		 * seeking a magic branch.
		 */
		branchtok.str = lastdot + 1;
		branchtok.len = findtok.str + findtok.len - branchtok.str;
		if (dotcount % 2 == 0)
			findtok.len = lastdot - findtok.str;
		else
			findtok.len = last2dot - findtok.str;

		searchbranch = 1;
	}

	findrev.rev = &findtok;
	rev = RB_FIND(rcsrevtree, &rcs->admin.revs, &findrev);
	if (rev == NULL)
		return NULL;

	if (searchbranch) {
		struct rcsrev *nextrev;
		char *branchstr;
		size_t branchlen;

		/* First locate the right branch, then climb up */
		branchlen = rev->rev->len + branchtok.len + 3;
		branchstr = malloc(branchlen);
		if (branchstr == NULL)
			return NULL;

		bcopy(rev->rev->str, branchstr, rev->rev->len);
		branchstr[rev->rev->len] = '.';
		bcopy(branchtok.str, branchstr + rev->rev->len + 1, branchtok.len);
		branchstr[branchlen - 2] = '.';
		branchstr[branchlen - 1] = '\0';

		SLIST_FOREACH(tok, &rev->branches, link)
		    if (tokeqstrn(tok, branchstr, branchlen - 1))
			    break;

		free(branchstr);

		findrev.rev = tok;
		while (findrev.rev != NULL &&
		    (nextrev = RB_FIND(rcsrevtree, &rcs->admin.revs, &findrev)) != NULL) {
			rev = nextrev;
			findrev.rev = rev->next;
		}
	}

	if (dotcount == 0) {
		for (;;) {
			if (rev->rev->len > branchtok.len + 1 &&
			    memcmp(rev->rev->str, branchtok.str, branchtok.len) == 0 &&
			    rev->rev->str[branchtok.len] == '.')
				break;

			if (rev->next == NULL)
				return NULL;

			findrev.rev = rev->next;
			rev = RB_FIND(rcsrevtree, &rcs->admin.revs, &findrev);
			if (rev == NULL)
				return NULL;
		}
	}
	tok = rev->rev;

found:
	retrev = malloc(tok->len + 1);
	if (retrev == NULL)
		return NULL;
	bcopy(tok->str, retrev, tok->len);
	retrev[tok->len] = '\0';

	return retrev;
}

char *
rcsgetlog(struct rcsfile *rcs, const char *logrev)
{
	struct rcstoken findtok;
	struct rcsrev findrev, *rev;

	if (rcsparsetree(rcs) < 0)
		return NULL;

	findtok.str = (char *)(long)logrev;
	findtok.len = strlen(logrev);
	findrev.rev = &findtok;

	rev = RB_FIND(rcsrevtree, &rcs->admin.revs, &findrev);
	if (rev == NULL)
		return NULL;

	if (rev->log != NULL)
		goto done;

	findrev.rev = rcs->admin.head;
	rev = RB_FIND(rcsrevtree, &rcs->admin.revs, &findrev);

	for (; rev != NULL; rev = rev->nextlog) {
		if (rcsparsetext(rcs, rev) < 0)
			return NULL;

		if (tokeqstr(rev->rev, logrev))
			break;
	}

	if (rev == NULL)
		return NULL;

done:
	return tokstripat(rev->log);
}

struct rcsfile *
rcsopen(const char *filename)
{
	struct stat st;
	struct rcsfile *rcs;

	rcs = calloc(1, sizeof(struct rcsfile));
	if (rcs == NULL)
		goto fail;

	rcs->file = open(filename, O_RDONLY);
	if (rcs->file < 0)
		goto fail;

	if (fstat(rcs->file, &st) < 0)
		goto fail;

	rcs->size = st.st_size;

	rcs->data = mmap(NULL, rcs->size, PROT_READ, MAP_PRIVATE, rcs->file, 0);
	if (rcs->data == MAP_FAILED)
		goto fail;

	rcs->end = rcs->data + rcs->size;
	rcs->pos = rcs->data;

	SLIST_INIT(&rcs->admin.access);
	RB_INIT(&rcs->admin.symbols);
	RB_INIT(&rcs->admin.locks);
	RB_INIT(&rcs->admin.revs);

	return rcs;

fail:
	if (rcs != NULL && rcs->file >= 0)
		close(rcs->file);
	if (rcs != NULL)
		free(rcs);

	return NULL;
}

void
rcsclose(struct rcsfile *rcs)
{
	struct rcstoken *tok;
	struct rcstokpair *pair;
	struct rcsrev *rev;

	if (rcs->tok != NULL) {
		free(rcs->tok);

		if (rcs->lasttok != NULL && rcs->lasttok != rcs->tok)
			free(rcs->lasttok);
	}

	if (rcs->admin.head != NULL)
		free(rcs->admin.head);
	if (rcs->admin.branch != NULL)
		free(rcs->admin.branch);
	while ((tok = SLIST_FIRST(&rcs->admin.access)) != NULL) {
		SLIST_REMOVE_HEAD(&rcs->admin.access, link);
		free(tok);
	}
	if (rcs->admin.comment != NULL)
		free(rcs->admin.comment);
	if (rcs->admin.expand != NULL)
		free(rcs->admin.expand);
	if (rcs->admin.desc != NULL)
		free(rcs->admin.desc);

	while ((pair = RB_MIN(rcstokmap, &rcs->admin.symbols)) != NULL) {
		RB_REMOVE(rcstokmap, &rcs->admin.symbols, pair);
		free(pair->first);
		free(pair->second);
		free(pair);
	}

	while ((pair = RB_MIN(rcstokmap, &rcs->admin.locks)) != NULL) {
		RB_REMOVE(rcstokmap, &rcs->admin.locks, pair);
		free(pair->first);
		free(pair->second);
		free(pair);
	}

	while ((rev = RB_MIN(rcsrevtree, &rcs->admin.revs)) != NULL) {
		RB_REMOVE(rcsrevtree, &rcs->admin.revs, rev);
		rcsfreerev(rev);
	}

	munmap(rcs->data, rcs->size);
	close(rcs->file);
	free(rcs);
}

#ifdef TESTING
int
main(int argc, char **argv)
{
	struct rcsfile *rcs;
	char *buf, *rev, *log;
	int i;
	size_t len;

	if (argc < 3)
		errx(1, "invalid arguments");

	rcs = rcsopen(argv[1]);
	if (rcs == NULL)
		return 1;

	if (rcsparseadmin(rcs) < 0)
		return 1;
	if (rcsparsetree(rcs) < 0)
		return 2;

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "all") == 0) {
			struct rcsrev *rrev;

			RB_FOREACH(rrev, rcsrevtree, &rcs->admin.revs) {
				rev = malloc(rrev->rev->len + 1);
				memcpy(rev, rrev->rev->str, rrev->rev->len);
				rev[rrev->rev->len] = 0;
				log = rcsgetlog(rcs, rev);
				free(log);
				buf = rcscheckout(rcs, rev, &len);
				free(buf);
				free(rev);
			}
		} else {
			rev = rcsrevfromsym(rcs, argv[i]);
			if (rev == NULL)
				return 3;

			log = rcsgetlog(rcs, rev);
			if (log == NULL)
				return 5;
			printf("%s\n", log);
			free(log);

			buf = rcscheckout(rcs, rev, &len);
			if (buf == NULL)
				return 4;
			fwrite(buf, 1, len, stdout);
			free(buf);
			free(rev);
		}
	}

	rcsclose(rcs);

	return 0;
}
#endif
