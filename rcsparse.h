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

#ifndef RCSPARSE_H
#define RCSPARSE_H

#include "queue.h"
#include "tree.h"


struct stringinfo;

RB_HEAD(rcsrevtree, rcsrev);
RB_HEAD(rcstokmap, rcstokpair);
SLIST_HEAD(rcstoklist, rcstoken);

struct rcstoken {
	char		*str;
	size_t		len;
	int		type;
	SLIST_ENTRY(rcstoken) link;
};

#define	TOK_STRING	0x100
#define	TOK_STRINGAT	0x101
#define	TOK_DIGIT	0x200
#define	TOK_DOT		0x400
#define	TOK_PRINT	0x800
#define	TOK_NUM		(TOK_DOT | TOK_DIGIT)

struct rcstokpair {
	RB_ENTRY(rcstokpair) link;
	struct rcstoken	*first;
	struct rcstoken	*second;
};

struct rcsrev {
	RB_ENTRY(rcsrev) link;
	struct rcstoken	*rev;
	struct rcstoken	*date;
	struct rcstoken	*author;
	struct rcstoken	*state;
	struct rcstoklist branches;
	struct rcstoken	*next;
	struct rcstoken *commitid;
	char		*logpos;
	struct rcstoken	*log;
	struct stringinfo *text;
	struct stringinfo *rawtext;
	struct rcsrev  *nextlog;
};

struct rcsadmin {
	struct rcstoken	*head;
	struct rcstoken	*branch;
	struct rcstoklist access;
	struct rcstokmap symbols;
	struct rcstokmap locks;
	int		strict;
	struct rcstoken	*comment;
	struct rcstoken	*expand;
	struct rcsrevtree revs;
	struct rcstoken	*desc;
};

struct rcsfile {
	int 		file;
	size_t		size;
	char 		*data;
	char 		*pos;
	char		*end;
	struct rcstoken	*tok;
	struct rcstoken	*lasttok;
	char		*revpos;
	char		*deltapos;
	struct rcsadmin	admin;
};


struct rcsfile *rcsopen(const char *);
void rcsclose(struct rcsfile *);
int rcsparseadmin(struct rcsfile *);
int rcsparsetree(struct rcsfile *);
char *rcscheckout(struct rcsfile *, const char *, size_t *);
char *rcsrevfromsym(struct rcsfile *, const char *);
char *rcsgetlog(struct rcsfile *, const char *);

RB_PROTOTYPE(rcsrevtree, rcsrev, link, cmprev);
RB_PROTOTYPE(rcstokmap, rcstokpair, link, cmptokpair);

#endif
