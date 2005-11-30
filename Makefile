PROG=	rcsparse

NOMAN=	yes
CFLAGS+=	-DTESTING

WARNS?=	6

.include <bsd.prog.mk>
