import rcsparse
import md5

f=rcsparse.rcsfile('test,v')
print f.head
print f.branch
s=f.symbols
print s['RELENG_4']
print s.items()
r=f.revs
i=r.items()
print i
print f.getlog(f.sym2rev('RELENG_4'))
