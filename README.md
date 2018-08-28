Python implementation of ECDSA signature scheme.
------------

Example :

``` python
from ecdsa import *
ecdsa = ECDSAParamsP521()
(public, private) = ecdsa.genKeys()

s = private.sign(b'hello world')
assert public.verify(s, b'hello world')
```
