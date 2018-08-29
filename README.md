Python implementation of ECDSA signature scheme.

------------

WARNING : this library should not be use in a production system.

------------

Example :

``` python
from ecdsa import *
ecdsa = ECDSAParamsP521()
(public, private) = ecdsa.genKeys()

s = private.sign(b'hello world')
assert public.verify(s, b'hello world')
```
