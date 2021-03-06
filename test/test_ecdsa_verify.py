import re
import os
import sys
import binascii

sys.path.insert(0, os.path.abspath('.'))

from ecdsa import *

# FIPS 186-4 tests vectors for signature verification
TEST_FILE = "test/SigVer.rsp"


if __name__ == '__main__':
    params = {}
    hashs = {}
    curves = {}

    hashs['SHA-1'] = hashlib.sha1
    hashs['SHA-224'] = hashlib.sha224
    hashs['SHA-256'] = hashlib.sha256
    hashs['SHA-384'] = hashlib.sha384
    hashs['SHA-512'] = hashlib.sha512

    curves['P-192'] = ECDSAParamsP192
    curves['P-224'] = ECDSAParamsP224
    curves['P-256'] = ECDSAParamsP256
    curves['P-384'] = ECDSAParamsP384
    curves['P-521'] = ECDSAParamsP521

    line_num = 0

    with open(TEST_FILE, 'r') as fd:
        for line in fd:
            line_num += 1
            line = line.replace("\n", "").replace("\r", "")
            if len(line) > 0 and line[0] != '#':

                m = re.search('^\[(\S+),(\S+)\]$', line)
                if m is not None:
                    params['Curve'] = m.group(1)
                    params['Hash'] = str(m.group(2))

                m = re.search('^(\S+) = (\S+)', line)
                if m is not None:
                    params[m.group(1)] = m.group(2)

                    if m.group(1) == 'Result':
                        if params['Curve'] in curves:
                            if params['Hash'] in hashs:
                                hash_fct = hashs[params['Hash']]
                                curve = curves[params['Curve']](hash_fct)

                                sys.stdout.write("Testing %s - %s (line %d)..." % (params['Curve'], params['Hash'], line_num))
                                sys.stdout.flush()

                                x = int(params['Qx'], 16)
                                y = int(params['Qy'], 16)

                                p = curve.curve.newPoint(x, y)
                                public = ECDSAPublicKey(curve, p)

                                r = int(params['R'], 16)
                                s = int(params['S'], 16)
                                m = binascii.unhexlify(params['Msg'])
                                sig = ECDSASignature(curve, r, s)

                                result = params['Result'][0] == 'P'
                                assert public.verify(sig, m) == result

                                sys.stdout.write("OK\n")
