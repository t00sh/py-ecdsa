import re
import sys

sys.path.insert(0, './src/')

from ecdsa import *

# FIPS 186-4 tests vectors for signature verification
TEST_FILE = "test/SigVer.rsp"


if __name__ == '__main__':
    params = {}
    hashs = {}
    curves = {}

    hashs['SHA-224'] = hashlib.sha224
    hashs['SHA-256'] = hashlib.sha256
    hashs['SHA-384'] = hashlib.sha384
    hashs['SHA-512'] = hashlib.sha512

    curves['P-521'] = ECDSAParamsP521()

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
                                curve = curves[params['Curve']]
                                curve.hash_fct = hashs[params['Hash']]

                                sys.stdout.write("Testing %s - %s (line %d)..." % (params['Curve'], params['Hash'], line_num))
                                sys.stdout.flush()

                                (public, private) = curve.genKeys()

                                public.p.x = int(params['Qx'], 16)
                                public.p.y = int(params['Qy'], 16)

                                r = int(params['R'], 16)
                                s = int(params['S'], 16)
                                m = bytes.fromhex(params['Msg'])
                                sig = ECDSASignature(curve, r, s)

                                result = params['Result'][0] == 'P'
                                assert public.verify(sig, m) == result

                                sys.stdout.write("OK\n")
