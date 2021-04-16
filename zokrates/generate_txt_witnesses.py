import hashlib

from zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from zokrates_pycrypto.field import FQ

def write_signature_for_zokrates_cli(sig, pk, hash_of_pk, msg, path):
    "Writes the input arguments for verifyEddsa in the ZoKrates stdlib to file."
    sig_R, sig_S = sig
    args = [sig_R.x, sig_R.y, sig_S, pk.p.x.n, pk.p.y.n]
    args = " ".join(map(str, args))

    bh = [str(int(hash_of_pk.hex()[i:i+8], 16)) for i in range(0,len(hash_of_pk.hex()), 8)]
    print(bh)
    to_write_hash = " ".join(bh)
    args = args + " " + to_write_hash

    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
    to_write_message = " ".join(b0 + b1)
    
    args = args + " " + to_write_message

    with open(path, "w+") as file:
        for l in args:
            file.write(l)

if __name__ == "__main__":
    raw_msg = "This is my secret message"
    msg = hashlib.sha512(raw_msg.encode("utf-8")).digest()

    # sk = PrivateKey.from_rand()
    # Seeded for debug purpose
    key = FQ(1997011358982923168928344992199991480689546837621580239342656433234255379025)
    sk = PrivateKey(key)
    sig = sk.sign(msg)

    pk = PublicKey.from_private(sk)
    is_verified = pk.verify(sig, msg)
    print('Message is signed by public key: ', is_verified)

    pk_str = str(pk.p.x.n) + str(pk.p.y.n)
    print('Public key is: ', pk_str)
    hash_of_pk = hashlib.sha256(pk_str.encode("utf-8")).digest()

    write_signature_for_zokrates_cli(sig, pk, hash_of_pk, msg, 'zokrates_inputs.txt')
