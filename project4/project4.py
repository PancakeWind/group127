def rotate_left(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def FF(X, Y, Z):
    return X ^ Y ^ Z

def GG(X, Y, Z):
    return (X & Y) | (X & Z) | (Y & Z)

def P0(X):
    return X ^ rotate_left(X, 9) ^ rotate_left(X, 17)

def P1(X):
    return X ^ rotate_left(X, 15) ^ rotate_left(X, 23)

def T(j):
    if 0 <= j < 16:
        return 0x79CC4519
    elif 16 <= j < 64:
        return 0x7A879D8A

def padding(msg):
    msg_len = len(msg) * 8
    msg += b'\x80'
    while len(msg) % 64 != 56:
        msg += b'\x00'
    msg += msg_len.to_bytes(8, 'big')
    return msg

def SM3(message):
    H = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]

    message = padding(message)

    for i in range(0, len(message), 64):
        W = [int.from_bytes(message[i+j:i+j+4], 'big') for j in range(64)]
        for j in range(16, 64):
            W.append(P1(W[j-16] ^ W[j-9] ^ rotate_left(W[j-3], 15)) ^ rotate_left(W[j-13], 7) ^ W[j-6])

        A, B, C, D, E, F, G, H0 = H

        for j in range(64):
            SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(T(j), j), 7)
            SS2 = SS1 ^ rotate_left(A, 12)
            TT1 = FF(A, B, C) + D + SS2 + W[j] + rotate_left(H0, 25)
            TT2 = GG(E, F, G) + H0 + SS1 + W[j]
            D = C
            C = rotate_left(B, 9)
            B = A
            A = TT1
            H0 = G
            G = rotate_left(F, 19)
            F = E
            E = P0(TT2)

        H = [(h_i ^ H_i) & 0xFFFFFFFF for h_i, H_i in zip([A, B, C, D, E, F, G, H0], H)]

    return b''.join(h.to_bytes(4, 'big') for h in H)
