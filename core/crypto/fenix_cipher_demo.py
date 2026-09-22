# fenix_cipher_demo.py
# ============================================================
#  Wlasny szyfr blokowy (siec Feistla) — DEMO EDUKACYJNE
#  Projekt: AnonNet / Fenix — nauka kryptografii
#  UWAGA: tylko do nauki! Do ochrony danych: AES-256/ChaCha20
# ============================================================

ROUNDS = 16            # liczba rund — jak mikser: 16x mieszanie
BLOCK  = 8             # rozmiar bloku w bajtach (64 bity)
KEYLEN = 16            # klucz glowny: 128 bitow

# ------------------------------------------------------------
# 1) S-BOX — tabelka podstawien (confusion)
#    Bajt wchodzi, wychodzi inny bajt. Prosta, nieliniowa.
# ------------------------------------------------------------
def build_sbox():
    sbox = []
    for i in range(256):
        x  = (i * 197) & 0xFF      # mnozenie = "rozjazd" wartosci
        x ^= (i * i) & 0xFF        # kwadrat = nieliniowosc
        x ^= 0x5A
        sbox.append(x & 0xFF)
    return sbox

SBOX = build_sbox()

# ------------------------------------------------------------
# 2) Rotacje bitowe — serce dyfuzji (diffusion)
# ------------------------------------------------------------
def rotl32(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def rotl128(x, n):
    n %= 128
    return ((x << n) | (x >> (128 - n))) & ((1 << 128) - 1)

# ------------------------------------------------------------
# 3) Funkcja rundy F — miesza polowe bloku z kluczem rundy
#    KOLEJNOSC: XOR klucza -> S-box -> rotacje -> dodawanie
# ------------------------------------------------------------
def f_function(half32, rkey32):
    x = half32 ^ rkey32                     # wmasuj klucz rundy
    mixed = 0
    for i in range(4):                      # kazdy bajt przez S-box
        b   = (x >> (8 * i)) & 0xFF
        sub = SBOX[(b + i * 17) & 0xFF]
        mixed = (mixed + ((sub << (8 * i)) ^ rotl32(sub, 3 * i + 1))) & 0xFFFFFFFF
    mixed ^= rotl32(mixed, 13)              # lawina: porozrzucaj bity
    mixed  = (mixed + 0x9E3779B9) & 0xFFFFFFFF   # "zlota stala" Fibonacciego
    mixed ^= rotl32(mixed, 7)
    return mixed

# ------------------------------------------------------------
# 4) KEY SCHEDULE — z 1 klucza glownego robimy 16 roznych
#    podkluczy (po jednym na kazda runde)
# ------------------------------------------------------------
def make_round_keys(key):
    if len(key) != KEYLEN:
        raise ValueError("Klucz musi miec dokladnie 16 bajtow!")
    mk = int.from_bytes(key, 'big')
    keys = []
    for r in range(ROUNDS):
        # rotacja + stala rundy = kazdy podklucz inny
        mk = rotl128(mk, 23) ^ (((0xA5 + r) * 0x01010101010101010101010101010101) & ((1 << 128) - 1))
        rk = (mk >> 96) & 0xFFFFFFFF        # wez gorne 32 bity
        # i dodatkowo przepusc je przez S-box (bajt po bajcie)
        rk = int.from_bytes(bytes(SBOX[(rk >> (8 * i)) & 0xFF] for i in range(4)), 'big')
        keys.append(rk)
    return keys

# ------------------------------------------------------------
# 5) SZYFROWANIE BLOKU — siec Feistla
#    Dzielimy 8 bajtow na polowy L i R i 16 razy mieszamy.
# ------------------------------------------------------------
def encrypt_block(block8, keys):
    L = int.from_bytes(block8[:4], 'big')
    R = int.from_bytes(block8[4:], 'big')
    for rk in keys:
        L, R = R, L ^ f_function(R, rk)
    return L.to_bytes(4, 'big') + R.to_bytes(4, 'big')

# 6) DESZYFROWANIE — te same rundy, ale klucze OD TYLKO
#    (to magia Feistla: nie trzeba odwracac funkcji F!)
def decrypt_block(block8, keys):
    L = int.from_bytes(block8[:4], 'big')
    R = int.from_bytes(block8[4:], 'big')
    for rk in reversed(keys):
        L, R = R ^ f_function(L, rk), L
    return L.to_bytes(4, 'big') + R.to_bytes(4, 'big')

# ------------------------------------------------------------
# 7) Padding PKCS#7 — wiadomosc musi miec dlugosc wielokrotna 8
# ------------------------------------------------------------
def pad(data):
    p = BLOCK - (len(data) % BLOCK)
    return data + bytes([p] * p)

def unpad(data):
    return data[:-data[-1]]

def encrypt(data, key):
    keys = make_round_keys(key)
    data = pad(data)
    out = b''
    for i in range(0, len(data), BLOCK):    # UWAGA: to jest tryb ECB —
        out += encrypt_block(data[i:i+BLOCK], keys)   # w praktyce lancuchujemy bloki!
    return out

def decrypt(ct, key):
    keys = make_round_keys(key)
    out = b''
    for i in range(0, len(ct), BLOCK):
        out += decrypt_block(ct[i:i+BLOCK], keys)
    return unpad(out)

# ------------------------------------------------------------
# 8) TEST LAWINY — zmiana 1 bita powinna zmienic ~50% bitow
# ------------------------------------------------------------
def avalanche_test(key):
    a = b"FENIXNET"
    b = bytearray(a); b[0] ^= 1             # odwracamy JEDEN bit
    keys = make_round_keys(key)
    ca = encrypt_block(a, keys)
    cb = encrypt_block(bytes(b), keys)
    diff = sum(bin(x ^ y).count("1") for x, y in zip(ca, cb))
    return diff, 64 - diff

# ============================================================
#  DEMO
# ============================================================
if __name__ == "__main__":
    klucz = b"FnxDemoKey_2026!"             # 16 bajtow

    tekst = b"AnonNet Fenix: pelna anonimowosc!"
    print(f"[i] Tekst jawny : {tekst}")

    ct = encrypt(tekst, klucz)
    print(f"[i] Szyfrogram  : {ct.hex()}")

    pt = decrypt(ct, klucz)
    print(f"[i] Odszyfrowane: {pt}")
    assert pt == tekst
    print("[OK] Szyfrowanie <-> deszyfrowanie dziala!\n")

    zmienione, niezmienione = avalanche_test(klucz)
    print(f"[LAWINA] 1 bit wejscia zmienil {zmienione}/64 bitow wyjscia")
    print(f"         (idealnie ~32; masz {zmienione} -> {'DOBRZE' if zmienione >= 24 else 'SLABO, popraw F'})")
