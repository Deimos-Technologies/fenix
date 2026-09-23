/* core/crypto/fnx64_accel.c — FNX64 wieża a↑↑h mod 2^mb, 1:1 z tower_mod() w fnx64.py.
 *
 * Czemu C: koszt strumienia to tetracja, nie blake2s. Python pow() na wieży
 * wysokości 10 jest poprawny i zostaje wzorcem; ta pętla liczy TEN SAM wynik
 * hurtowo (jedno wejście do C na ramkę, nie jedno na blok).
 *
 * Dlaczego mnożenie uint64 wystarcza dla mod 2^mb przy mb<=64:
 * (x*y) mod 2^mb == ((x*y) mod 2^64) mod 2^mb, bo 2^64 jest wielokrotnością
 * 2^mb. Maska po mnożeniu w uint64 jest więc dokładna, nie skrótem.
 *
 * Kontrakt: przy złych argumentach zwracamy -1 ZANIM cokolwiek zapiszemy.
 * Przy 0 nadpisujemy bases[i] wynikiem wieży. Brak alokacji, brak errno.
 */
#include <stdint.h>

static uint64_t mask_of(unsigned mb)
{
    if (mb >= 64)
        return ~(uint64_t)0;
    if (mb == 0)
        return 0;
    return ((uint64_t)1 << mb) - 1;
}

/* λ(2^mb) jako liczba bitów wykładnika — ta sama tabela co _lambda_bits(). */
static unsigned lambda_bits(unsigned mb)
{
    if (mb >= 3)
        return mb - 2;
    if (mb == 2)
        return 1;
    return 0;
}

static uint64_t mod_pow(uint64_t base, uint64_t exp, unsigned mb)
{
    uint64_t m = mask_of(mb);
    uint64_t r = 1;
    base &= m;
    while (exp) {
        if (exp & 1)
            r = (r * base) & m;
        base = (base * base) & m;
        exp >>= 1;
    }
    return r & m;
}

static uint64_t tower_one(uint64_t a, unsigned h, unsigned mb, const unsigned *mods)
{
    unsigned m1;
    uint64_t v;
    unsigned hh;

    /* a zredukowane raz, mod 2^mb — jak `a %= 1<<mb` na wejściu tower_mod. */
    a &= mask_of(mb);
    if (h == 1)
        return a;
    m1 = mods[1];
    v = (m1 == 0) ? 0 : (a & mask_of(m1));
    for (hh = 2; hh <= h; hh++) {
        unsigned m = mods[hh];
        if (m == 0) {
            v = 0;
            continue;
        }
        v = mod_pow(a, v, m);
    }
    return v;
}

int fnx64_tower_batch(uint64_t *bases, uint32_t n, uint32_t height, uint32_t mb)
{
    unsigned mods[65];
    uint32_t i;
    unsigned hh;

    if (bases == 0 || height < 1 || height > 64 || mb < 1 || mb > 64)
        return -1;
    mods[height] = (unsigned)mb;
    for (hh = (unsigned)height; hh > 1; hh--)
        mods[hh - 1] = lambda_bits(mods[hh]);
    for (i = 0; i < n; i++)
        bases[i] = tower_one(bases[i], (unsigned)height, (unsigned)mb, mods);
    return 0;
}
