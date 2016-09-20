#include <stdio.h>
#include <stdlib.h>

#define ROTATE_R(v, d) ((v >> d) | (v << (8 * sizeof(v) - d)))
#define ROTATE_L(v, d) ((v << d) | (v >> (8 * sizeof(v) - d)))

#define FIESTEL_ROTATE(v) ((ROTATE_L(v, 1) & ROTATE_L(v, 8)) ^ ROTATE_L(v, 2))

#define BLOCK_SIZE 32
#define WORDS 8

#define CONSTANT_C 0xfffffffffffffffc


// TODO: accept other sizes
#define WORD_SIZE  64
#define KEY_WORDS  4
#define ROUNDS     72
#define Z_VECTOR_J 4



/**
 * What you see is whit is Simon :-)
 *
 *
 * pt1               pt2
 *  |   1             |
 *  |-> << --         |
 *  |       |         |
 *  |       v         v
 *  |       & -> X -> X
 *  |       ^    ^    |
 *  |   8   |    |    |
 *  |-> << --    |    |
 *  |            |    |
 *  |   2        |    v
 *  |-> << -------    X <- key
 *  |                 |
 *  --------   --------
 *          \ /
 *           x
 *          / \
 *  --------   --------
 *  |                 |
 *  v                 v
 * ct1               ct2
 *
 */

/**
 * Z vector const
 * https://eprint.iacr.org/2013/543.pdf (3 Differential Attack)
 */
const uint64_t Z_VECTOR[5][62] = {
    {1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0},
    {1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0},
    {1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1},
    {1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1},
    {1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1}
};

/**
 * key schedule formula
 * https://eprint.iacr.org/2013/526.pdf (2 SIMON) 
 *
 * 4 key words:
 *     Y = K[i + 1] ^ (K[i + 3] >> 3)
 *     K[i + KEY_WORDS] = K[i] ^ Y ^ (Y >> 1) ^ CONSTANT_C ^ (z[j])[i]
 * 3 - 1 key words:
 *     Y = K[i + 1]
 *     K[i + KEY_WORDS] = K[i] ^ Y ^ (Y >> 1) ^ CONSTANT_C ^ (z[j])[i]
 */
void key_schedule(uint64_t* key, uint64_t* dest)
{
    for (int i = 0; i < KEY_WORDS; i++)
        dest[i] = key[i];
    
    for (int i = KEY_WORDS; i < ROUNDS; i++){
        uint64_t y = ROTATE_R(dest[i - 1], 3);
        if (KEY_WORDS == 4)
            y ^= dest[i - 3];
        dest[i] = dest[i - KEY_WORDS] ^ y ^ ROTATE_R(y, 1) ^ CONSTANT_C ^ Z_VECTOR[Z_VECTOR_J][(i - KEY_WORDS) % 62];
    }
}

static inline void simon_round(uint64_t* pt1, uint64_t* pt2, uint64_t key)
{
    uint64_t _pt1 = *pt1;
    *pt1 = *pt2 ^ FIESTEL_ROTATE(*pt1) ^ key;
    *pt2 = _pt1;
}

static inline void simon_back(uint64_t* pt1, uint64_t* pt2, uint64_t key)
{
    uint64_t _pt2 = *pt2;
    *pt2 = *pt1 ^ FIESTEL_ROTATE(*pt2) ^ key;
    *pt1 = _pt2;
}

void simon_encrypt(const uint64_t pt[2], uint64_t ct[2], uint64_t key[ROUNDS])
{
    ct[0] = pt[0];
    ct[1] = pt[1];
    
    for (unsigned int i = 0; i < ROUNDS; i++)
        simon_round(&ct[0], &ct[1], key[i]);
}

void simon_decrypt(const uint64_t ct[2], uint64_t pt[2], uint64_t key[ROUNDS])
{
    pt[0] = ct[0];
    pt[1] = ct[1];
    
    for (unsigned int i = ROUNDS; i > 0; i--)
        simon_back(&pt[0], &pt[1], key[i - 1]);
}

static inline void cast_uint8_array_to_uint64(uint64_t *dst, const unsigned char *array)
{
  // TODO: byte order
    *dst =  (uint64_t)array[7] << 56 | (uint64_t)array[6] << 48 | (uint64_t)array[5] << 40 | (uint64_t)array[4] << 32 |
            (uint64_t)array[3] << 24 | (uint64_t)array[2] << 16 | (uint64_t)array[1] << 8  | (uint64_t)array[0];
}

static inline void cast_uint64_to_uint8_array(unsigned char *dst, uint64_t src)
{
    // TODO: byte order
    dst[0] = (unsigned char) (src & 0x00000000000000ff);
    dst[1] = (unsigned char)((src & 0x000000000000ff00) >> 8);
    dst[2] = (unsigned char)((src & 0x0000000000ff0000) >> 16);
    dst[3] = (unsigned char)((src & 0x00000000ff000000) >> 24);
    dst[4] = (unsigned char)((src & 0x000000ff00000000) >> 32);
    dst[5] = (unsigned char)((src & 0x0000ff0000000000) >> 40);
    dst[6] = (unsigned char)((src & 0x00ff000000000000) >> 48);
    dst[7] = (unsigned char)((src & 0xff00000000000000) >> 56);
}

static inline int simon_encrypt_all(const unsigned char* pt, unsigned char* ct, uint64_t* key, int src_length)
{
    if (src_length % BLOCK_SIZE != 0)
        return -1;
    
    int block_count = src_length / BLOCK_SIZE;
    int block_parts = BLOCK_SIZE / WORDS;
    
    for (int i = 0; i < block_count; i++) {
        uint64_t pb[2];
        uint64_t cb[2];

        int char_index = (i * BLOCK_SIZE);
        int forward    = 0;
        
        while (forward < BLOCK_SIZE) {
            unsigned char* cursor_pt = (unsigned char *)(pt + char_index + forward);
            unsigned char* cursor_ct = (unsigned char *)(ct + char_index + forward);
            
            cast_uint8_array_to_uint64(&pb[0], cursor_pt);
            cast_uint8_array_to_uint64(&pb[1], cursor_pt + WORDS);

            simon_encrypt(pb, cb, key);

            cast_uint64_to_uint8_array(cursor_ct, cb[0]);
            cast_uint64_to_uint8_array(cursor_ct + WORDS, cb[1]);
            
            forward += WORDS * 2;
        }
    }

    return 0;
}

static inline int simon_decrypt_all(const unsigned char* ct, unsigned char* pt, uint64_t* key, int src_length)
{
    if (src_length % BLOCK_SIZE != 0)
        return -1;

    int block_count = src_length / BLOCK_SIZE;
    int block_parts = BLOCK_SIZE / WORDS;
    
    for (int i = 0; i < block_count; i++) {
        uint64_t pb[2];
        uint64_t cb[2];

        int char_index = (i * BLOCK_SIZE);
        int forward    = 0;
        
        while (forward < BLOCK_SIZE) {
            unsigned char* cursor_ct = (unsigned char *)(ct + char_index + forward);
            unsigned char* cursor_pt = (unsigned char *)(pt + char_index + forward);

            cast_uint8_array_to_uint64(&cb[0], cursor_ct);
            cast_uint8_array_to_uint64(&cb[1], cursor_ct + WORDS);

            simon_decrypt(cb, pb, key);

            cast_uint64_to_uint8_array(cursor_pt, pb[0]);
            cast_uint64_to_uint8_array(cursor_pt + WORDS, pb[1]);

            forward += WORDS * 2;
        }
    }

    return 0;
}

int main(int argc, const char** argv)
{
    //uint64_t k[4] = {0x1f1e1d1c1b1a1918, 0x1716151413121110, 0x0f0e0d0c0b0a0908, 0x0706050403020100};
    uint64_t k[4] = {0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110, 0x1f1e1d1c1b1a1918};
    uint64_t sk[72];
    
    uint64_t p[2] = {0x74206e69206d6f6f, 0x6d69732061207369};
    uint64_t c[2];
    uint64_t d[2];
    
    uint64_t expect[2] = {0x8d2b5579afc8a3a0, 0x3bf72a87efe7b868};

    
    key_schedule(k, sk);
    
    printf("%llu %llu \n", p[0], p[1]);
    
    simon_encrypt(p, c, sk);
    
    printf("%llu %llu \n", c[0], c[1]);
    
    if (c[0] == expect[0] && c[1] == expect[1])
        printf("algorithm passed\n");
    else
        printf("algorithm failed\n");
    
    simon_decrypt(c, d, sk);
    
    printf("%llu %llu \n", d[0], d[1]);

    if (p[0] == d[0] && p[1] == d[1])
        printf("round trip succeeded\n");
    else
        printf("round trip failed\n");
    

    return 0;
}
