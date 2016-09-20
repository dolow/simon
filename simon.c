#include <stdio.h>
#include <stdlib.h>

#define ROTATE_R(v, d) ((v >> d) | (v << (8 * sizeof(v) - d)))
#define ROTATE_L(v, d) ((v << d) | (v >> (8 * sizeof(v) - d)))

#define ROUNDS 32
#define BLOCK_SIZE 32
#define WORDS 8

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


static inline void simon_round(uint64_t* pt1, uint64_t* pt2, uint64_t key)
{
    uint64_t s1 = ROTATE_L(*pt1, 1);
    uint64_t s2 = ROTATE_L(*pt1, 8);
    
    *pt2 ^= ROTATE_L(*pt1, 2) ^ (s1 & s2);
    
    *pt2 ^= key;
    
    uint64_t _pt1 = *pt1;
    *pt1 = *pt2;
    *pt2 = _pt1;
}

static inline void simon_back(uint64_t* pt1, uint64_t* pt2, uint64_t key)
{
    uint64_t _pt2 = *pt2;
    *pt2 = *pt1;
    *pt1 = _pt2;
    
    *pt2 ^= key;
    
    uint64_t s1 = ROTATE_L(*pt1, 1);
    uint64_t s2 = ROTATE_L(*pt1, 8);
    
    *pt2 ^= ROTATE_L(*pt1, 2) ^ (s1 & s2);
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

const char* test_key = "abcdefghijklmnopqrstuvwxyz123456";

int main(int argc, const char** argv)
{
    int length = 64;

    unsigned char pt[64] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B
    };
    //const char pt[32] = "hello world!1234567890ABCDEFGHIJ";
    unsigned char ct[64];
    unsigned char dt[64];
    
    for (int i = 0; i < length; i++) printf("%03u ", pt[i]);
    printf("\n");
    
    simon_encrypt_all(pt, ct, (uint64_t*)test_key, length);
    
    for (int i = 0; i < length; i++) printf("%03u ", ct[i]);
    printf("\n");
    
    simon_decrypt_all(ct, dt, (uint64_t*)test_key, length);
    
    for (int i = 0; i < length; i++) printf("%03u ", dt[i]);
    printf("\n");
    
    return 0;
}
